import asyncio
from typing import Any

import httpx

from ai_engine.model_gateway.base import ProviderRequest, ProviderResult
from ai_security.prompt_injection.policy import SECURITY_SYSTEM_POLICY


class ProviderError(RuntimeError):
    def __init__(self, message: str, *, code: str = "provider_error") -> None:
        super().__init__(message)
        self.code = code


class HttpChatProvider:
    name = "openai_compatible"
    cloud = True

    def __init__(self, base_url: str, model: str, *, api_key: str | None = None, timeout: float = 30, retries: int = 1, client: httpx.AsyncClient | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.retries = max(0, min(retries, 5))
        self.client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None

    def _endpoint(self) -> str:
        if self.base_url.endswith("/chat/completions"):
            return self.base_url
        return self.base_url + "/chat/completions"

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}

    async def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                response = await self.client.post(self._endpoint(), headers=self._headers(), json=body)
                response.raise_for_status()
                return response.json()
            except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as exc:
                last_error = exc
                status = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
                if status is not None and status < 500 and status != 429:
                    break
                if attempt < self.retries:
                    await asyncio.sleep(0.15 * (attempt + 1))
        if isinstance(last_error, httpx.TimeoutException):
            raise ProviderError("Model provider timed out.", code="timeout") from last_error
        raise ProviderError("Model provider request failed.", code="upstream_error") from last_error

    async def infer(self, request: ProviderRequest) -> ProviderResult:
        body = {
            "model": request.model or self.model,
            "messages": [
                {"role": "system", "content": f"{SECURITY_SYSTEM_POLICY}\nReturn only one JSON object valid for this schema: {request.output_schema}"},
                {"role": "user", "content": request.prompt},
            ],
            "max_tokens": request.max_tokens,
            "response_format": {"type": "json_object"},
        }
        data = await self._post(body)
        try:
            content = data["choices"][0]["message"]["content"]
            usage = data.get("usage", {})
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError("Model provider returned an invalid response.", code="invalid_upstream_response") from exc
        if not isinstance(content, str):
            raise ProviderError("Model provider returned no text content.", code="invalid_upstream_response")
        return ProviderResult(content, str(data.get("model", request.model)), str(data.get("system_fingerprint") or "unknown"), usage.get("prompt_tokens"), usage.get("completion_tokens"))

    async def health(self) -> dict[str, Any]:
        try:
            response = await self.client.get(self.base_url + "/models", headers=self._headers(), timeout=min(self.timeout, 5))
            response.raise_for_status()
            return {"status": "ok", "model": self.model}
        except (httpx.HTTPError, ValueError, AttributeError, TypeError):
            return {"status": "unavailable", "model": self.model}

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()


class OpenAICompatibleProvider(HttpChatProvider):
    name = "openai_compatible"
    cloud = True

    def __init__(self, base_url: str, model: str, **kwargs: Any) -> None:
        super().__init__(base_url, model, **kwargs)


class LlamaCppProvider(HttpChatProvider):
    name = "llama_cpp"
    cloud = False

    def __init__(self, base_url: str, model: str, **kwargs: Any) -> None:
        super().__init__(base_url, model, **kwargs)

    async def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        body.pop("response_format", None)
        return await super()._post(body)

    async def health(self) -> dict[str, Any]:
        try:
            response = await self.client.get(self.base_url.rsplit("/v1", 1)[0] + "/health", timeout=min(self.timeout, 5))
            response.raise_for_status()
            return {"status": "ok", "model": self.model}
        except (httpx.HTTPError, ValueError, AttributeError, TypeError):
            return {"status": "unavailable", "model": self.model}

