import asyncio
from typing import Any

import httpx

from ai_engine.model_gateway.base import ProviderRequest, ProviderResult
from ai_engine.model_gateway.providers.openai_compatible import ProviderError
from ai_security.prompt_injection.policy import SECURITY_SYSTEM_POLICY


class AnthropicProvider:
    name = "anthropic"
    cloud = True

    def __init__(self, base_url: str, model: str, api_key: str | None = None, *, timeout: float = 30, retries: int = 1, api_version: str = "2023-06-01", client: httpx.AsyncClient | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.retries = max(0, min(retries, 5))
        self.api_version = api_version
        self.client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None

    def _headers(self) -> dict[str, str]:
        return {"x-api-key": self.api_key or "", "anthropic-version": self.api_version, "content-type": "application/json"}

    async def infer(self, request: ProviderRequest) -> ProviderResult:
        body = {
            "model": request.model or self.model,
            "max_tokens": request.max_tokens,
            "system": f"{SECURITY_SYSTEM_POLICY}\nReturn only one JSON object valid for this schema: {request.output_schema}",
            "messages": [{"role": "user", "content": request.prompt}],
        }
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                response = await self.client.post(self.base_url + "/v1/messages", headers=self._headers(), json=body, timeout=self.timeout)
                response.raise_for_status()
                data = response.json()
                content = "".join(block.get("text", "") for block in data.get("content", []) if block.get("type") == "text")
                usage = data.get("usage", {})
                if not content:
                    raise ProviderError("Model provider returned no text content.", code="invalid_upstream_response")
                return ProviderResult(content, str(data.get("model", request.model)), data.get("model_version"), usage.get("input_tokens"), usage.get("output_tokens"))
            except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as exc:
                last_error = exc
                status = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
                if status is not None and status < 500 and status != 429:
                    break
                if attempt < self.retries:
                    await asyncio.sleep(0.15 * (attempt + 1))
        if isinstance(last_error, httpx.TimeoutException):
            raise ProviderError("Hosted model timed out.", code="timeout") from last_error
        raise ProviderError("Hosted model request failed.", code="upstream_error") from last_error

    async def health(self) -> dict[str, Any]:
        try:
            response = await self.client.get(self.base_url + "/v1/models", headers=self._headers(), timeout=min(self.timeout, 5))
            response.raise_for_status()
            data = response.json()
            return {"status": "ok", "model": self.model, "available_models": len(data.get("data", []))}
        except (httpx.HTTPError, ValueError, AttributeError, TypeError):
            return {"status": "unavailable", "model": self.model}

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()
