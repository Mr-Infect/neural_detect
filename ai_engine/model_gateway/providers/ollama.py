import asyncio
import json
from typing import Any

import httpx

from ai_engine.model_gateway.base import ProviderRequest, ProviderResult
from ai_engine.model_gateway.providers.openai_compatible import ProviderError
from ai_security.prompt_injection.policy import SECURITY_SYSTEM_POLICY


class OllamaProvider:
    name = "ollama"
    cloud = False

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        timeout: float = 30,
        retries: int = 1,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.retries = max(0, min(retries, 5))
        self.client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None

    async def infer(self, request: ProviderRequest) -> ProviderResult:
        body = {
            "model": request.model or self.model,
            "stream": False,
            "format": json.loads(request.output_schema),
            "messages": [
                {
                    "role": "system",
                    "content": f"{SECURITY_SYSTEM_POLICY}\nReturn only one JSON object valid for this schema: {request.output_schema}",
                },
                {"role": "user", "content": request.prompt},
            ],
            "options": {"num_predict": request.max_tokens},
        }
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                response = await self.client.post(
                    self.base_url + "/api/chat", json=body, timeout=self.timeout
                )
                response.raise_for_status()
                data = response.json()
                content = data["message"]["content"]
                return ProviderResult(
                    str(content),
                    str(data.get("model", request.model)),
                    None,
                    data.get("prompt_eval_count"),
                    data.get("eval_count"),
                )
            except httpx.TimeoutException as exc:
                last_error = exc
                if attempt < self.retries:
                    await asyncio.sleep(0.15 * (attempt + 1))
            except (
                httpx.NetworkError,
                httpx.HTTPStatusError,
                KeyError,
                TypeError,
                ValueError,
            ) as exc:
                last_error = exc
                status = (
                    exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
                )
                if status is not None and status < 500 and status != 429:
                    break
                if attempt < self.retries:
                    await asyncio.sleep(0.15 * (attempt + 1))
        if isinstance(last_error, httpx.TimeoutException):
            raise ProviderError("Local model timed out.", code="timeout") from last_error
        raise ProviderError("Local model request failed.", code="upstream_error") from last_error

    async def health(self) -> dict[str, Any]:
        try:
            response = await self.client.get(
                self.base_url + "/api/tags", timeout=min(self.timeout, 5)
            )
            response.raise_for_status()
            models = response.json().get("models", [])
            found = any(
                model.get("name", "").split(":")[0] == self.model.split(":")[0] for model in models
            )
            return {
                "status": "ok" if found else "model_unavailable",
                "model": self.model,
                "available_models": len(models),
            }
        except (httpx.HTTPError, ValueError, AttributeError, TypeError):
            return {"status": "unavailable", "model": self.model}

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()
