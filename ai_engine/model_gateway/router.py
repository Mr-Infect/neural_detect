import asyncio
import json
import os
import time
from dataclasses import dataclass
from typing import Any

from ai_engine.model_gateway.base import ProviderRequest, ProviderResult
from ai_engine.model_gateway.cost_tracker import CostEstimate, estimate_cost
from ai_engine.model_gateway.policy import TenantPolicy, authorize_provider
from ai_engine.model_gateway.providers import (
    AnthropicProvider,
    LlamaCppProvider,
    OllamaProvider,
    OpenAICompatibleProvider,
    ProviderError,
)
from ai_engine.model_gateway.redaction import detect_raw_telemetry, redact_sensitive_data
from ai_engine.model_gateway.response_validator import OUTPUT_MODELS, validate_response
from ai_engine.model_gateway.token_manager import secret_for_provider


@dataclass(frozen=True)
class GatewayResult:
    provider: str
    model: str
    model_version: str | None
    latency_ms: int
    prompt_tokens: int | None
    completion_tokens: int | None
    output: Any
    redacted_categories: tuple[str, ...]
    cost: CostEstimate


class RateLimitExceeded(RuntimeError):
    pass


class TenantRateLimiter:
    def __init__(self) -> None:
        self._events: dict[str, list[float]] = {}
        self._lock = asyncio.Lock()

    async def check(self, tenant_id: str, limit: int) -> None:
        now = time.monotonic()
        async with self._lock:
            events = [stamp for stamp in self._events.get(tenant_id, []) if stamp > now - 60]
            if len(events) >= limit:
                self._events[tenant_id] = events
                raise RateLimitExceeded("Model inference rate limit exceeded.")
            events.append(now)
            self._events[tenant_id] = events


class ModelGateway:
    def __init__(self) -> None:
        timeout = float(os.getenv("ND_AI_TIMEOUT_SECONDS", "30"))
        retries = int(os.getenv("ND_AI_RETRIES", "1"))
        self.providers = {
            "ollama": OllamaProvider(os.getenv("ND_OLLAMA_URL", "http://ollama:11434"), os.getenv("ND_OLLAMA_MODEL", "llama3.2:3b"), timeout=timeout, retries=retries),
            "llama_cpp": LlamaCppProvider(os.getenv("ND_LLAMA_CPP_URL", "http://llama-cpp:8080/v1"), os.getenv("ND_LLAMA_CPP_MODEL", "local-model"), api_key=secret_for_provider("llama_cpp").get_secret_value() if secret_for_provider("llama_cpp") else None, timeout=timeout, retries=retries),
            "openai_compatible": OpenAICompatibleProvider(os.getenv("ND_OPENAI_BASE_URL", "https://api.openai.com/v1"), os.getenv("ND_OPENAI_MODEL", "gpt-4o-mini"), api_key=secret_for_provider("openai_compatible").get_secret_value() if secret_for_provider("openai_compatible") else None, timeout=timeout, retries=retries),
            "anthropic": AnthropicProvider(os.getenv("ND_ANTHROPIC_BASE_URL", "https://api.anthropic.com"), os.getenv("ND_ANTHROPIC_MODEL", "claude-3-5-haiku-latest"), api_key=secret_for_provider("anthropic").get_secret_value() if secret_for_provider("anthropic") else None, timeout=timeout, retries=retries),
        }
        self.limiter = TenantRateLimiter()

    def configured(self, name: str) -> bool:
        if name == "ollama":
            return bool(os.getenv("ND_OLLAMA_URL", "http://ollama:11434"))
        if name == "llama_cpp":
            return bool(os.getenv("ND_LLAMA_CPP_URL", "http://llama-cpp:8080/v1"))
        if name == "openai_compatible":
            return bool(secret_for_provider(name)) and bool(os.getenv("ND_AI_CLOUD_ENABLED", "false").lower() == "true")
        if name == "anthropic":
            return bool(secret_for_provider(name)) and bool(os.getenv("ND_AI_CLOUD_ENABLED", "false").lower() == "true")
        return False

    async def provider_status(self) -> list[dict[str, Any]]:
        async def status(name: str, provider: Any) -> dict[str, Any]:
            if not self.configured(name):
                return {"provider": name, "status": "not_configured", "cloud": provider.cloud, "model": provider.model}
            result = await provider.health()
            return {"provider": name, **result, "cloud": provider.cloud}
        return await asyncio.gather(*(status(name, provider) for name, provider in self.providers.items()))

    async def infer(
        self,
        *,
        tenant_id: str,
        prompt: str,
        output_kind: str,
        provider_name: str | None,
        model: str | None,
        fallback_providers: list[str],
        cloud_consent: bool,
        contains_raw_telemetry: bool,
        max_response_tokens: int,
    ) -> GatewayResult:
        policy = TenantPolicy.for_tenant(tenant_id)
        if len(prompt) > policy.max_prompt_chars:
            raise ValueError("Prompt exceeds tenant size limit.")
        if output_kind not in OUTPUT_MODELS:
            raise ValueError("Unsupported structured output type.")
        await self.limiter.check(tenant_id, policy.max_requests_per_minute)
        primary = provider_name or os.getenv("ND_AI_DEFAULT_PROVIDER", "ollama")
        candidates = list(dict.fromkeys([primary, *fallback_providers]))
        if len(candidates) > 5:
            raise ValueError("At most four fallback providers are allowed.")
        safe_prompt = redact_sensitive_data(prompt)
        output_schema = json.dumps(OUTPUT_MODELS[output_kind].model_json_schema(), separators=(",", ":"))
        failures: list[str] = []
        for name in candidates:
            provider = self.providers.get(name)
            if provider is None:
                failures.append(name)
                continue
            try:
                authorize_provider(name, policy, cloud_consent=cloud_consent, contains_raw_telemetry=(contains_raw_telemetry or detect_raw_telemetry(prompt)))
            except PermissionError:
                if name == primary:
                    raise
                failures.append(name)
                continue
            if not self.configured(name):
                failures.append(name)
                continue
            await self.limiter.check(f"provider:{tenant_id}:{name}", policy.max_requests_per_minute)
            start = time.perf_counter()
            try:
                result: ProviderResult = await provider.infer(ProviderRequest(model or provider.model, safe_prompt.text, output_schema, max_response_tokens))
                if len(result.content) > policy.max_response_chars:
                    raise ProviderError("Model response exceeds tenant size limit.", code="response_too_large")
                output = validate_response(output_kind, result.content)
                return GatewayResult(name, result.model, result.model_version, int((time.perf_counter() - start) * 1000), result.prompt_tokens, result.completion_tokens, output, safe_prompt.categories, estimate_cost(name, result.prompt_tokens, result.completion_tokens))
            except (ProviderError, ValueError) as exc:
                failures.append(name)
                if name == candidates[-1]:
                    raise ProviderError("No configured provider returned a valid response.", code=exc.code if isinstance(exc, ProviderError) else "invalid_response") from exc
        raise ProviderError("No configured provider was available for this request.", code="no_provider")

    async def close(self) -> None:
        await asyncio.gather(*(provider.close() for provider in self.providers.values() if hasattr(provider, "close")), return_exceptions=True)


gateway = ModelGateway()




