import json
import os
from dataclasses import dataclass

CLOUD_PROVIDERS = frozenset({"openai_compatible", "anthropic"})


@dataclass(frozen=True)
class TenantPolicy:
    cloud_enabled: bool = False
    raw_telemetry_to_cloud: bool = False
    allowed_providers: tuple[str, ...] = ("ollama", "llama_cpp", "openai_compatible", "anthropic")
    max_prompt_chars: int = 20_000
    max_response_chars: int = 32_000
    max_requests_per_minute: int = 20

    @classmethod
    def for_tenant(cls, tenant_id: str) -> "TenantPolicy":
        try:
            policies = json.loads(os.getenv("ND_AI_TENANT_POLICIES_JSON", "{}"))
            raw = policies.get(tenant_id, {})
            if not isinstance(raw, dict):
                raw = {}
        except (ValueError, AttributeError):
            raw = {}
        return cls(
            cloud_enabled=bool(raw.get("cloud_enabled", False)),
            raw_telemetry_to_cloud=bool(raw.get("raw_telemetry_to_cloud", False)),
            allowed_providers=tuple(raw.get("allowed_providers", cls.allowed_providers)),
            max_prompt_chars=max(256, min(int(raw.get("max_prompt_chars", 20_000)), 100_000)),
            max_response_chars=max(256, min(int(raw.get("max_response_chars", 32_000)), 100_000)),
            max_requests_per_minute=max(1, min(int(raw.get("max_requests_per_minute", 20)), 600)),
        )


def authorize_provider(
    provider: str,
    policy: TenantPolicy,
    *,
    cloud_consent: bool,
    contains_raw_telemetry: bool,
) -> None:
    if provider not in policy.allowed_providers:
        raise PermissionError("Provider is not allowed by tenant model policy.")
    if provider in CLOUD_PROVIDERS:
        if os.getenv("ND_AI_CLOUD_ENABLED", "false").lower() != "true":
            raise PermissionError("Hosted inference is disabled by global policy.")
        if not policy.cloud_enabled or not cloud_consent:
            raise PermissionError("Hosted inference requires tenant policy and explicit request consent.")
        if contains_raw_telemetry and not policy.raw_telemetry_to_cloud:
            raise PermissionError("Raw telemetry is blocked from hosted inference by tenant policy.")

