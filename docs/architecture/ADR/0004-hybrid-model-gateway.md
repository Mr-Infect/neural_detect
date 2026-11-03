# ADR 0004: Hybrid AI Model Gateway

- **Status:** Accepted
- **Date:** 2026-11-02
- **Decision:** Keep provider adapters behind a typed async `ModelProvider` interface and use HTTPX for Ollama, llama.cpp/OpenAI-compatible Chat Completions, and Anthropic Messages. Validate every response through Pydantic output schemas before returning it.
- **Privacy:** Cloud calls require a global deployment switch, tenant policy permission, and per-request consent. Detected raw telemetry also requires a tenant-specific override. Known credential, email, phone, and IP values are redacted before calls. Evaluation records store provider/model/latency/token counts/validation metadata only; prompts and completions are not retained.
- **Fallback:** Fallbacks are explicit per request and are individually checked against the same policy. No implicit local-to-cloud fallback is configured.
- **Consequences:** Providers can be swapped without changing agents. Provider credentials remain in environment-backed secret values. Current tenant identity is caller-supplied because authentication/RBAC is not yet implemented; the gateway is for a trusted local deployment until that phase is complete. Local model weights and hosted credentials are operator-provided.
