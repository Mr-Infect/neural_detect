# Model configuration

## Provider architecture

The model gateway provides provider adapters behind a common request interface. The default profile is local Ollama. Model provider, name, timeout, retries, cloud policy, redaction, and tenant policy are configured through `ND_AI_*`, `ND_OLLAMA_*`, `ND_OPENAI_*`, and `ND_ANTHROPIC_*` variables in `.env`. Use `.env.example` as the key inventory and never commit credentials.

## Local Ollama

Run Ollama in WSL and start the Compose relay. Set `ND_OLLAMA_URL=http://host.docker.internal:11435` and choose a model already available from `ollama list`. `./scripts/setup.sh --pull-models` pulls the default chat and embedding models. Model weight storage remains outside Git and can require several gigabytes.

## Cloud providers

Cloud inference is disabled by default. Enable it only after security/privacy review, tenant consent and policy configuration. Raw telemetry is blocked from cloud providers; redaction and structured-output validation apply before data leaves the local gateway. Configure only the provider's API key through the local secret file or secret manager. Review provider retention, data residency, and contractual terms independently.

## Resource sizing and provenance

Record the exact model identifier/tag, quantization, provider, runtime, context length, embedding model, hardware, and settings when evaluating results. A `:latest` tag can change behavior; pin a specific local tag or immutable provider model version for repeatable evaluations. Performance depends on available RAM/VRAM and concurrency. The repository has not published measured latency or accuracy claims; see `BENCHMARKS.md`.
