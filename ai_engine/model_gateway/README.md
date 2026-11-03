# Hybrid AI Model Gateway

The gateway routes typed inference requests to configurable local and hosted providers. Prompts are bounded, sensitive values are redacted before provider calls, and hosted inference is denied unless both tenant policy and explicit request consent allow it. Provider credentials are read from environment variables and are never returned by the API.

## Architecture

`router.py` applies tenant privacy policy, redacts user content, limits rate, invokes provider adapters with timeout/retry/fallback controls, validates typed output, and records evaluation metadata in PostgreSQL. Provider adapters use Ollama's local chat API, llama.cpp and OpenAI-compatible Chat Completions, and Anthropic Messages.

## Configuration

See `.env.example` for provider URLs, model names, hosted API credentials, retry and size limits, and the global cloud inference switch. Local Ollama is available through the `local-ai` Compose profile. No model download occurs automatically.

## Usage and API

`POST /api/v1/ai/models/infer` executes one inference. `GET /api/v1/ai/models/providers` reports configuration and health without exposing credentials. `GET /api/v1/ai/models/evaluations` returns persisted latency, model, provider, token usage, and validation status.

## Tests and limitations

Unit tests exercise redaction, policy decisions, structured outputs, retry/fallback and provider protocol parsing with deterministic fake HTTP transports. A real local model requires a configured Ollama or llama.cpp server and model. Hosted inference requires user-managed credentials and explicit cloud consent. Tenant identity must be supplied by a trusted deployment boundary until authentication/RBAC is implemented.

