# System architecture

NEURAL DETECT is a local-first modular monolith with a FastAPI API, React/TypeScript frontend, PostgreSQL operational store, Elasticsearch telemetry/detection store, Logstash Beats input, Kibana detection integration, Redis worker queue, Qdrant, OPA, and OpenTelemetry Collector.

The Phase 3 detection engine is isolated under detection_engine/. It validates Sigma source using pySigma and compiles through pySigma-backend-elasticsearch. PostgreSQL stores rule source, compiled query, deployment representation, version history, and approval records. Elasticsearch executes fixture tests; Kibana Security Detection Engine is the deployment target after approval.

See DATABASE_SCHEMA.md, API_SPECIFICATION.md, SECURITY_ARCHITECTURE.md, and DATA_FLOW.md for current interfaces and constraints.
## Phase 4 Model Gateway

The FastAPI process includes an asynchronous provider-neutral model gateway. Ollama and llama.cpp are local adapters; OpenAI-compatible and Anthropic Messages providers are optional hosted adapters. A policy/redaction/validation layer wraps every inference call, and PostgreSQL stores request evaluation metadata without prompts or completions.
