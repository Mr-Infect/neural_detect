# NEURAL DETECT architecture

NEURAL DETECT is a local-first modular monolith. FastAPI exposes versioned endpoints. PostgreSQL stores operational state, users, tenants, approvals, audit events, and detection/intelligence records. Elasticsearch stores and queries security telemetry. Qdrant supports vector retrieval. Redis backs asynchronous processing. OPA makes role and tenant authorization decisions. The worker handles background tasks. Ollama and other model adapters sit behind a provider-neutral model gateway.

The browser application is a React/TypeScript SPA. Development uses Vite; production builds static assets into a minimal Node runtime that proxies API traffic within the Compose network. External TLS is provided by the deployment's reverse proxy.

See [system architecture](docs/architecture/SYSTEM_ARCHITECTURE.md), [data flow](docs/architecture/DATA_FLOW.md), [database schema](docs/architecture/DATABASE_SCHEMA.md), [API specification](docs/architecture/API_SPECIFICATION.md), [agent architecture](docs/architecture/AGENT_ARCHITECTURE.md), and [security architecture](docs/architecture/SECURITY_ARCHITECTURE.md). Decisions are recorded under `docs/architecture/ADR/`.

The production-style Compose overlay is single-host and not a complete high-availability design. The bundled Elasticsearch configuration disables built-in security for development; production settings reject an unauthenticated or non-HTTPS Elasticsearch connection.
