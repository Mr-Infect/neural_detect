# API reference

The FastAPI OpenAPI document is generated from the running application at `/openapi.json`; interactive docs are served at `/docs` in the development configuration. Production deployments should expose documentation only through their approved access policy.

Unless listed as public below, routes require `Authorization: Bearer <token>`. Obtain a token with `POST /api/v1/auth/login`. `GET /api/v1/auth/me` returns the authenticated user, role, and tenant. Authorization is checked by the API and OPA on each request. A requested tenant outside the user's scope is denied.

## Public routes

- `GET /health`
- `GET /api/v1/health`
- `GET /api/v1/health/dependencies`
- `GET /api/v1/system/info`
- `POST /api/v1/auth/login`
- `/docs`, `/openapi.json`, `/redoc` (development documentation)

## Route groups

- Identity, role, tenant, integration, and audit administration: `/api/v1/auth/*` (administrator role).
- Automation approvals and SOAR operations: `/api/v1/automation/*`.
- Detection rules and deployment approvals: `/api/v1/detections/*`, `/api/v1/detection-lifecycle/*`.
- Telemetry, health, source registration, search, ES|QL, EQL, and alerts: `/api/v1/telemetry/*`.
- Overview data: `/api/v1/dashboard/*`.
- SOC hunting/investigations: `/api/v1/soc-agents/*`.
- Intelligence ingestion and search: `/api/v1/intelligence/*`.
- Model gateway: `/api/v1/models/*`.
- AI detection engineering: `/api/v1/ai/detection/*`.
- Agent security evaluations: `/api/v1/ai-security/*`.

The live OpenAPI document is the source of truth for operation schemas, response fields, status codes, and query parameters. Common authorization failures are 401 for missing/invalid sessions, 403 for denied role or tenant scope, 409 for an unavailable or stale approved action, and 503 when OPA is unavailable. Do not treat this summary as a substitute for version-specific OpenAPI.
