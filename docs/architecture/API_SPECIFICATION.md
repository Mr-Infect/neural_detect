# API specification

All routes are versioned under /api/v1.

Detection lifecycle:
- GET /detections — list stored rules.
- POST /detections — import one Sigma YAML rule or create a native rule.
- GET /detections/{uuid} — read a rule.
- PATCH /detections/{uuid} — create a new version.
- POST /detections/{uuid}/validate — schema and metadata validation plus compilation.
- POST /detections/{uuid}/compile — return source, compiled query, deployment representation.
- GET /detections/{uuid}/export — download original Sigma YAML.
- POST /detections/{uuid}/test — execute positive/negative fixtures against a temporary Elasticsearch index.
- POST /detections/{uuid}/approvals — request deployment approval.
- POST /detections/approvals/{uuid}/review — record a reviewer decision with X-Approval-Token.
- POST /detections/{uuid}/deploy?approval_id={uuid} — deploy via Kibana only with a matching, unexpired approved request for the current rule version.

Phase 2 Kibana rule proxy remains at GET/POST /detections/rules. See the FastAPI OpenAPI page at /docs for request schemas.
## Phase 4 — Model Gateway

- `GET /api/v1/ai/models/providers` reports safe configuration and health metadata.
- `POST /api/v1/ai/models/infer` accepts a tenant identifier, prompt, output schema kind, provider/model selection, explicit cloud consent, raw telemetry declaration, and fallback list.
- `GET /api/v1/ai/models/evaluations` returns recent metadata for the requested tenant. Prompts and completions are omitted.

Hosted inference returns 403 unless deployment-level cloud access, tenant policy, and request consent all allow it. Raw telemetry patterns require an additional tenant policy override.
