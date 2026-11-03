# Detection as Code Engine

## Purpose and architecture

The engine stores source rules and immutable version snapshots in PostgreSQL. Sigma YAML is parsed and schema-checked by pySigma, then compiled by the official pySigma Elasticsearch backend. Native EQL, ES|QL, KQL, and threshold formats are represented separately from their deployment payloads.

## Configuration and dependencies

Python 3.12+, PostgreSQL, Elasticsearch/Kibana, pySigma, and pySigma-backend-elasticsearch are required. Versions are pinned in the root pyproject.toml. Deployment approvals require ND_DETECTION_APPROVAL_TOKEN; keep it only in the local environment or an external secret manager.

## Usage

Import a single Sigma rule with POST /api/v1/detections and {"source_yaml":"..."}. Native rules use format, metadata, query, and index. Validate and compile with their respective action endpoints. Export returns the current Sigma source. Seed the initial library after migrations with python -m scripts.seed_detections.

## Approval and deployment

Deployment is fail-closed. A rule must have a non-expired approved request. Reviewer decisions require the shared approval token and record reviewer identity, decision, and timestamp. The token is not a substitute for user authentication/RBAC; reviewer identity must come from a trusted deployment environment.

## Tests and limitations

Automated tests cover schema and metadata validation, compilation, version snapshots, native formats, and fixture matching. Kibana detection rule deployment requires a configured, reachable Kibana Security Detection Engine. The local Phase 2 Compose cluster currently has Elasticsearch security disabled.