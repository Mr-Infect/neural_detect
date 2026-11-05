# Database schema

Alembic migrations are authoritative.

- tenants, users: initial platform identity foundation.
- telemetry_sources: registered collector metadata; credentials are prohibited in source configuration.
- detection_rules: owning tenant, stable rule ID (unique per tenant), current format/source/query/deployment and metadata, current version.
- detection_rule_versions: immutable snapshots keyed by detection and version.
- detection_approvals: pending/approved/rejected deployment requests bound to a rule version, with reviewer, note, timestamps, and expiry.

Detection source, compiled query, and deployment data remain separate. A rule mutation increments current_version and inserts a snapshot in the same transaction. Foreign-key deletion cascades only from a detection to its version/approval history.
## Model evaluations (Phase 4)

`model_evaluations` stores tenant, provider, model name/version, output kind, latency, token usage, schema validity, error code, and safe evaluation metadata. Request prompts and model completions are intentionally excluded.
