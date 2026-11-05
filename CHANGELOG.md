# Changelog

## Unreleased

- Added `ndctl import` (community Sigma rules such as SigmaHQ, with filters, ECS-field safety checks, and generated fixtures for simple rules) and `ndctl coverage` (ATT&CK tactic and technique coverage, optionally against MITRE's official bundle).
- Matching is now case-insensitive for process, user, host, file, registry, and DNS fields (lowercase normalizer in the ECS index template). Previously `CertUtil.exe` or `-URLCache` evaded rules written in lowercase. Applies to newly created indices.
- More Sysmon-style field names map to ECS (`Description`, `Product`, `Company`, `FileVersion` map to `process.pe.*`).
- Fixture placeholders named `TODO...` now fail `ndctl validate`.
- Added `ndctl`, a command line for detection-as-code: `validate`, `test`, `plan`, `apply`, `status`, `request-approval`, and `deploy` (see `docs/CLI.md`). CI now runs it.
- Detection rules are now scoped to a tenant. A rule ID is unique per tenant, rules and approvals from another tenant return 404, and administrators can act on another tenant with `?tenant_id=`. Migration `0011_detection_tenancy` assigns existing rules to the `default` tenant.
- Kibana rule IDs for non-default tenants are prefixed with the tenant slug, and every deployed rule is tagged `tenant:<slug>`.
- `scripts/seed_detections.py` accepts `--tenant`; the rule loader is shared in `detection_engine/library.py`.
- Fixed Kibana rule deployment: Kibana now receives a generated encryption key (`ND_KIBANA_ENCRYPTION_KEY`, created by `scripts/setup.sh`).
- Deploy payloads are built in one place, include threshold settings, and map Sigma severities to Kibana's.
- Community Sigma field names (Image, CommandLine, ...) are mapped to ECS when compiling.
- Fixture tests now run against a real Elasticsearch in CI (`validate_detections --live`).
- Elasticsearch security is now enabled in the development Compose stack (generated `ND_ELASTIC_PASSWORD` and `ND_KIBANA_SYSTEM_PASSWORD`); Kibana, Logstash, and the API authenticate. Without it Kibana could not show or run detection rules.
- Dashboard alerts are scoped by tenant from the stored alert source, because Kibana's alerts index does not map `tenant.id`.
- Detection page: run fixture tests, review approvals, and deploy from the UI; added `GET /detections/{id}/approvals`.

## 1.0.0-rc.1 — 2026-11-03

Release-candidate preparation for the unified platform.

- Added OPA-backed authorization, tenant scoping, account administration, audit records, and second-person response approvals.
- Added optional signed SOAR webhook dispatch; actions remain blocked when no provider is configured.
- Added local-first model gateway and AI security assurance workflows from earlier phases.
- Added production-mode configuration rejection for weak secrets and insecure Elasticsearch connections.
- Added non-root API and static frontend images plus a loopback-only production-style Compose overlay.
- Added CI, dependency update configuration, image SBOM/provenance generation, release image scanning, contributor templates, and release documentation.
- Performance, complete end-to-end/security test coverage, deployment restore drills, and AI evaluation benchmarks remain incomplete. No benchmark numbers are asserted.
- License selection and maintainer vulnerability contact are required before public distribution.
