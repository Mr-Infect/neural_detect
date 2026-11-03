# Changelog

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
