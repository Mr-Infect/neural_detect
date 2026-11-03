# Release checklist

This release process is not complete until an owner verifies every item and records evidence.

- [ ] Select and add the project's LICENSE; confirm ownership and third-party notices.
- [ ] Add `.github/CODEOWNERS` after the maintainer GitHub account/team is confirmed.
- [ ] Configure GitHub private vulnerability reporting or publish a verified security contact.
- [ ] Review `CHANGELOG.md`, version, migrations, and upgrade/rollback notes.
- [ ] Run full CI, dependency audits, container scans, API/DB/Elastic integrations, and end-to-end workflow checks.
- [ ] Resolve the DiskCache transitive vulnerability without weakening the audit gate.
- [ ] Complete an independent security review and test a clean-host deployment and restore.
- [ ] Record performance/AI benchmark methodology and measured results; do not substitute expected values.
- [ ] Verify production external Elasticsearch is authenticated HTTPS, service ports are restricted, secrets are managed, and TLS is active at the public edge.
- [ ] Publish signed/tagged source and matching versioned images with SBOM/provenance only after all blocking items are closed.
