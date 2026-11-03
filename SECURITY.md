# Security policy

## Supported version

Security fixes are developed against the current default branch. There is not yet a published stable release or a guaranteed backport policy.

## Reporting a vulnerability

Do not report exploitable vulnerabilities, credentials, personal information, or customer telemetry through a public issue. Use GitHub's private vulnerability reporting for this repository if the owner has enabled it. If private reporting is unavailable, contact the repository owner through a verified private channel and share only the minimum details needed to reproduce the issue. The maintainers need to configure and publish a dedicated security contact before a public release.

Please include affected version/commit, impact, prerequisites, a minimal reproduction, and a suggested mitigation where known. Allow maintainers reasonable time to investigate and coordinate a fix before public disclosure.

## Operational security

- Keep `.env` mode 0600 and use a secret manager for deployed environments.
- Rotate the application signing key and bootstrap credentials if exposed.
- Use authenticated HTTPS Elasticsearch in production; production-mode settings reject development defaults.
- Put the UI/API behind TLS, restrict internal service ports, and review Compose exposure.
- Keep agents read-only by default and use the audited approval flow for consequential actions.
- Treat LLM output, telemetry, detection source, webhooks, and retrieved content as untrusted input.
- Review dependency and container scan results before publishing images.

Security controls reduce risk but do not constitute a certification or penetration test.

## Current dependency finding

The current pySigma 1.5.1 release requires DiskCache 5.6.3, which pip-audit reports as PYSEC-2026-2447 because cache files use pickle deserialization. The Elasticsearch pySigma backend currently constrains pySigma to below 2.0, so pySigma 2.0 cannot yet replace this dependency without breaking rule conversion. The application does not use pySigma's ATT&CK/D3FEND disk-cache code paths, and the API/worker images run as non-root; production app containers also use read-only root filesystems. This is a known residual risk. CI keeps the audit blocking until an upstream-compatible upgrade is available.
