# Threat model

## Scope and assets

This model covers the single-host Compose deployment and its API, frontend, PostgreSQL, Elasticsearch, Qdrant, Redis, OPA, worker, model gateway, and optional Ollama/SOAR connections. Assets include credentials, tenant data, security telemetry, detection rules, approvals, audit history, model prompts/results, and service availability.

## Trust boundaries

1. Browser to API: bearer token over HTTP in local development; production requires external TLS.
2. API to PostgreSQL/Elasticsearch/Qdrant/Redis/OPA: Docker network; production must provide authenticated HTTPS Elasticsearch and protect service networking.
3. API/worker to model providers: local Ollama is preferred. Cloud inference requires explicit policy/consent and redaction checks.
4. API to SOAR webhook: optional outbound integration; response operations require a reviewed approval.
5. Telemetry, threat intelligence, model output, and tool results: untrusted data crossing into query, prompt, and workflow code.
6. Host to containers: image build, environment secrets, Docker daemon, and persistent volumes.

## Threat actors and abuse cases

- A stolen or guessed account attempts privilege escalation, cross-tenant reads, or approval self-review.
- Malicious telemetry, prompts, retrieval content, or model output attempts injection or data exfiltration.
- A compromised API, worker, or dependency attempts lateral movement or credential theft.
- A malicious/compromised webhook or external model provider receives sensitive information or triggers an unauthorized action.
- An operator accidentally exposes service ports, commits `.env`, or loses durable data during upgrade.
- Denial of service consumes model, query, queue, or storage resources.

## Current controls

Password hashing uses PBKDF2, sessions are signed and expire, user state/tenant/role are checked against PostgreSQL per request, OPA fails closed, cross-tenant request scopes are denied, and consequential automation actions require another authorized reviewer. Audit events are recorded for security-sensitive operations. Production settings reject weak application/database secrets and insecure Elasticsearch URLs. Production Compose restricts published ports to loopback and drops capabilities for application containers. The API and frontend images run without root privileges.

## Residual risks and out-of-scope work

- The bundled development Elasticsearch disables native authentication and TLS. It is not suitable for production; the production-mode API requires an external authenticated HTTPS Elasticsearch endpoint.
- The production-style Compose overlay is single-host, and the Docker bridge is not a strong isolation boundary. Use network segmentation, host firewalling, managed secrets, backups, and a reviewed reverse proxy.
- Browser tokens use local storage and require HTTPS in deployments; XSS prevention and browser policy remain important.
- Webhook URL allowlisting/egress control, replay protection, rate limiting, and provider-specific signatures need deployment and integration review.
- No independent penetration test, container scan, full integration/e2e suite, restore drill, load test, or AI benchmark has been completed in this phase.
- The project license and maintainer vulnerability contact are not selected/configured yet.

Update this document when trust boundaries, data flows, or response capabilities change. This is a working threat model, not a security certification.
