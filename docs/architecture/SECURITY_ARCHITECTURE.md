# Security architecture

Sigma YAML is size-limited, loaded with safe YAML parsing, parsed by pySigma, and constrained to one rule with a stable UUID and ATT&CK tags. Elasticsearch fixture indices use a neural-detect-rule-tests-* namespace and are deleted in a finally block. Rule search/index patterns are restricted to neural-detect-*.

Deployment fails closed unless a matching approved approval record is unexpired. Reviewer decisions require ND_DETECTION_APPROVAL_TOKEN, compared without logging or returning the token. The shared-token model is an interim local control and does not replace authenticated reviewer accounts, RBAC, or tenant isolation.

The local Compose Elasticsearch/Kibana stack has security disabled. Keep it bound to a trusted development environment. Production TLS, authentication, RBAC, tenant isolation, and secret-management deployment are not complete.
## Model Gateway privacy controls (Phase 4)

Hosted inference is disabled globally by default. A hosted request requires global enablement, tenant allowlisting, and explicit request consent. The gateway redacts common credentials, emails, phone numbers, and IPs. It detects common ECS and security event structures and blocks them from hosted inference unless a separate tenant policy enables raw telemetry. Fallback providers are checked under the same policy. Evaluation persistence excludes prompts and completions. Tenant IDs are not authenticated yet, so deployments must remain on a trusted network until the planned authentication/RBAC phase.

## Phase 10 production boundary

Production-mode settings reject weak signing/admin/database secrets and require authenticated HTTPS Elasticsearch with certificate verification. The production-style Compose overlay binds UI/API ports to loopback, disables the unsecured bundled Elastic stack, and applies read-only filesystems/capability dropping to API, worker, and frontend. TLS termination, host firewall policy, external service hardening, secret-manager operation, and multi-host network isolation remain deployment responsibilities.
