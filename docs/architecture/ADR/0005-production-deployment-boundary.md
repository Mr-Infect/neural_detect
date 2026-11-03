# ADR 0005: production deployment boundary

- Status: Accepted for the v1.0.0 release candidate
- Date: 2026-11-03

## Context

The development Compose file publishes internal service ports and bundles an Elasticsearch instance with security disabled. The development frontend also runs the Vite server. Those defaults are convenient on a private workstation but are not safe production defaults.

## Decision

Keep the existing development profile behavior and add a separate production-style overlay. The overlay disables bundled Elasticsearch/Kibana/Logstash, binds UI/API to loopback, uses a static frontend image, and applies read-only filesystems, capability dropping, and no-new-privileges to application containers. Production-mode API settings require strong secrets and an authenticated HTTPS Elasticsearch endpoint with certificate verification.

## Consequences

The production overlay requires a secured external Elasticsearch deployment and an external TLS reverse proxy. It is a single-host baseline, not a high-availability or compliance profile. Local development remains unchanged.
