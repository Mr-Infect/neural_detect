# ADR 0003: Store rule source, compiled query, and deployment separately

Status: accepted.

## Context

Detection rules need to remain reviewable and reproducible after conversion. Directly replacing Sigma YAML with an Elastic query would lose provenance and make revalidation, version history, and export unreliable. Enabling a rule is consequential and must not happen as an unreviewed import side effect.

## Decision

Store original Sigma YAML or native query, compiled query, and Kibana deployment representation in separate fields. Store immutable version snapshots on every update. Keep new detections disabled in their deployment representation. Require an expiring approval row and a configured reviewer token before deployment.

## Consequences

The rule library preserves source and compiled output independently. Reviewer identity is currently asserted by the token holder because application authentication/RBAC is not yet implemented; this is a known limitation. Kibana deployment also requires a secured, reachable Detection Engine.