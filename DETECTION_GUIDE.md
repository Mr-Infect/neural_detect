# Detection engineering guide

## Rule lifecycle

1. Author a Sigma YAML rule with a stable UUID, title, status, log source, detection, and tags in `detection_rules/library/`.
2. Add positive and negative JSON fixtures under `detection_rules/fixtures/` using the same rule stem.
3. Run `python -m scripts.validate_detections` and review pySigma compilation output.
4. Create or update a rule using the versioned detection API. Review source and compiled query output independently.
5. Request deployment approval for the exact rule version. A changed version invalidates an earlier approval.
6. A different authorized reviewer approves or rejects. Rejection reason and lifecycle events are audited.
7. Deploy only after the approval gate succeeds; confirm the rule in Kibana/Elasticsearch.

## Safety

Generated Sigma is untrusted candidate content. Validate the schema, compile it with the target backend, inspect index scope and query cost, run positive/negative fixtures, and obtain human review. Do not deploy from generated output alone. Test in a lab index first and record the target version. Keep fixture events synthetic and do not place customer telemetry in Git.

Native query and index validation deliberately restrict targets to the `neural-detect-*` namespace. See `detection_engine/README.md` for compiler/validator limitations.
