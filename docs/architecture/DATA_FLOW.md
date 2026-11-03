# Detection data flow

1. A user submits Sigma YAML or a native EQL, ES|QL, KQL, or threshold rule to FastAPI.
2. Sigma source is parsed and validated; pySigma generates a Lucene query. Native rules are validated by format and platform index namespace.
3. PostgreSQL stores original source, generated query, deployment representation, metadata, and an initial version snapshot.
4. Validate/compile endpoints report stored representations. Test creates an isolated temporary Elasticsearch index, inserts submitted fixture events, executes the compiled rule, returns positive/negative outcomes, and deletes the test index.
5. A deploy request is denied unless an approval record is approved and unexpired. Kibana receives the deployment payload only after that check.
## AI inference flow (Phase 4)

UI/API request → tenant and cloud policy → sensitive data redaction and raw telemetry detection → provider adapter with timeout/retry → Pydantic output validation → response to caller; provider/model/latency/usage/validation metadata is stored separately without prompt or completion text.
