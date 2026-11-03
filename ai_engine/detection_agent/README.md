# Phase 5 — AI Detection Engineer
LangGraph coordinates candidate generation, independent Sigma validation and Elasticsearch compilation, duplicate lookup, and positive/negative fixture tests. Provenance stores source SHA-256, prompt version, provider/model, candidate, validation, and benchmark. Raw input remains in process memory during the request; checkpoints use AES encryption derived from the app secret. Candidates cannot deploy or merge; passing validation requires human review.
Routes: POST /api/v1/ai/detection/generate, /improve, /explain; GET /api/v1/ai/detection/jobs/{id}.

