# NEURAL DETECT

Local-first security telemetry, detection engineering, threat intelligence, and AI security assurance.

## Quick setup in WSL Ubuntu

From the project directory, run:

    ./scripts/setup.sh

The setup script creates a private .env with fresh local secrets if one is not present, builds and starts this project's Docker Compose services, applies database migrations, installs Elasticsearch mappings, and seeds the starter detection rules.

Ollama is configured as a native WSL service. Start Ollama separately with ollama serve; then optionally pull the configured models with:

    ./scripts/setup.sh --pull-models

After the services are ready, use:

- Frontend: http://localhost:5173
- API documentation: http://localhost:8001/docs
- Kibana: http://localhost:5601
- Elasticsearch: http://localhost:9200

To download and index the official MITRE ATT&CK Enterprise bundle after setup:

    ./scripts/setup.sh --sync-attack

The ATT&CK sync downloads a large bundle and embeds its searchable content, so it can take several minutes. .env stays local and must not be committed. For hosted deployment, use managed secrets and review infrastructure/docker-compose.prod.yml; that overlay is not a hardened production deployment.

## Python development

Python 3.12 is required. The project and runtime dependencies are pinned in pyproject.toml and requirements.txt. Install development tools in a virtual environment:

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install -r requirements-dev.txt

The API and worker run from Compose. Run Compose commands from WSL when working in this environment.

## Project phases

- Detection rules are stored with version snapshots and compiled Sigma/EQL/ES|QL/KQL queries.
- The local-first model gateway enforces provider policy, redacts sensitive content, and validates structured model responses.
- The SOC agents generate constrained read-only hunts and evidence-based investigations.
- Threat intelligence ingests versioned MITRE ATT&CK/STIX content into PostgreSQL, Elasticsearch, and Qdrant.
- The AI Security Assurance Engine stores repeatable control evaluations and synthetic adversarial prompt results. Start it from the AI security assurance page or POST /api/v1/ai-security/evaluations.

The assurance dashboard currently reports a high-severity tenant identity-binding gap: tenant-scoped endpoints accept a caller-supplied tenant_id because authentication and RBAC are not yet implemented. The evaluation reports this honestly; do not expose the development API to untrusted networks.

## Validation

    ruff check apps ai_engine ai_security core detection_engine integrations scripts tests
    pytest
    python -m scripts.validate_detections

Frontend production build:

    docker compose run --rm --no-deps frontend npm run build

Phase screenshots are kept in artifacts. Heavy model weights, service data, local caches, and generated build outputs are excluded by .gitignore.
