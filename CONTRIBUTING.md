# Contributing

## Before opening an issue or pull request

Read `README.md`, `ARCHITECTURE.md`, `SECURITY.md`, and the relevant module README. For suspected vulnerabilities, follow `SECURITY.md` and do not post exploit details or sensitive telemetry in a public issue.

## Development environment

Use WSL Ubuntu 22.04 or Linux for Docker work. Run `./scripts/setup.sh`, create a Python 3.12 virtual environment, install `requirements-dev.txt`, and use Node 22 for frontend changes. Keep `.env`, service data, tokens, model weights, and customer telemetry out of Git.

## Validation

Run the checks relevant to the change before requesting review:

```bash
ruff check apps ai_engine ai_security core detection_engine integrations scripts tests
pytest -q
python -m scripts.validate_detections
(cd apps/frontend && npm ci && npm run build)
docker compose config --quiet
docker compose -f docker-compose.yml -f infrastructure/docker-compose.prod.yml config --quiet
```

If UI files change, capture and inspect a browser screenshot at a representative viewport. If a migration, API, provider, or Compose service changes, validate against the available running services and describe anything that could not be exercised.

## Pull requests

Use the pull request template. Keep changes focused, include migration and rollback notes, document new configuration, and state test results and known limitations. Do not include fabricated telemetry or benchmark results. New externally visible modules need a README describing purpose, architecture, dependencies, configuration, usage, interface, tests, and limitations.

## License status

The repository has not selected a license yet. Until a project owner adds the chosen license, contributors should not assume permission to redistribute or relicense the project. The release workflow intentionally refuses to publish without `LICENSE`.
