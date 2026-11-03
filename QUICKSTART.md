# NEURAL DETECT quickstart

## Requirements

- WSL 2 with Ubuntu 22.04 (or a Linux host), Docker Engine, and Docker Compose v2.
- At least 8 GB RAM for the default Elasticsearch heap plus application services; local inference needs additional model memory.
- Python 3.12 and Node 22 only for host development. Runtime services use the pinned container images and project dependency locks.

## First start

From WSL, change to the repository and run:

```bash
./scripts/setup.sh
```

The script creates a mode-0600 ignored `.env` when absent, generates database/application/admin secrets, builds the development images, waits for dependencies, applies Alembic migrations, prepares Elasticsearch, and seeds the versioned starter rule library. The bootstrap administrator is `admin@neural-detect.local`; retrieve the generated password locally with `grep '^ND_BOOTSTRAP_ADMIN_PASSWORD=' .env` and never paste it into logs or source control.

Open `http://localhost:5173`, sign in, and verify:

```bash
curl -fsS http://localhost:8001/api/v1/health
curl -fsS http://localhost:8181/health
# /api/v1/health/dependencies requires an authenticated bearer token
```

Use `docker compose ps` from the repository directory to inspect only this project. Use `docker ps` to inspect all WSL containers. Do not use `docker compose down -v` on a shared development host; it deletes this project's persistent data.

## Local model

The default model gateway expects native Ollama in WSL. Start Ollama separately, then run `./scripts/setup.sh --pull-models` to pull the configured chat and embedding models. Model files are local and excluded from Git.

## Real telemetry and detections

Configure a real collector using `docs/telemetry/README.md` and `infrastructure/telemetry/`. Run `python -m scripts.validate_detections` to validate every library rule and fixture. Send controlled lab telemetry before interpreting dashboard counts; empty indices are reported as empty rather than populated with examples.

## Upgrade and recovery

Back up PostgreSQL and Elasticsearch snapshots before upgrades. Then fetch the intended source revision and run `docker compose up -d --build --wait`, followed by `docker compose exec api alembic current`. To stop this project without deleting volumes use `docker compose down`; keep the volumes for restart. Database restore procedures are in `docs/DEPLOYMENT.md`.

## Production-style deployment

Read `docs/DEPLOYMENT.md` before using the production overlay. It requires non-default secrets and authenticated HTTPS Elasticsearch; the development `.env` is deliberately rejected in production mode. The overlay binds the UI and API to loopback and assumes an external TLS reverse proxy. It is a single-host deployment pattern, not a substitute for a reviewed multi-node production design.
