# Deployment, backup, and upgrade

## Development Compose

Use `./scripts/setup.sh` from the repository root in WSL. It builds development containers, creates local secrets, applies migrations, and prepares Elasticsearch. Review `docker compose ps` and health endpoints before operating the UI.

## Production-style local Compose

The production overlay is intended for a private single host behind a separately managed HTTPS reverse proxy. It binds only `127.0.0.1:5173` and `127.0.0.1:8001`, runs API/worker/frontend read-only where supported, drops Linux capabilities, enables `no-new-privileges`, and uses the static frontend image. Validate without starting containers:

```bash
docker compose -f docker-compose.yml -f infrastructure/docker-compose.prod.yml config --quiet
```

Before starting, set `ND_ENVIRONMENT=production`, a random `ND_SECRET_KEY` with at least 32 characters, a unique bootstrap password of at least 20 characters, a non-default database password, and an authenticated `https://` Elasticsearch endpoint with certificate verification. The bundled single-node Elasticsearch, Kibana, and Logstash services are disabled by the production overlay because the bundled Elasticsearch has security disabled for development and is not accepted as a production endpoint. Configure an external secured endpoint and credentials in `.env` or the deployment secret manager. Keep `.env` mode 0600 and out of source control.

The frontend/API loopback listeners do not provide TLS. Terminate TLS at a maintained reverse proxy, configure HTTPS and secure headers there, restrict access to that proxy, and verify the resulting external URL. Do not expose Postgres, Redis, Qdrant, Elasticsearch, Kibana, OPA, Logstash, OTEL, or the Ollama relay to an untrusted network. Use managed external services with authentication and TLS for internet-facing deployments.

Start only after configuration review:

```bash
docker compose -f docker-compose.yml -f infrastructure/docker-compose.prod.yml up -d --build --wait
```

The application applies Alembic migrations during API startup. For a controlled maintenance window, inspect the migration head and take a backup first. Do not use `down -v` when preserving data.

## Backups

Back up PostgreSQL with `pg_dump -Fc` and store the output in encrypted off-host storage. Create Elasticsearch snapshots through a configured snapshot repository; filesystem copies of a live data directory are not a reliable backup. Back up external OPA policy/configuration, deployment secrets in the approved secrets manager, and custom detection/telemetry configuration separately. Qdrant collections can be exported using its snapshot API. Record backup checksums and test restores in an isolated environment before relying on them.

This repository does not currently automate snapshot retention or perform a full restore drill. Owners must choose retention, encryption, RPO/RTO, and off-site policy for their environment.

## Upgrade and rollback

1. Read release notes and dependency advisories.
2. Take and verify a database backup and Elasticsearch snapshot.
3. Validate Compose files and the new migration head.
4. Build/pull the intended versioned images and run the deployment.
5. Check API/dependency health, OPA, frontend, and `alembic current`.
6. Roll back application images if needed. Database downgrade is not guaranteed; restore from the verified backup when a migration is not backward-compatible.

Never roll back a database migration manually. Review each Alembic revision before applying it.
