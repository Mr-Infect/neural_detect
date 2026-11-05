#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"

PULL_MODELS=false
SYNC_ATTACK=false
for arg in "$@"; do
  case "$arg" in
    --pull-models) PULL_MODELS=true ;;
    --sync-attack) SYNC_ATTACK=true ;;
    -h|--help)
      cat <<'HELP'
Usage: ./scripts/setup.sh [--pull-models] [--sync-attack]

Build and start this project's Docker Compose services, create local secrets if
.env does not exist, apply migrations, install Elasticsearch mappings, and
seed starter detection rules.

  --pull-models  Pull llama3.2:3b and nomic-embed-text from a running native
                 Ollama server in WSL.
  --sync-attack  Download and embed the official MITRE ATT&CK bundle after
                 setup. This can take a while.
HELP
      exit 0
      ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

command -v docker >/dev/null || { echo "Docker is required in WSL." >&2; exit 1; }
docker compose version >/dev/null || { echo "Docker Compose v2 is required." >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required." >&2; exit 1; }

if [[ ! -f .env ]]; then
  command -v openssl >/dev/null || { echo "openssl is required to create local secrets." >&2; exit 1; }
  cp .env.example .env
  DB_PASSWORD="$(openssl rand -hex 32)"
  APP_SECRET="$(openssl rand -hex 32)"
  ADMIN_PASSWORD="$(openssl rand -hex 32)"
  sed -i "s#^POSTGRES_PASSWORD=.*#POSTGRES_PASSWORD=$DB_PASSWORD#" .env
  sed -i "s#^ND_DATABASE_URL=.*#ND_DATABASE_URL=postgresql+asyncpg://neural:$DB_PASSWORD@postgres:5432/neural_detect#" .env
  sed -i "s#^ND_SECRET_KEY=.*#ND_SECRET_KEY=$APP_SECRET#" .env
  sed -i "s#^ND_BOOTSTRAP_ADMIN_PASSWORD=.*#ND_BOOTSTRAP_ADMIN_PASSWORD=$ADMIN_PASSWORD#" .env
  chmod 600 .env
  echo "Created .env with fresh local secrets."
fi

if ! grep -q '^ND_BOOTSTRAP_ADMIN_EMAIL=' .env; then
  printf '%s\n' 'ND_BOOTSTRAP_ADMIN_EMAIL=admin@neural-detect.local' >> .env
fi
if ! grep -q '^ND_BOOTSTRAP_ADMIN_PASSWORD=' .env || grep -q '^ND_BOOTSTRAP_ADMIN_PASSWORD=generate-a-random-32-byte-secret$' .env; then
  ADMIN_PASSWORD="$(openssl rand -hex 32)"
  if grep -q '^ND_BOOTSTRAP_ADMIN_PASSWORD=' .env; then
    sed -i "s#^ND_BOOTSTRAP_ADMIN_PASSWORD=.*#ND_BOOTSTRAP_ADMIN_PASSWORD=$ADMIN_PASSWORD#" .env
  else
    printf 'ND_BOOTSTRAP_ADMIN_PASSWORD=%s\n' "$ADMIN_PASSWORD" >> .env
  fi
fi
if ! grep -q '^ND_KIBANA_ENCRYPTION_KEY=' .env || grep -q '^ND_KIBANA_ENCRYPTION_KEY=generate-with-openssl-rand-hex-32$' .env; then
  KIBANA_KEY="$(openssl rand -hex 32)"
  if grep -q '^ND_KIBANA_ENCRYPTION_KEY=' .env; then
    sed -i "s#^ND_KIBANA_ENCRYPTION_KEY=.*#ND_KIBANA_ENCRYPTION_KEY=$KIBANA_KEY#" .env
  else
    printf 'ND_KIBANA_ENCRYPTION_KEY=%s\n' "$KIBANA_KEY" >> .env
  fi
fi
set_env() {
  if grep -q "^$1=" .env; then sed -i "s#^$1=.*#$1=$2#" .env; else printf '%s=%s\n' "$1" "$2" >> .env; fi
}
for key in ND_ELASTIC_PASSWORD ND_KIBANA_SYSTEM_PASSWORD; do
  if ! grep -q "^$key=." .env || grep -q "^$key=generate-with-openssl-rand-hex-32$" .env; then
    set_env "$key" "$(openssl rand -hex 32)"
  fi
done
ES_PASSWORD="$(grep '^ND_ELASTIC_PASSWORD=' .env | cut -d= -f2-)"
set_env ND_ELASTICSEARCH_USERNAME elastic
set_env ND_ELASTICSEARCH_PASSWORD "$ES_PASSWORD"
for entry in 'ND_OPA_URL=http://opa:8181' 'ND_SOAR_WEBHOOK_URL=' 'ND_SOAR_WEBHOOK_TOKEN='; do
  key="${entry%%=*}"
  grep -q "^$key=" .env || printf '%s\n' "$entry" >> .env
done
chmod 600 .env

if grep -Eq '^(POSTGRES_PASSWORD|ND_SECRET_KEY|ND_BOOTSTRAP_ADMIN_PASSWORD|ND_KIBANA_ENCRYPTION_KEY|ND_ELASTIC_PASSWORD|ND_KIBANA_SYSTEM_PASSWORD|ND_ELASTICSEARCH_PASSWORD)=((replace-me)|(replace-with-a-random-secret-before-deployment)|(generate-a-random-32-byte-secret)|(generate-with-openssl-rand-hex-32))$' .env; then
  echo ".env still contains example secrets. Replace them before setup." >&2
  exit 1
fi

if [[ "$PULL_MODELS" == true ]]; then
  command -v ollama >/dev/null || { echo "Install Ollama in WSL before using --pull-models." >&2; exit 1; }
  curl -fsS http://127.0.0.1:11434/api/tags >/dev/null || {
    echo "Start the native WSL Ollama server first (ollama serve)." >&2; exit 1;
  }
  ollama pull llama3.2:3b
  ollama pull nomic-embed-text
fi

docker compose up -d --build --wait --wait-timeout 300

wait_for_url() {
  local url="$1" auth="${2:-}" attempt
  for attempt in $(seq 1 90); do
    if curl -fsS ${auth:+-u "$auth"} "$url" >/dev/null; then return 0; fi
    sleep 2
  done
  echo "Timed out waiting for $url" >&2
  return 1
}

wait_for_url http://127.0.0.1:8181/health
wait_for_url http://127.0.0.1:9200/ "elastic:$ES_PASSWORD"
wait_for_url http://127.0.0.1:8001/api/v1/health

docker compose run --rm --no-deps api alembic upgrade head
docker compose run --rm --no-deps api python -m scripts.setup_elastic
docker compose run --rm --no-deps api python -m scripts.seed_detections

if [[ "$SYNC_ATTACK" == true ]]; then
  curl -fsS -X POST http://127.0.0.1:8001/api/v1/intelligence/sync \
    -H 'Content-Type: application/json' \
    -d '{"tenant_id":"default","source":"mitre_attack"}'
  echo
fi

echo
echo "NEURAL DETECT is ready:"
echo "  Frontend:  http://localhost:5173"
echo "  API docs:  http://localhost:8001/docs"
echo "  Kibana:    http://localhost:5601 (sign in as elastic; password is ND_ELASTIC_PASSWORD in ignored .env)"
echo "  Login:     admin@neural-detect.local (password is stored in ignored .env)"
docker compose ps
