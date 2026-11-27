#!/usr/bin/env bash
# Deploys EDEL.TRAUD.AI on the server: fetch, build, restart, health check.
#
#   sudo /opt/edeltraud/ai-check/deploy/update.sh          # latest main
#   sudo /opt/edeltraud/ai-check/deploy/update.sh 1a2b3c4  # a specific commit (rollback)
#
# Needs: git, docker compose, /opt/edeltraud/api.env (see deploy/README.md).
set -euo pipefail

cd "$(dirname "$0")/.."
REF="${1:-main}"
COMPOSE=(docker compose -f deploy/compose.yaml)
ENV_FILE=/opt/edeltraud/api.env

[ -r "$ENV_FILE" ] || { echo "missing $ENV_FILE (see deploy/README.md)"; exit 1; }
before="$(git rev-parse --short HEAD)"

git fetch --quiet origin
if git show-ref --verify --quiet "refs/remotes/origin/$REF"; then
  git checkout --quiet "$REF"
  git merge --quiet --ff-only "origin/$REF"
else
  git checkout --quiet --detach "$REF"
fi
after="$(git rev-parse --short HEAD)"
echo "deploying $after (was $before)"

# Build first, restart afterwards: a failed build leaves the running version untouched.
"${COMPOSE[@]}" build api
"${COMPOSE[@]}" --profile jobs --profile watch build jobs watch

"${COMPOSE[@]}" up -d api

# If Caddy (or another proxy) runs in its own Docker container, 127.0.0.1 there is the proxy
# itself. PROXY_NETWORK in api.env names the proxy's Docker network; the API joins it under
# the name "edeltraud-api", so the Caddyfile says: reverse_proxy edeltraud-api:8787
PROXY_NETWORK="$( (grep -E '^PROXY_NETWORK=' "$ENV_FILE" || true) | tail -1 | cut -d= -f2- | tr -d '"'"'"' ')"
if [ -n "$PROXY_NETWORK" ]; then
  api_id="$("${COMPOSE[@]}" ps -q api)"
  if ! docker network inspect "$PROXY_NETWORK" >/dev/null 2>&1; then
    echo "PROXY_NETWORK=$PROXY_NETWORK does not exist (docker network ls)"; exit 1
  fi
  if ! docker inspect -f '{{json .NetworkSettings.Networks}}' "$api_id" | grep -q "\"$PROXY_NETWORK\""; then
    docker network connect --alias edeltraud-api "$PROXY_NETWORK" "$api_id"
    echo "api joined network $PROXY_NETWORK as edeltraud-api"
  fi
fi
if grep -Eq '^PADDLE_API_KEY=.+' "$ENV_FILE" && grep -Eq '^PADDLE_WEBHOOK_SECRET=.+' "$ENV_FILE"; then
  "${COMPOSE[@]}" --profile jobs up -d jobs
fi

for i in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8787/health >/dev/null 2>&1; then
    echo "ok: $after is live (health check passed after ${i}s)"
    docker image prune -f >/dev/null
    exit 0
  fi
  sleep 1
done

echo "health check failed – last log lines:"
"${COMPOSE[@]}" logs --tail 50 api
echo "roll back with: $0 $before"
exit 1
