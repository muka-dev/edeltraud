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

# compose.yaml puts the API into the proxy's Docker network (alias "edeltraud-api"), so a
# recreate never drops it. PROXY_NETWORK in api.env names that network (default: proxy).
PROXY_NETWORK="$( (grep -E '^PROXY_NETWORK=' "$ENV_FILE" || true) | tail -1 | cut -d= -f2- | tr -d '"'"'"' ')"
export PROXY_NETWORK="${PROXY_NETWORK:-proxy}"
if ! docker network inspect "$PROXY_NETWORK" >/dev/null 2>&1; then
  echo "Docker network $PROXY_NETWORK missing (docker network ls; set PROXY_NETWORK in $ENV_FILE)"; exit 1
fi

# One-time switch from the old project name "deploy" (folder name) to "edeltraud": remove the
# old containers first, otherwise they keep port 8787. Matches only this checkout's folder.
old_ids="$(docker ps -aq --filter label=com.docker.compose.project=deploy \
  --filter "label=com.docker.compose.project.working_dir=$PWD/deploy")"
if [ -n "$old_ids" ]; then
  echo "removing old containers of project \"deploy\": $(docker ps -a --format '{{.Names}}' --filter label=com.docker.compose.project=deploy --filter "label=com.docker.compose.project.working_dir=$PWD/deploy" | tr '\n' ' ')"
  docker rm -f $old_ids >/dev/null
  docker network rm deploy_default deploy_egress >/dev/null 2>&1 || true
fi

"${COMPOSE[@]}" up -d api

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
