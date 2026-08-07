#!/usr/bin/env bash
# One-shot local setup. Safe to re-run.
set -euo pipefail

cd "$(dirname "$0")"
say() { printf '\n\033[0;32m▸ %s\033[0m\n' "$1"; }
die() { printf '\n\033[0;31m✗ %s\033[0m\n' "$1" >&2; exit 1; }

command -v docker >/dev/null || die "Docker is not installed."
command -v node   >/dev/null || die "Node.js is not installed."

node_major=$(node -v | sed 's/v\([0-9]*\).*/\1/')
[ "$node_major" -ge 20 ] || die "Node 20+ required, found $(node -v)."

[ -f .env ] || { cp .env.example .env; say "Created .env from the example."; }

say "Starting Neo4j"
docker compose up -d neo4j

say "Waiting for Neo4j to accept connections"
for i in $(seq 1 60); do
  if docker exec nexus-neo4j cypher-shell -u neo4j -p nexus_dev_pass 'RETURN 1' >/dev/null 2>&1; then
    printf 'ready after %ss\n' "$i"; break
  fi
  [ "$i" -eq 60 ] && die "Neo4j did not come up. Check: docker compose logs neo4j"
  sleep 1
done

say "Installing API dependencies"
npm install --silent

say "Loading schema and sample data"
docker exec -i nexus-neo4j cypher-shell -u neo4j -p nexus_dev_pass < db/schema.cypher
docker exec -i nexus-neo4j cypher-shell -u neo4j -p nexus_dev_pass < db/seed.cypher

say "Converting edges into claims"
docker exec -i nexus-neo4j cypher-shell -u neo4j -p nexus_dev_pass < db/backfill-claims.cypher

say "Installing UI dependencies"
npm install --silent --prefix frontend

say "Running the test suite"
npm test

cat <<'DONE'

Setup finished. Two terminals:

  npm run dev                    API   -> http://localhost:3000
  npm run dev --prefix frontend  UI    -> http://localhost:5173

Neo4j browser: http://localhost:7474  (neo4j / nexus_dev_pass)

Then check the API answers:

  curl localhost:3000/api/health
  curl localhost:3000/api/analysis/chains

DONE
