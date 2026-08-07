#!/usr/bin/env bash
# Bring up nexus: start Neo4j in Docker, wait for it, load schema/seed/
# backfill, install deps, run the test suite. Re-running this script wipes
# and recreates the Neo4j container so the graph always starts from the
# same known seed state.
set -euo pipefail

CONTAINER_NAME="nexus-neo4j"
NEO4J_PASSWORD="${NEO4J_PASSWORD:-nexuspassword}"
BOLT_PORT="${BOLT_PORT:-7687}"
HTTP_PORT="${HTTP_PORT:-7474}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==> Resetting Neo4j container (${CONTAINER_NAME})"
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

echo "==> Starting Neo4j"
docker run -d --name "$CONTAINER_NAME" \
  -p "${HTTP_PORT}:7474" -p "${BOLT_PORT}:7687" \
  -e NEO4J_AUTH="neo4j/${NEO4J_PASSWORD}" \
  neo4j:5-community >/dev/null

echo "==> Waiting for Neo4j to answer on bolt://localhost:${BOLT_PORT}"
attempts=60
until docker exec "$CONTAINER_NAME" cypher-shell -u neo4j -p "$NEO4J_PASSWORD" "RETURN 1;" >/dev/null 2>&1; do
  attempts=$((attempts - 1))
  if [ "$attempts" -le 0 ]; then
    echo "Neo4j did not become ready in time" >&2
    docker logs "$CONTAINER_NAME" --tail 100 >&2
    exit 1
  fi
  sleep 2
done
echo "==> Neo4j is up"

run_cypher_file() {
  local file="$1"
  echo "==> Loading ${file}"
  if ! docker exec -i "$CONTAINER_NAME" cypher-shell -u neo4j -p "$NEO4J_PASSWORD" < "$file"; then
    echo "Failed loading ${file} - see cypher-shell output above" >&2
    exit 1
  fi
}

run_cypher_file db/schema.cypher
run_cypher_file db/seed.cypher
run_cypher_file db/backfill-claims.cypher

echo "==> Installing dependencies"
npm install

echo "==> Running tests"
export NEO4J_URI="bolt://localhost:${BOLT_PORT}"
export NEO4J_PASSWORD
npm test

echo
echo "==> setup.sh completed successfully"
echo "Start the API with: npm run dev"
echo "Then verify with:   ./verify.sh"
