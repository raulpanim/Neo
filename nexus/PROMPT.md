# NEXUS — bring-up and repair

You are working in the extracted `nexus/` project: a Neo4j + Hono + React
OSINT/vulnerability graph. The pure logic is unit-tested (98 assertions), but
no Cypher has ever run against a live database. Your job is to stand it up,
find what breaks, and fix it — without changing the design.

## Ground rules
- Dependencies are only: neo4j-driver, hono, @hono/node-server, react,
  cytoscape, axios, tailwind. Do not add libraries.
- Every fact in the graph goes through the claim model
  (`src/ingest/claims.js`): assertions are `(:Claim)` nodes, direct edges are
  derived and recomputed. Never write edges that bypass it.
- Fix root causes. Do not weaken tests to make things pass. All 98 assertions
  must still pass when you finish.
- Explain each fix in one line: what was wrong, why your change is correct.

## Steps
1. Run `./setup.sh`. It starts Neo4j, waits for it to answer, loads
   `db/schema.cypher`, `db/seed.cypher`, `db/backfill-claims.cypher`, and runs
   the tests. If it fails, read the log and fix the cause before continuing.
2. Start the API: `npm run dev` (port 3000).
3. Run `./verify.sh`. Every check must reach 2xx, except `nope.invalid` (404).
4. For each failure, read the route and the query, fix it. Prime suspects,
   never run before:
   - `src/ingest/conflicts.js` — claim-grouping and timeline: `collect` and
     list comprehensions, null handling, cardinality.
   - `src/ingest/claims.js` — `recompute` must drop the edge when the last
     claim is retracted.
   - `src/analysis/chains.js` — the `CVES_BY_HOST` traversal and `elementId`
     lookups.
5. Spot-check the data, not just status codes:
   - `/api/analysis/chains` must return CVE-2021-44228 → CVE-2021-41617.
   - `/api/vulnerabilities/domain/example.com` must rank KEV/exploited first.
   - `/api/intel/conflicts` must return valid JSON with no 500.
6. Start the UI: `npm run dev --prefix frontend` (5173). Confirm the graph
   renders and the chains tab (key `a`) shows the seeded chain.

## Report when done
- What failed in `verify.sh`, with a one-line cause+fix each.
- Confirmation that `npm test` is still fully green.
- Anything that felt like a design problem rather than a bug — flag it, don't
  silently redesign it.
