# NEXUS

Vulnerability-centric OSINT graph. Domains, hosts, services and CVEs as one
queryable network, with every fact attributed to the source that claimed it.

```
example.com ──RESOLVES_TO──> 1.2.3.4 ──HAS_PORT──> :8009
                                                     └─RUNS_SOFTWARE─> Log4j 2.14.1
                                                                        └─VULNERABLE_TO─> CVE-2021-44228
                                                                                           └─HAS_EXPLOIT─> EDB-50592
```

## Requirements

- Docker and Docker Compose
- Node.js 20 or newer
- No API keys needed to start. Optional: `NVD_API_KEY`, `SHODAN_API_KEY`,
  `TELEGRAM_BOT_TOKEN`.

## Setup

```bash
cp .env.example .env          # optional — defaults work without it
docker compose up -d          # Neo4j on 7474 (browser) and 7687 (bolt)
npm install
npm run db:init               # constraints, indexes, sample data
npm run db:backfill           # converts edge properties into :Claim nodes
npm run dev                   # API on :3000

cd frontend && npm install && npm run dev   # UI on :5173
```

Wait for the Neo4j healthcheck before `db:init`:

```bash
docker compose ps             # neo4j should read "healthy"
```

Then open http://localhost:5173. The graph loads `example.com` automatically.

## Verify it works

```bash
npm test                                        # 132 assertions, no services needed
curl localhost:3000/api/health
curl localhost:3000/api/graph/attack-surface/example.com | head -c 400
curl localhost:3000/api/vulnerabilities/domain/example.com
curl localhost:3000/api/analysis/chains                 # should find Log4Shell -> local privesc
curl localhost:3000/api/intel/conflicts
```

## Layout

```
src/
  index.js              Hono app, CORS, error handling
  db.js                 Neo4j driver and session management
  serialize.js          Neo4j records -> Cytoscape elements
  queries.js            all Cypher for reads, LIMIT-capped
  risk.js               risk scoring and attention scoring
  routes/               graph, vulnerabilities, sources, intel, analysis
  sources/              NVD, CISA KEV, Shodan, RSS feeds, CPE matching,
                        reliability matrix
  ingest/               claim model, sync jobs, conflict detection
  analysis/             CVSS capability inference, attack chains
  telegram/             chat interface onto the same API - see below
frontend/src/
  App.jsx               state, commands, keyboard
  components/           canvas, rail, inspector, drawer panels
  cytoscape/style.js    node and edge visual language
db/
  schema.cypher         constraints and indexes
  seed.cypher           sample dataset
  backfill-claims.cypher
test/                   pure-logic assertions, no network or database
```

## The claim model

Relationships in Neo4j cannot hold structured history, so an assertion is a node:

```
(subject)-[:SUBJECT_OF]->(:Claim {predicate, source, observed_at})-[:OBJECT_IS]->(object)
```

The direct edge remains for traversal but is derived: its `confidence` and
`sources` are recomputed from the live claims behind it. Withdrawing a claim
never deletes history, so an audit trail survives.

Sources are graded on the Admiralty scale (`GET /api/intel/sources`). Confidence
combines by noisy-OR over *independent* sources — a site that republishes NVD is
collapsed into NVD rather than counted as a second opinion.

## Collectors

| Endpoint | Needs a key | What it does |
| --- | --- | --- |
| `POST /api/sources/nvd/sync` | optional | CVE metadata and CPE applicability |
| `POST /api/sources/kev/sync` | no | flags CVEs exploited in the wild |
| `POST /api/sources/shodan/sync` | optional | ports and services; falls back to InternetDB |
| `POST /api/sources/feeds/sync` | no | press coverage as an attention signal |

Without `NVD_API_KEY` the NVD sync makes one request every 6.5 seconds. Without
`SHODAN_API_KEY` host scanning uses InternetDB, which returns ports and CPEs but
no versions and no port attribution.

## Telegram bot

A read-only chat interface onto the same API — no new dependency, the
Telegram Bot API is plain REST and `axios` already covers it.

```bash
# message @BotFather on Telegram, /newbot, copy the token it gives you
echo "TELEGRAM_BOT_TOKEN=123456:your-token-here" >> .env
npm run bot            # long-polls Telegram; needs `npm run dev` running too
```

| Command | Does |
| --- | --- |
| `/vulns <domain>` | ranked findings for a domain, same ordering as the UI |
| `/chains` | inferred exploit chains |
| `/conflicts` | live intel disagreements |
| `/exploitable` | everything with a known exploit, graph-wide |
| `/search <query>` | full-text graph search |
| `/health` | API + Neo4j status |

It long-polls (`getUpdates`) rather than registering a webhook, so it needs
no public HTTPS endpoint — run it anywhere that can reach
`api.telegram.org` and `NEXUS_API_URL` (defaults to `localhost:3000`).
`src/telegram/format.js` is pure (command parsing + Markdown formatting,
capped to Telegram's 4096-char limit) and unit-tested without a token;
`client.js`/`nexusClient.js`/`bot.js` are the two HTTP clients and the
polling loop that wire it to Telegram and to the API.

## Known limits

- **No authentication.** Every endpoint is open, including the ones that spend
  your Shodan and NVD quota. Do not expose this beyond localhost yet.
- **Job state is in memory** and lost on restart. Redis is in `docker-compose.yml`
  under the `full` profile, unused so far.
- **Attack chains approximate reachability by shared IP.** Containers behind one
  address are isolated, and privilege escalation inside a container is not root
  on the host. Read chains as leads, not confirmed paths.
- **Cytoscape degrades past a few hundred nodes.** Every query caps at 100.

## Legal

Query only public data or infrastructure you are authorised to assess. Entities
carry an `owned` flag and `ownership_proof`; the Shodan collector skips hosts
without proven ownership unless given an explicit override and a stated reason.
Domains without proof render with a dashed outline in the graph.
