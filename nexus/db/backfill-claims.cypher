// ==========================================================
// NEXUS :: backfill — turns edge.sources arrays into :Claim nodes.
// Run once after upgrading to the claim model. Idempotent.
// ==========================================================

CREATE CONSTRAINT claim_key IF NOT EXISTS
  FOR (c:Claim) REQUIRE c.key IS UNIQUE;
CREATE INDEX claim_predicate IF NOT EXISTS FOR (c:Claim) ON (c.predicate);
CREATE INDEX claim_observed  IF NOT EXISTS FOR (c:Claim) ON (c.observed_at);
CREATE INDEX claim_source    IF NOT EXISTS FOR (c:Claim) ON (c.source);

// One claim per (edge, source) pair. `sources` is a plain array on the edge,
// so each entry becomes its own attributable observation.
MATCH (s)-[r]->(o)
WHERE r.sources IS NOT NULL AND size(r.sources) > 0
UNWIND r.sources AS source
WITH s, o, r, source,
     type(r) + '|' + elementId(s) + '|' + elementId(o) + '|' + source AS key,
     coalesce(r.last_seen, date()) AS seen,
     coalesce(r.first_seen, r.last_seen, date()) AS born
MERGE (s)-[:SUBJECT_OF]->(c:Claim {key: key})-[:OBJECT_IS]->(o)
ON CREATE SET c.observations = 1
SET c.predicate   = type(r),
    c.source      = source,
    c.observed_at = datetime({date: seen}),
    c.first_seen  = datetime({date: born}),
    c.retracted   = false,
    c.note        = 'backfilled from edge properties',
    c.value       = r.method;

// Mark the edges as derived so the recompute path is allowed to rewrite them.
MATCH (s)-[r]->(o)
WHERE r.sources IS NOT NULL AND size(r.sources) > 0
SET r.derived = true;

// Sanity check — claim count should equal the sum of all sources arrays.
MATCH (c:Claim) WITH count(c) AS claims
MATCH ()-[r]->() WHERE r.sources IS NOT NULL
RETURN claims AS claims_created, sum(size(r.sources)) AS expected;
