// One-time bootstrap: materialize derived edges/properties from every claim
// present in the database right now. This is the bulk equivalent of calling
// claims.js `recompute()` / `recomputeProperty()` for every distinct
// (subject, predicate[, object]) group. Ingestion after this point must go
// through claims.js so recompute stays incremental and correct — this script
// is not meant to be re-run against a live, edited graph (it does not clean
// up derived edges/properties whose claims were retracted after seeding; that
// case is claims.js's job — see retractClaim/recompute).

// ---- Relationship predicates: one block per predicate name, since Cypher
// relationship types cannot be parameterized. ----

MATCH (cl:Claim {predicate: 'RESOLVES_TO', retracted: false})-[:SUBJECT]->(s), (cl)-[:OBJECT]->(o)
WITH s, o, collect(cl) AS claims
MERGE (s)-[r:RESOLVES_TO]->(o)
SET r.claimCount = size(claims),
    r.confidence = reduce(m = 0.0, c IN claims | CASE WHEN c.confidence > m THEN c.confidence ELSE m END),
    r.sources = [c IN claims | c.source],
    r.updatedAt = datetime();

MATCH (cl:Claim {predicate: 'HAS_VULNERABILITY', retracted: false})-[:SUBJECT]->(s), (cl)-[:OBJECT]->(o)
WITH s, o, collect(cl) AS claims
MERGE (s)-[r:HAS_VULNERABILITY]->(o)
SET r.claimCount = size(claims),
    r.confidence = reduce(m = 0.0, c IN claims | CASE WHEN c.confidence > m THEN c.confidence ELSE m END),
    r.sources = [c IN claims | c.source],
    r.updatedAt = datetime();

MATCH (cl:Claim {predicate: 'CHAINS_TO', retracted: false})-[:SUBJECT]->(s), (cl)-[:OBJECT]->(o)
WITH s, o, collect(cl) AS claims
MERGE (s)-[r:CHAINS_TO]->(o)
SET r.claimCount = size(claims),
    r.confidence = reduce(m = 0.0, c IN claims | CASE WHEN c.confidence > m THEN c.confidence ELSE m END),
    r.sources = [c IN claims | c.source],
    r.updatedAt = datetime();

// ---- Property predicates: most recent non-retracted claim per (subject,
// property) wins. Dynamic property key via `s[prop] =` (Cypher 5 dynamic
// property SET), scoped to the current row with CALL (s, prop, winner). ----

MATCH (cl:Claim {predicate: 'PROPERTY', retracted: false})-[:SUBJECT]->(s)
WHERE cl.property IS NOT NULL
WITH s, cl.property AS prop, cl
ORDER BY cl.assertedAt DESC
WITH s, prop, collect(cl)[0] AS winner
CALL (s, prop, winner) {
  SET s[prop] = winner.value
}
RETURN count(*) AS propertiesBackfilled;
