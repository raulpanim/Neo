import { read, write } from '../db.js';
import { combineConfidence, bestSource, predicateInfo, sourceInfo } from '../sources/reliability.js';

// Relationships in Neo4j can't carry structured history — a property can hold
// primitives or arrays of primitives, nothing nested. So every assertion is
// reified as a (:Claim) node:
//
//   (subject)-[:SUBJECT_OF]->(:Claim {predicate, source, observed_at})-[:OBJECT_IS]->(object)
//
// The direct edge stays for fast traversal, but it is now *derived*: its
// confidence and sources are recomputed from the live claims behind it.

const CLAIM_UPSERT = `
MATCH (s) WHERE elementId(s) = $subject
MATCH (o) WHERE elementId(o) = $object
MERGE (s)-[:SUBJECT_OF]->(c:Claim {key: $key})-[:OBJECT_IS]->(o)
ON CREATE SET c.first_seen = datetime($observed_at), c.observations = 0
SET c.predicate   = $predicate,
    c.source      = $source,
    c.observed_at = datetime($observed_at),
    c.value       = $value,
    c.note        = $note,
    c.retracted   = false,
    c.observations = coalesce(c.observations, 0) + 1
RETURN c.key AS key, c.observations AS observations
`;

const CLAIM_RETRACT = `
MATCH (c:Claim {key: $key})
SET c.retracted = true, c.retracted_at = datetime(), c.retract_reason = $reason
RETURN c.key AS key
`;

/** All live claims behind one subject-predicate-object triple. */
const CLAIMS_FOR_TRIPLE = `
MATCH (s)-[:SUBJECT_OF]->(c:Claim {predicate: $predicate})-[:OBJECT_IS]->(o)
WHERE elementId(s) = $subject AND elementId(o) = $object AND c.retracted = false
RETURN collect(DISTINCT c.source) AS sources,
       toString(max(c.observed_at)) AS latest,
       toString(min(c.first_seen)) AS earliest
`;

/** Rewrites the derived edge. The relationship type can't be parameterised, so
 *  the predicate is validated against the whitelist before interpolation. */
const materialise = (predicate) => `
MATCH (s) WHERE elementId(s) = $subject
MATCH (o) WHERE elementId(o) = $object
MERGE (s)-[r:${predicate}]->(o)
SET r.sources    = $sources,
    r.confidence = $confidence,
    r.best_source = $best_source,
    r.first_seen = date(datetime($earliest)),
    r.last_seen  = date(datetime($latest)),
    r.derived    = true
RETURN elementId(r) AS eid
`;

const DROP_EDGE = (predicate) => `
MATCH (s)-[r:${predicate}]->(o)
WHERE elementId(s) = $subject AND elementId(o) = $object AND r.derived = true
DELETE r
RETURN count(*) AS dropped
`;

const num = (v) => (typeof v?.toNumber === 'function' ? v.toNumber() : v);

function assertPredicate(predicate) {
  if (!Object.prototype.hasOwnProperty.call(predicateInfo(predicate), 'cardinality')) {
    throw new Error(`Unknown predicate "${predicate}".`);
  }
  if (!/^[A-Z_]+$/.test(predicate)) throw new Error(`Illegal predicate "${predicate}".`);
  return predicate;
}

export const claimKey = ({ predicate, subject, object, source }) =>
  `${predicate}|${subject}|${object}|${source}`;

/**
 * Records one source saying one thing, then rebuilds the derived edge from
 * every live claim about that triple. Re-observing the same thing bumps the
 * timestamp and the counter instead of creating a duplicate.
 */
export async function assertClaim({
  subject,
  object,
  predicate,
  source,
  value = null,
  note = null,
  observedAt = new Date().toISOString(),
}) {
  assertPredicate(predicate);
  const key = claimKey({ predicate, subject, object, source });

  await write(CLAIM_UPSERT, {
    key, subject, object, predicate, source, value, note,
    observed_at: observedAt,
  });

  return recompute({ subject, object, predicate });
}

/** Marks one source's claim as withdrawn without deleting the audit trail. */
export async function retractClaim({ subject, object, predicate, source, reason = null }) {
  assertPredicate(predicate);
  await write(CLAIM_RETRACT, { key: claimKey({ predicate, subject, object, source }), reason });
  return recompute({ subject, object, predicate });
}

/** Derives the edge from live claims. No claims left -> the edge goes away. */
export async function recompute({ subject, object, predicate }) {
  assertPredicate(predicate);
  const rows = await read(CLAIMS_FOR_TRIPLE, { subject, object, predicate });
  const sources = rows[0]?.get('sources') ?? [];

  if (!sources.length) {
    await write(DROP_EDGE(predicate), { subject, object });
    return { predicate, sources: [], confidence: 0, dropped: true };
  }

  const confidence = combineConfidence(sources);
  const best = bestSource(sources);

  await write(materialise(predicate), {
    subject, object, sources, confidence,
    best_source: best,
    earliest: rows[0].get('earliest'),
    latest: rows[0].get('latest'),
  });

  return {
    predicate,
    sources,
    confidence,
    best_source: best,
    grade: `${sourceInfo(best).reliability}${sourceInfo(best).credibility}`,
  };
}

export { num };
