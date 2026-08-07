import { read } from '../db.js';
import {
  PREDICATES, sourceInfo, predicateInfo, combineConfidence, bestSource, staleness,
} from '../sources/reliability.js';

const NAME = `coalesce(n.name, n.address, n.id, n.key, toString(n.number))`;

/** Live claims grouped by subject + predicate + object. One row per edge. */
const CLAIM_GROUPS = `
MATCH (s)-[:SUBJECT_OF]->(c:Claim)-[:OBJECT_IS]->(o)
WHERE c.retracted = false AND c.predicate IN $predicates
WITH s, c.predicate AS predicate, o,
     collect(DISTINCT c.source) AS sources,
     toString(max(c.observed_at)) AS latest
WITH s, predicate,
     collect({
       object_id: elementId(o),
       object: [n IN [o] | ${NAME}][0],
       object_type: labels(o)[0],
       sources: sources,
       latest: latest
     }) AS options
RETURN elementId(s) AS subject_id,
       [n IN [s] | ${NAME}][0] AS subject,
       labels(s)[0] AS subject_type,
       predicate,
       options
LIMIT $limit
`;

/** Claims that were withdrawn while others about the same triple stayed live. */
const RETRACTION_SPLITS = `
MATCH (s)-[:SUBJECT_OF]->(c:Claim)-[:OBJECT_IS]->(o)
WITH s, o, c.predicate AS predicate,
     collect(CASE WHEN c.retracted THEN c.source END) AS retracted,
     collect(CASE WHEN NOT c.retracted THEN c.source END) AS live
WITH s, o, predicate,
     [x IN retracted WHERE x IS NOT NULL] AS retracted,
     [x IN live WHERE x IS NOT NULL] AS live
WHERE size(retracted) > 0 AND size(live) > 0
RETURN elementId(s) AS subject_id, [n IN [s] | ${NAME}][0] AS subject,
       elementId(o) AS object_id,  [n IN [o] | ${NAME}][0] AS object,
       predicate, retracted, live
LIMIT $limit
`;

const plainRow = (r) => Object.fromEntries(r.keys.map((k) => [k, r.get(k)]));

/**
 * Four kinds of disagreement, deliberately distinct because they need
 * different responses from an analyst:
 *
 *   cardinality  — two sources assert mutually exclusive facts. Investigate.
 *   weak_support — nothing but low-grade sources back this. Go confirm it.
 *   stale        — the claim outlived its source's shelf life. Re-observe it.
 *   retraction   — one source withdrew what another still asserts. Adjudicate.
 *
 * Lumping them into one "conflict" count would hide which action to take.
 */
export async function detectConflicts({ limit = 100 } = {}) {
  const functional = Object.entries(PREDICATES)
    .filter(([, v]) => v.cardinality === 'one')
    .map(([k]) => k);

  const conflicts = [];

  // --- 1. mutually exclusive facts ---------------------------------
  if (functional.length) {
    const rows = await read(CLAIM_GROUPS, { predicates: functional, limit });
    for (const r of rows.map(plainRow)) {
      if (r.options.length < 2) continue;
      const ranked = r.options
        .map((o) => ({
          ...o,
          confidence: combineConfidence(o.sources),
          best: bestSource(o.sources),
        }))
        .sort((a, b) => b.confidence - a.confidence);

      const [winner, runnerUp] = ranked;
      conflicts.push({
        kind: 'cardinality',
        severity: winner.confidence - runnerUp.confidence < 0.15 ? 'high' : 'medium',
        subject: r.subject,
        subject_id: r.subject_id,
        subject_type: r.subject_type,
        predicate: r.predicate,
        detail: `${r.predicate} allows one value; ${ranked.length} are asserted.`,
        candidates: ranked,
        suggestion:
          winner.confidence - runnerUp.confidence < 0.15
            ? 'Sources are near-equally trusted. Re-observe before acting on either.'
            : `Prefer "${winner.object}" — ${sourceInfo(winner.best).label} outranks ${sourceInfo(runnerUp.best).label}.`,
      });
    }
  }

  // --- 2. weak support and 3. staleness ----------------------------
  const allPredicates = Object.keys(PREDICATES);
  const rows = await read(CLAIM_GROUPS, { predicates: allPredicates, limit });

  for (const r of rows.map(plainRow)) {
    for (const opt of r.options) {
      const best = bestSource(opt.sources);
      const info = sourceInfo(best);

      if (info.weight < 0.6) {
        conflicts.push({
          kind: 'weak_support',
          severity: info.weight < 0.4 ? 'medium' : 'low',
          subject: r.subject,
          subject_id: r.subject_id,
          predicate: r.predicate,
          object: opt.object,
          object_id: opt.object_id,
          sources: opt.sources,
          detail: `Only ${info.label} (grade ${info.reliability}${info.credibility}) supports this.`,
          suggestion: info.note,
        });
      }

      const age = staleness(best, opt.latest, r.predicate);
      if (age.stale && age.ageDays !== null) {
        conflicts.push({
          kind: 'stale',
          severity: age.ageDays > age.ttlDays * 4 ? 'medium' : 'low',
          subject: r.subject,
          subject_id: r.subject_id,
          predicate: r.predicate,
          object: opt.object,
          object_id: opt.object_id,
          sources: opt.sources,
          detail: `Last observed ${age.ageDays}d ago; ${info.label} data is good for ${age.ttlDays}d.`,
          suggestion: 'Re-run the collector for this entity.',
        });
      }
    }
  }

  // --- 4. one source withdrew, another did not ---------------------
  const splits = await read(RETRACTION_SPLITS, { limit });
  for (const r of splits.map(plainRow)) {
    conflicts.push({
      kind: 'retraction',
      severity: 'high',
      subject: r.subject,
      subject_id: r.subject_id,
      predicate: r.predicate,
      object: r.object,
      object_id: r.object_id,
      detail: `${r.retracted.join(', ')} withdrew this; ${r.live.join(', ')} still asserts it.`,
      suggestion: 'Decide which observation is current and retract the other.',
    });
  }

  const order = { high: 0, medium: 1, low: 2 };
  conflicts.sort((a, b) => order[a.severity] - order[b.severity]);

  return {
    total: conflicts.length,
    by_kind: conflicts.reduce((acc, c) => ({ ...acc, [c.kind]: (acc[c.kind] ?? 0) + 1 }), {}),
    conflicts: conflicts.slice(0, limit),
  };
}

/** Every observation about one entity, newest first. Feeds the timeline view. */
const TIMELINE = `
MATCH (n) WHERE elementId(n) = $id
MATCH (n)-[:SUBJECT_OF|OBJECT_IS]-(c:Claim)
MATCH (subj)-[:SUBJECT_OF]->(c)-[:OBJECT_IS]->(obj)
RETURN c.predicate AS predicate, c.source AS source,
       toString(c.observed_at) AS observed_at,
       toString(c.first_seen) AS first_seen,
       c.observations AS observations,
       c.retracted AS retracted,
       toString(c.retracted_at) AS retracted_at,
       c.note AS note,
       [x IN [subj] | ${NAME}][0] AS subject,
       [x IN [obj]  | ${NAME}][0] AS object,
       elementId(subj) AS subject_id, elementId(obj) AS object_id,
       CASE WHEN elementId(subj) = $id THEN 'outgoing' ELSE 'incoming' END AS direction
ORDER BY c.observed_at DESC
LIMIT $limit
`;

export async function timelineFor(id, { limit = 100 } = {}) {
  const rows = await read(TIMELINE, { id, limit });
  return rows
    .map(plainRow)
    .map((r) => {
      const info = sourceInfo(r.source);
      const age = staleness(r.source, r.observed_at, r.predicate);
      return {
        ...r,
        observations: typeof r.observations?.toNumber === 'function' ? r.observations.toNumber() : r.observations,
        source_label: info.label,
        grade: `${info.reliability}${info.credibility}`,
        weight: info.weight,
        stale: age.stale,
        age_days: age.ageDays,
      };
    });
}

export { predicateInfo };
