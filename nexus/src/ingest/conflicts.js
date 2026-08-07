// Surfaces disagreement between live (non-retracted) claims: either the same
// subject/property asserted with different values by different sources, or
// (for predicates that should be single-valued per subject) the same
// subject pointing at different objects. Retracted claims are excluded -
// only claims that are still "in force" can conflict.

const BUSINESS_KEY_BY_LABEL = { Domain: 'name', Host: 'ip', CVE: 'id' };

// Predicates where a subject is expected to have at most one live object at
// a time; more than one live, disagreeing claim is worth surfacing.
const FUNCTIONAL_RELATIONSHIP_PREDICATES = ['RESOLVES_TO'];

function labelOf(node) {
  return node.labels[0];
}

function describeNode(node) {
  const label = labelOf(node);
  const key = BUSINESS_KEY_BY_LABEL[label];
  return { label, key: key ? node.properties[key] : null };
}

function describeClaim(claimNode) {
  const p = claimNode.properties;
  return {
    claimId: p.id,
    source: p.source,
    confidence: p.confidence,
    assertedAt: p.assertedAt?.toString?.() ?? p.assertedAt,
    value: p.value,
  };
}

export async function findPropertyConflicts(session) {
  const result = await session.run(`
    MATCH (cl:Claim {predicate: 'PROPERTY', retracted: false})-[:SUBJECT]->(s)
    WHERE cl.property IS NOT NULL
    WITH s, cl.property AS property, collect(cl) AS claims, collect(DISTINCT cl.value) AS distinctValues
    WHERE size(distinctValues) > 1
    RETURN s, property, claims
    ORDER BY property
  `);

  return result.records.map((record) => ({
    kind: 'property',
    subject: describeNode(record.get('s')),
    property: record.get('property'),
    claims: record.get('claims').map(describeClaim),
  }));
}

export async function findRelationshipConflicts(session) {
  const conflicts = [];
  for (const predicate of FUNCTIONAL_RELATIONSHIP_PREDICATES) {
    const result = await session.run(
      `
      MATCH (cl:Claim {predicate: $predicate, retracted: false})-[:SUBJECT]->(s), (cl)-[:OBJECT]->(o)
      WITH s, collect(cl) AS claims, collect(DISTINCT o) AS distinctObjects
      WHERE size(distinctObjects) > 1
      RETURN s, distinctObjects, claims
      `,
      { predicate }
    );
    for (const record of result.records) {
      conflicts.push({
        kind: 'relationship',
        predicate,
        subject: describeNode(record.get('s')),
        objects: record.get('distinctObjects').map(describeNode),
        claims: record.get('claims').map(describeClaim),
      });
    }
  }
  return conflicts;
}

export async function findConflicts(session) {
  // A single session only supports one query in flight at a time, so these
  // must run sequentially rather than via Promise.all.
  const propertyConflicts = await findPropertyConflicts(session);
  const relationshipConflicts = await findRelationshipConflicts(session);
  return [...propertyConflicts, ...relationshipConflicts];
}

/**
 * Full claim history for a subject (including retracted claims), oldest
 * first, so callers can see how intel about it evolved over time.
 */
export async function timeline(session, { label, value }) {
  const key = BUSINESS_KEY_BY_LABEL[label];
  if (!key) throw new Error(`unknown node label: ${label}`);

  const result = await session.run(
    `
    MATCH (s:${label} {${key}: $value})
    MATCH (cl:Claim)-[:SUBJECT]->(s)
    OPTIONAL MATCH (cl)-[:OBJECT]->(o)
    RETURN cl.id AS claimId, cl.predicate AS predicate, cl.property AS property,
           cl.value AS value, o AS object,
           cl.source AS source, cl.confidence AS confidence, cl.assertedAt AS assertedAt,
           cl.retracted AS retracted, cl.retractedAt AS retractedAt, cl.retractedReason AS retractedReason
    ORDER BY cl.assertedAt ASC
    `,
    { value }
  );

  return result.records.map((record) => ({
    claimId: record.get('claimId'),
    predicate: record.get('predicate'),
    property: record.get('property'),
    value: record.get('value'),
    object: record.get('object') ? describeNode(record.get('object')) : null,
    source: record.get('source'),
    confidence: record.get('confidence'),
    assertedAt: record.get('assertedAt')?.toString?.() ?? record.get('assertedAt'),
    retracted: record.get('retracted'),
    retractedAt: record.get('retractedAt')?.toString?.() ?? record.get('retractedAt') ?? null,
    retractedReason: record.get('retractedReason') ?? null,
  }));
}
