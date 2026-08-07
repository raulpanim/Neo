// The claim model: every fact in the graph is asserted through a (:Claim)
// node. Direct edges (RESOLVES_TO / HAS_VULNERABILITY / CHAINS_TO) and
// derived node properties (CVE.exploited) are never written directly - they
// are recomputed here from the set of currently non-retracted claims that
// support them. Nothing outside this module should CREATE/MERGE/SET those
// edges or properties.

const BUSINESS_KEY_BY_LABEL = {
  Domain: 'name',
  Host: 'ip',
  CVE: 'id',
};

const RELATIONSHIP_PREDICATES = new Set(['RESOLVES_TO', 'HAS_VULNERABILITY', 'CHAINS_TO']);
const ALLOWED_PROPERTIES = new Set(['exploited']);

function requireKnownLabel(label) {
  if (!Object.prototype.hasOwnProperty.call(BUSINESS_KEY_BY_LABEL, label)) {
    throw new Error(`unknown node label: ${label}`);
  }
  return BUSINESS_KEY_BY_LABEL[label];
}

function requireRelationshipPredicate(predicate) {
  if (!RELATIONSHIP_PREDICATES.has(predicate)) {
    throw new Error(`unknown relationship predicate: ${predicate}`);
  }
  return predicate;
}

function requireKnownProperty(property) {
  if (!ALLOWED_PROPERTIES.has(property)) {
    throw new Error(`unknown property: ${property}`);
  }
  return property;
}

/**
 * Assert a relationship claim: subject -[predicate]-> object.
 * subject/object: { label: 'Domain'|'Host'|'CVE', value: <business key value> }
 * Recomputes the derived edge before returning.
 */
export async function addClaim(session, { subject, predicate, object, source, confidence, assertedAt }) {
  const subjectKey = requireKnownLabel(subject.label);
  const objectKey = requireKnownLabel(object.label);
  requireRelationshipPredicate(predicate);

  const result = await session.run(
    `
    MATCH (s:${subject.label} {${subjectKey}: $subjectValue})
    MATCH (o:${object.label} {${objectKey}: $objectValue})
    CREATE (cl:Claim {
      id: randomUUID(),
      predicate: $predicate,
      source: $source,
      confidence: $confidence,
      assertedAt: datetime($assertedAt),
      retracted: false
    })
    CREATE (cl)-[:SUBJECT]->(s)
    CREATE (cl)-[:OBJECT]->(o)
    RETURN cl.id AS claimId, elementId(s) AS subjectId, elementId(o) AS objectId
    `,
    {
      subjectValue: subject.value,
      objectValue: object.value,
      predicate,
      source,
      confidence,
      assertedAt: assertedAt || new Date().toISOString(),
    }
  );
  if (result.records.length === 0) {
    throw new Error('subject or object node not found');
  }
  const record = result.records[0];
  const subjectId = record.get('subjectId');
  const objectId = record.get('objectId');
  await recompute(session, { subjectId, predicate, objectId });
  return record.get('claimId');
}

/**
 * Assert a property claim: subject.property = value.
 * subject: { label, value }
 * Recomputes the derived property before returning.
 */
export async function addPropertyClaim(session, { subject, property, value, source, confidence, assertedAt }) {
  const subjectKey = requireKnownLabel(subject.label);
  requireKnownProperty(property);

  const result = await session.run(
    `
    MATCH (s:${subject.label} {${subjectKey}: $subjectValue})
    CREATE (cl:Claim {
      id: randomUUID(),
      predicate: 'PROPERTY',
      property: $property,
      value: $value,
      source: $source,
      confidence: $confidence,
      assertedAt: datetime($assertedAt),
      retracted: false
    })
    CREATE (cl)-[:SUBJECT]->(s)
    RETURN cl.id AS claimId, elementId(s) AS subjectId
    `,
    {
      subjectValue: subject.value,
      property,
      value,
      source,
      confidence,
      assertedAt: assertedAt || new Date().toISOString(),
    }
  );
  if (result.records.length === 0) {
    throw new Error('subject node not found');
  }
  const record = result.records[0];
  await recomputeProperty(session, { subjectId: record.get('subjectId'), property });
  return record.get('claimId');
}

/**
 * Retract a claim by id, then recompute whatever it was supporting
 * (a relationship edge, or a node property). Works for either kind because
 * the claim itself records its predicate/property.
 */
export async function retractClaim(session, claimId, { reason } = {}) {
  const result = await session.run(
    `
    MATCH (cl:Claim {id: $claimId})
    OPTIONAL MATCH (cl)-[:SUBJECT]->(s)
    OPTIONAL MATCH (cl)-[:OBJECT]->(o)
    SET cl.retracted = true, cl.retractedAt = datetime(), cl.retractedReason = $reason
    RETURN cl.predicate AS predicate, cl.property AS property, elementId(s) AS subjectId, elementId(o) AS objectId
    `,
    { claimId, reason: reason ?? null }
  );
  if (result.records.length === 0) {
    throw new Error(`no claim found with id ${claimId}`);
  }
  const record = result.records[0];
  const predicate = record.get('predicate');
  const subjectId = record.get('subjectId');

  if (predicate === 'PROPERTY') {
    return recomputeProperty(session, { subjectId, property: record.get('property') });
  }
  return recompute(session, { subjectId, predicate, objectId: record.get('objectId') });
}

/**
 * Rebuild the derived (subject)-[predicate]->(object) edge from the current
 * set of non-retracted claims supporting that exact triple. If none remain
 * (all retracted, or none ever existed), the derived edge is dropped.
 */
export async function recompute(session, { subjectId, predicate, objectId }) {
  requireRelationshipPredicate(predicate);

  const claimsResult = await session.run(
    `
    MATCH (s), (o)
    WHERE elementId(s) = $subjectId AND elementId(o) = $objectId
    MATCH (cl:Claim {predicate: $predicate, retracted: false})-[:SUBJECT]->(s)
    MATCH (cl)-[:OBJECT]->(o)
    RETURN collect(cl) AS claims
    `,
    { subjectId, objectId, predicate }
  );
  const claims = claimsResult.records[0].get('claims');

  if (claims.length === 0) {
    // No supporting claim survives (e.g. the last one was just retracted) -
    // the derived edge must not exist. This is the case a naive
    // "MERGE the edge" recompute forgets to handle.
    await session.run(
      `
      MATCH (s), (o)
      WHERE elementId(s) = $subjectId AND elementId(o) = $objectId
      MATCH (s)-[r:${predicate}]->(o)
      DELETE r
      `,
      { subjectId, objectId }
    );
    return { edgeExists: false, claimCount: 0 };
  }

  const confidence = Math.max(...claims.map((c) => c.properties.confidence));
  const sources = [...new Set(claims.map((c) => c.properties.source))];

  await session.run(
    `
    MATCH (s), (o)
    WHERE elementId(s) = $subjectId AND elementId(o) = $objectId
    MERGE (s)-[r:${predicate}]->(o)
    SET r.claimCount = $claimCount, r.confidence = $confidence, r.sources = $sources, r.updatedAt = datetime()
    `,
    { subjectId, objectId, claimCount: claims.length, confidence, sources }
  );
  return { edgeExists: true, claimCount: claims.length };
}

/**
 * Rebuild subject[property] from the most recent non-retracted claim for
 * that (subject, property) pair. If none remain, the property is removed
 * rather than left stale.
 */
export async function recomputeProperty(session, { subjectId, property }) {
  requireKnownProperty(property);

  const result = await session.run(
    `
    MATCH (s) WHERE elementId(s) = $subjectId
    MATCH (cl:Claim {predicate: 'PROPERTY', property: $property, retracted: false})-[:SUBJECT]->(s)
    RETURN cl ORDER BY cl.assertedAt DESC
    `,
    { subjectId, property }
  );

  if (result.records.length === 0) {
    await session.run(
      `MATCH (s) WHERE elementId(s) = $subjectId SET s[$property] = null`,
      { subjectId, property }
    );
    return { value: null, claimCount: 0 };
  }

  const winner = result.records[0].get('cl');
  await session.run(
    `MATCH (s) WHERE elementId(s) = $subjectId SET s[$property] = $value`,
    { subjectId, property, value: winner.properties.value }
  );
  return { value: winner.properties.value, claimCount: result.records.length };
}
