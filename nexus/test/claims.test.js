import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { addClaim, addPropertyClaim, retractClaim } from '../src/ingest/claims.js';
import { closeDriver } from '../src/db.js';
import { withSession, setupFixtures, teardownFixtures, createFixture } from './helpers.js';

const fixture = createFixture(1);

before(() => setupFixtures(fixture));
after(async () => {
  await teardownFixtures(fixture);
  await closeDriver();
});

async function edgeBetween(session, fromIp, toId) {
  const result = await session.run(
    `MATCH (h:Host {ip: $fromIp})-[r:HAS_VULNERABILITY]->(c:CVE {id: $toId}) RETURN r`,
    { fromIp, toId }
  );
  return result.records[0]?.get('r') ?? null;
}

test('addClaim creates the derived edge with claimCount 1', async () => {
  await withSession(async (session) => {
    const claimId = await addClaim(session, {
      subject: { label: 'Host', value: fixture.host },
      predicate: 'HAS_VULNERABILITY',
      object: { label: 'CVE', value: fixture.cveA },
      source: 'source-1',
      confidence: 0.6,
    });
    assert.ok(claimId);
    const edge = await edgeBetween(session, fixture.host, fixture.cveA);
    assert.ok(edge, 'derived edge should exist after first claim');
    assert.strictEqual(edge.properties.claimCount, 1);
    assert.strictEqual(edge.properties.confidence, 0.6);
  });
});

test('a second corroborating claim raises confidence to the max and claimCount to 2', async () => {
  await withSession(async (session) => {
    await addClaim(session, {
      subject: { label: 'Host', value: fixture.host },
      predicate: 'HAS_VULNERABILITY',
      object: { label: 'CVE', value: fixture.cveA },
      source: 'source-2',
      confidence: 0.9,
    });
    const edge = await edgeBetween(session, fixture.host, fixture.cveA);
    assert.strictEqual(edge.properties.claimCount, 2);
    assert.strictEqual(edge.properties.confidence, 0.9);
    assert.deepStrictEqual(new Set(edge.properties.sources), new Set(['source-1', 'source-2']));
  });
});

test('retracting one of two supporting claims keeps the edge (only claimCount drops)', async () => {
  await withSession(async (session) => {
    const result = await session.run(
      `MATCH (cl:Claim {source: 'source-1', predicate: 'HAS_VULNERABILITY'}) RETURN cl.id AS id`
    );
    const claimId = result.records[0].get('id');
    await retractClaim(session, claimId, { reason: 'superseded' });
    const edge = await edgeBetween(session, fixture.host, fixture.cveA);
    assert.ok(edge, 'edge must survive while one non-retracted claim remains');
    assert.strictEqual(edge.properties.claimCount, 1);
    assert.deepStrictEqual(edge.properties.sources, ['source-2']);
  });
});

test('retracting the last supporting claim drops the derived edge entirely', async () => {
  await withSession(async (session) => {
    const result = await session.run(
      `MATCH (cl:Claim {source: 'source-2', predicate: 'HAS_VULNERABILITY'}) RETURN cl.id AS id`
    );
    const claimId = result.records[0].get('id');
    await retractClaim(session, claimId, { reason: 'false positive' });
    const edge = await edgeBetween(session, fixture.host, fixture.cveA);
    assert.strictEqual(edge, null, 'edge must be gone once its only supporting claim is retracted');
  });
});

test('a claim that starts retracted never materializes an edge', async () => {
  await withSession(async (session) => {
    const claimId = await addClaim(session, {
      subject: { label: 'Host', value: fixture.host2 },
      predicate: 'HAS_VULNERABILITY',
      object: { label: 'CVE', value: fixture.cveA },
      source: 'auto-scanner',
      confidence: 0.3,
    });
    await retractClaim(session, claimId, { reason: 'immediately retracted for the test' });
    const edge = await edgeBetween(session, fixture.host2, fixture.cveA);
    assert.strictEqual(edge, null);
  });
});

test('property claims: most recent non-retracted claim wins', async () => {
  await withSession(async (session) => {
    await addPropertyClaim(session, {
      subject: { label: 'CVE', value: fixture.cveB },
      property: 'exploited',
      value: false,
      source: 'nvd',
      confidence: 0.9,
      assertedAt: '2024-01-01T00:00:00Z',
    });
    let result = await session.run(`MATCH (c:CVE {id: $id}) RETURN c.exploited AS exploited`, {
      id: fixture.cveB,
    });
    assert.strictEqual(result.records[0].get('exploited'), false);

    await addPropertyClaim(session, {
      subject: { label: 'CVE', value: fixture.cveB },
      property: 'exploited',
      value: true,
      source: 'greynoise',
      confidence: 0.5,
      assertedAt: '2024-06-01T00:00:00Z',
    });
    result = await session.run(`MATCH (c:CVE {id: $id}) RETURN c.exploited AS exploited`, {
      id: fixture.cveB,
    });
    assert.strictEqual(result.records[0].get('exploited'), true, 'newer claim should win regardless of confidence');
  });
});

test('retracting every property claim removes the property rather than leaving it stale', async () => {
  await withSession(async (session) => {
    const result = await session.run(
      `MATCH (cl:Claim {predicate: 'PROPERTY', property: 'exploited'})-[:SUBJECT]->(:CVE {id: $id})
       RETURN cl.id AS id`,
      { id: fixture.cveB }
    );
    for (const record of result.records) {
      await retractClaim(session, record.get('id'));
    }
    const check = await session.run(`MATCH (c:CVE {id: $id}) RETURN c.exploited AS exploited`, {
      id: fixture.cveB,
    });
    assert.strictEqual(check.records[0].get('exploited'), null);
  });
});
