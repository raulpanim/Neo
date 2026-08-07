import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { getVulnerabilityChains, getChainsForHost } from '../src/analysis/chains.js';
import { addClaim } from '../src/ingest/claims.js';
import { closeDriver } from '../src/db.js';
import { withSession, setupFixtures, teardownFixtures, createFixture } from './helpers.js';

const fixture = createFixture(3);

before(() => setupFixtures(fixture));
after(async () => {
  await teardownFixtures(fixture);
  await closeDriver();
});

test('getVulnerabilityChains returns the seeded Log4Shell -> OpenSSH chain', async () => {
  await withSession(async (session) => {
    const chains = await getVulnerabilityChains(session);
    const match = chains.find(
      (c) => c.cves[0] === 'CVE-2021-44228' && c.cves[c.cves.length - 1] === 'CVE-2021-41617'
    );
    assert.ok(match, 'expected the seeded chain to be present');
    assert.deepStrictEqual(match.cves, ['CVE-2021-44228', 'CVE-2021-41617']);
  });
});

test('a 3-hop chain is reported once as a maximal path, not also as its 1- and 2-hop sub-chains', async () => {
  await withSession(async (session) => {
    await addClaim(session, {
      subject: { label: 'CVE', value: fixture.cveA },
      predicate: 'CHAINS_TO',
      object: { label: 'CVE', value: fixture.cveB },
      source: 'test',
      confidence: 0.5,
    });
    await addClaim(session, {
      subject: { label: 'CVE', value: fixture.cveB },
      predicate: 'CHAINS_TO',
      object: { label: 'CVE', value: fixture.cveC },
      source: 'test',
      confidence: 0.5,
    });

    const chains = await getVulnerabilityChains(session);
    const fixtureChains = chains.filter((c) => c.cves.includes(fixture.cveA));
    assert.strictEqual(fixtureChains.length, 1, 'only the full 3-node chain should be reported');
    assert.deepStrictEqual(fixtureChains[0].cves, [fixture.cveA, fixture.cveB, fixture.cveC]);

    // sub-chains must not appear as separate entries either
    assert.strictEqual(
      chains.some((c) => c.cves.length === 2 && c.cves[0] === fixture.cveA && c.cves[1] === fixture.cveB),
      false
    );
  });
});

test('getChainsForHost resolves by elementId and includes CVEs with no outgoing chain as singletons', async () => {
  await withSession(async (session) => {
    await addClaim(session, {
      subject: { label: 'Host', value: fixture.host },
      predicate: 'HAS_VULNERABILITY',
      object: { label: 'CVE', value: fixture.cveA },
      source: 'test',
      confidence: 0.5,
    });
    const hostIdResult = await session.run(`MATCH (h:Host {ip: $ip}) RETURN elementId(h) AS id`, {
      ip: fixture.host,
    });
    const hostElementId = hostIdResult.records[0].get('id');

    const chains = await getChainsForHost(session, hostElementId);
    const entry = chains.find((c) => c.rootCve === fixture.cveA);
    assert.ok(entry);
    assert.strictEqual(entry.chains.length, 1);
  });
});

test('getChainsForHost returns [] for a host with no HAS_VULNERABILITY edges', async () => {
  await withSession(async (session) => {
    const hostIdResult = await session.run(`MATCH (h:Host {ip: $ip}) RETURN elementId(h) AS id`, {
      ip: fixture.host2,
    });
    const hostElementId = hostIdResult.records[0].get('id');
    const chains = await getChainsForHost(session, hostElementId);
    assert.deepStrictEqual(chains, []);
  });
});
