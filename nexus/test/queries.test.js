import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as queries from '../src/queries.js';
import { closeDriver } from '../src/db.js';
import { withSession, setupFixtures, teardownFixtures, createFixture } from './helpers.js';

const fixture = createFixture(4);

before(() => setupFixtures(fixture));
after(async () => {
  await teardownFixtures(fixture);
  await closeDriver();
});

test('getDomain returns null for a domain that does not exist', async () => {
  await withSession(async (session) => {
    const domain = await queries.getDomain(session, 'definitely-not-seeded.invalid');
    assert.strictEqual(domain, null);
  });
});

test('getDomain returns the seeded example.com resolving to its host', async () => {
  await withSession(async (session) => {
    const domain = await queries.getDomain(session, 'example.com');
    assert.ok(domain);
    assert.deepStrictEqual(domain.hosts, ['93.184.216.34']);
  });
});

test('listDomains includes a domain with zero resolved hosts as an empty array, not [null]', async () => {
  await withSession(async (session) => {
    const domains = await queries.listDomains(session);
    const match = domains.find((d) => d.name === fixture.domain);
    assert.ok(match);
    assert.deepStrictEqual(match.hosts, []);
  });
});

test('getHost returns null for an unknown ip', async () => {
  await withSession(async (session) => {
    const host = await queries.getHost(session, '198.51.100.254');
    assert.strictEqual(host, null);
  });
});

test('getHost lists vulnerabilities as [] rather than [null] when there are none', async () => {
  await withSession(async (session) => {
    const host = await queries.getHost(session, fixture.host);
    assert.ok(host);
    assert.deepStrictEqual(host.vulnerabilities, []);
  });
});

test('listHosts reports the correct vulnerabilityCount for the seeded host', async () => {
  await withSession(async (session) => {
    const hosts = await queries.listHosts(session);
    const match = hosts.find((h) => h.ip === '93.184.216.34');
    assert.ok(match);
    assert.strictEqual(match.vulnerabilityCount, 4);
  });
});

test('listCves is ordered by cvss descending', async () => {
  await withSession(async (session) => {
    const cves = await queries.listCves(session);
    for (let i = 1; i < cves.length; i++) {
      assert.ok(cves[i - 1].cvss >= cves[i].cvss);
    }
  });
});

test('getCve reports chainsTo/chainsFrom for the seeded chain', async () => {
  await withSession(async (session) => {
    const from = await queries.getCve(session, 'CVE-2021-44228');
    assert.deepStrictEqual(from.chainsTo, ['CVE-2021-41617']);
    assert.deepStrictEqual(from.chainsFrom, []);

    const to = await queries.getCve(session, 'CVE-2021-41617');
    assert.deepStrictEqual(to.chainsFrom, ['CVE-2021-44228']);
    assert.deepStrictEqual(to.chainsTo, []);
  });
});

test('getCve returns null for an unknown id', async () => {
  await withSession(async (session) => {
    const cve = await queries.getCve(session, 'CVE-0000-0000');
    assert.strictEqual(cve, null);
  });
});

test('rankedVulnerabilitiesForDomain puts KEV/exploited CVEs ahead of a higher-CVSS non-exploited one', async () => {
  await withSession(async (session) => {
    const ranked = await queries.rankedVulnerabilitiesForDomain(session, 'example.com');
    const ids = ranked.map((v) => v.id);
    const log4shellIdx = ids.indexOf('CVE-2021-44228'); // kev, cvss 10
    const opensshIdx = ids.indexOf('CVE-2021-41617'); // not exploited, cvss 7
    assert.ok(log4shellIdx !== -1 && opensshIdx !== -1);
    assert.ok(log4shellIdx < opensshIdx, 'KEV CVE must rank above a non-exploited CVE even with lower CVSS gap');
    for (const v of ranked) {
      assert.ok(v.kev === true || v.exploited === true || v.exploited === false);
    }
    // every exploited/kev entry must precede every non-exploited entry
    const firstNonExploitedIdx = ranked.findIndex((v) => !v.kev && !v.exploited);
    if (firstNonExploitedIdx !== -1) {
      for (let i = 0; i < firstNonExploitedIdx; i++) {
        assert.ok(ranked[i].kev || ranked[i].exploited);
      }
    }
  });
});

test('rankedVulnerabilitiesForDomain returns [] for a domain with no vulnerable hosts', async () => {
  await withSession(async (session) => {
    const ranked = await queries.rankedVulnerabilitiesForDomain(session, fixture.domain);
    assert.deepStrictEqual(ranked, []);
  });
});

test('getGraph includes the seeded chain edge with type CHAINS_TO', async () => {
  await withSession(async (session) => {
    const graph = await queries.getGraph(session);
    assert.ok(graph.nodes.length > 0);
    const chainEdge = graph.edges.find((e) => e.type === 'CHAINS_TO');
    assert.ok(chainEdge);
    const sourceNode = graph.nodes.find((n) => n.id === chainEdge.source);
    const targetNode = graph.nodes.find((n) => n.id === chainEdge.target);
    assert.strictEqual(sourceNode.properties.id, 'CVE-2021-44228');
    assert.strictEqual(targetNode.properties.id, 'CVE-2021-41617');
  });
});

test('getGraph never includes Claim nodes (only derived entities/edges are exposed)', async () => {
  await withSession(async (session) => {
    const graph = await queries.getGraph(session);
    assert.ok(graph.nodes.every((n) => n.label !== 'Claim'));
  });
});
