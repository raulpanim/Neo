import { getSession } from '../src/db.js';

export async function withSession(fn) {
  const session = getSession();
  try {
    return await fn(session);
  } finally {
    await session.close();
  }
}

// node:test runs separate test files concurrently (one worker process per
// file) by default, so fixtures must be namespaced per file - otherwise two
// files racing on the same host IP / CVE id would corrupt each other's
// state. Each test file calls createFixture() with its own unique tag.
export function createFixture(tag) {
  return {
    domain: `test-fixture-${tag}.invalid`,
    host: `203.0.113.${tag * 10 + 1}`,
    host2: `203.0.113.${tag * 10 + 2}`,
    cveA: `CVE-9999-${tag}001`,
    cveB: `CVE-9999-${tag}002`,
    cveC: `CVE-9999-${tag}003`,
  };
}

export async function setupFixtures(fixture) {
  await withSession(async (session) => {
    await session.run(
      `
      MERGE (:Domain {name: $domain})
      MERGE (:Host {ip: $host})
      MERGE (:Host {ip: $host2})
      MERGE (:CVE {id: $cveA, description: 'fixture A', cvss: 5.0, kev: false})
      MERGE (:CVE {id: $cveB, description: 'fixture B', cvss: 5.0, kev: false})
      MERGE (:CVE {id: $cveC, description: 'fixture C', cvss: 5.0, kev: false})
      `,
      fixture
    );
  });
}

export async function teardownFixtures(fixture) {
  await withSession(async (session) => {
    await session.run(
      `
      MATCH (n) WHERE n.name = $domain OR n.ip IN [$host, $host2] OR n.id IN [$cveA, $cveB, $cveC]
      OPTIONAL MATCH (n)<-[:SUBJECT|OBJECT]-(cl:Claim)
      DETACH DELETE n, cl
      `,
      fixture
    );
  });
}
