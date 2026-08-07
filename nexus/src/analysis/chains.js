import { read } from '../db.js';
import { assertClaim } from './../ingest/claims.js';
import { capabilities, canFollow, chainScore } from './cvss.js';

// A chain is only meaningful between vulnerabilities an attacker can actually
// reach in sequence. Here that means co-located on the same IP: a network RCE
// on :443 followed by a local privilege escalation on the same host is a real
// path; the same two CVEs on unrelated hosts are just two findings.

const CVES_BY_HOST = `
MATCH (ip:IP)-[:HAS_PORT]->(port:Port)-[:RUNS_SOFTWARE]->(sw:Software)-[:VULNERABLE_TO]->(cve:CVE)
OPTIONAL MATCH (d:Domain)-[:RESOLVES_TO]->(ip)
WITH ip, cve, sw, port, collect(DISTINCT d.name) AS domains
RETURN ip.address AS host,
       elementId(ip) AS host_id,
       domains,
       collect(DISTINCT {
         eid: elementId(cve),
         id: cve.id,
         cvss: cve.cvss,
         vector: cve.vector,
         attack_vector: cve.attack_vector,
         cwe: cve.cwe,
         kev: cve.kev,
         software: sw.name,
         version: sw.version,
         port: port.number
       }) AS cves
LIMIT $limit
`;

const EXISTING_CHAINS = `
MATCH (a:CVE)-[r:CHAINS_TO]->(b:CVE)
RETURN a.id AS from, b.id AS to, r.sources AS sources, r.rationale AS rationale
LIMIT $limit
`;

const num = (v) => (typeof v?.toNumber === 'function' ? v.toNumber() : v);
const plainRow = (r) => Object.fromEntries(r.keys.map((k) => [k, r.get(k)]));

/**
 * Depth-first walk over the compatibility graph for one host.
 * Capped at `maxDepth` hops and `maxChains` results — the search is
 * exponential in principle and an analyst cannot read a thousand paths anyway.
 */
function buildChains(profiles, { maxDepth = 3, maxChains = 40 } = {}) {
  const chains = [];
  const entries = profiles.filter((p) => p.isEntryPoint);

  const walk = (path, used) => {
    if (chains.length >= maxChains) return;
    if (path.length >= 2) {
      chains.push([...path]);
      if (chains.length >= maxChains) return;
    }
    if (path.length >= maxDepth) return;

    const last = path.at(-1);
    for (const candidate of profiles) {
      if (used.has(candidate.id)) continue;
      const reason = canFollow(last, candidate);
      if (!reason) continue;
      used.add(candidate.id);
      // Clone rather than mutate `candidate` — it's the same shared profile
      // object for every branch of this search, so writing `_reason` onto it
      // directly leaked whichever branch ran last into every other chain
      // that happened to reuse this CVE, producing rationale text for a
      // transition that wasn't the one in that chain.
      walk([...path, { ...candidate, _reason: reason }], used);
      used.delete(candidate.id);
    }
  };

  for (const entry of entries) {
    walk([entry], new Set([entry.id]));
    if (chains.length >= maxChains) break;
  }

  // Drop chains that are a prefix of a longer one — the longer path already
  // tells the analyst everything the prefix would.
  const asKey = (c) => c.map((s) => s.id).join('>');
  const keys = chains.map(asKey);
  return chains.filter((c, i) => !keys.some((k, j) => j !== i && k.startsWith(keys[i] + '>')));
}

/** Finds chains without writing anything. Safe to call from a GET. */
export async function detectChains({ limit = 100, maxDepth = 3 } = {}) {
  const rows = await read(CVES_BY_HOST, { limit });
  const results = [];

  for (const row of rows.map(plainRow)) {
    const cves = (row.cves ?? []).map((c) => ({ ...c, cvss: num(c.cvss), port: num(c.port) }));
    if (cves.length < 2) continue;

    const byId = new Map();
    const profiles = cves.map((c) => {
      const p = { ...capabilities(c), meta: c };
      byId.set(p.id, p);
      return p;
    });

    for (const chain of buildChains(profiles, { maxDepth })) {
      results.push({
        host: row.host,
        host_id: row.host_id,
        domains: (row.domains ?? []).filter(Boolean),
        length: chain.length,
        score: chainScore(chain),
        starts_unauthenticated: chain[0].isEntryPoint,
        reaches_privileged: chain.at(-1).privilegeAfter === 'high',
        steps: chain.map((s, i) => ({
          position: i + 1,
          cve: s.id,
          cvss: s.cvss,
          software: s.meta.software,
          version: s.meta.version,
          port: s.meta.port,
          kev: s.meta.kev ?? false,
          grants: s.grants,
          privilege_after: s.privilegeAfter,
          rationale: i === 0 ? 'Reachable unauthenticated over the network.' : s._reason,
        })),
      });
    }
  }

  results.sort((a, b) => b.score - a.score);
  return {
    count: results.length,
    chains: results.slice(0, limit),
    note: results.length
      ? 'Chains are inferred from CVSS vectors and CWE families, not verified. Treat them as leads.'
      : 'No chain found. Needs at least two CVEs on one host where the first grants what the second requires.',
  };
}

/**
 * Persists inferred chains as CHAINS_TO claims from the `guess` source, so they
 * sit visibly below anything an analyst asserted by hand and get pruned by the
 * normal staleness rules rather than lingering as fact.
 */
export async function persistChains({ limit = 100, maxDepth = 3 } = {}) {
  const { chains } = await detectChains({ limit, maxDepth });
  const written = [];

  for (const chain of chains) {
    for (let i = 0; i < chain.steps.length - 1; i++) {
      const from = chain.steps[i];
      const to = chain.steps[i + 1];
      const fromEid = await eidFor(from.cve);
      const toEid = await eidFor(to.cve);
      if (!fromEid || !toEid) continue;

      await assertClaim({
        subject: fromEid,
        object: toEid,
        predicate: 'CHAINS_TO',
        source: 'guess',
        value: `score:${chain.score}`,
        note: to.rationale,
      });
      written.push(`${from.cve} -> ${to.cve}`);
    }
  }

  return { written: [...new Set(written)], chains: chains.length };
}

const EID_FOR = `MATCH (c:CVE {id: $id}) RETURN elementId(c) AS eid`;
async function eidFor(id) {
  const rows = await read(EID_FOR, { id });
  return rows[0]?.get('eid') ?? null;
}

/** Chains already recorded, whoever asserted them. */
export async function listChains({ limit = 100 } = {}) {
  const rows = await read(EXISTING_CHAINS, { limit });
  return rows.map(plainRow).map((r) => ({
    ...r,
    asserted_by: (r.sources ?? []).includes('analyst') ? 'analyst' : 'inference',
  }));
}
