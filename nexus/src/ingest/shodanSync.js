import { read, write } from '../db.js';
import { assertClaim, retractClaim } from './claims.js';
import { lookupHost } from '../sources/shodan.js';
import {
  softwareFromCpe, softwareFromBanner, portKey, ownershipGate,
} from '../sources/shodanParser.js';

// Everything here goes through assertClaim rather than writing edges directly.
// That is the point of the week 5-6 work: a scan result is one source's opinion
// at one moment, and it should sit alongside the others rather than overwrite
// them.

const HOSTS_TO_SCAN = `
MATCH (ip:IP)
OPTIONAL MATCH (d:Domain)-[:RESOLVES_TO]->(ip)
WITH ip, collect(d) AS domains
RETURN elementId(ip) AS eid,
       ip.address AS address,
       any(d IN domains WHERE d.owned = true) AS owned,
       [d IN domains | d.name] AS domains
ORDER BY ip.address
LIMIT $limit
`;

const ONE_HOST = `
MATCH (ip:IP {address: $address})
OPTIONAL MATCH (d:Domain)-[:RESOLVES_TO]->(ip)
WITH ip, collect(d) AS domains
RETURN elementId(ip) AS eid, ip.address AS address,
       any(d IN domains WHERE d.owned = true) AS owned,
       [d IN domains | d.name] AS domains
`;

const UPSERT_PORT = `
MERGE (p:Port {key: $key})
ON CREATE SET p.first_seen = date()
SET p.number = $number, p.protocol = $protocol, p.service = coalesce($service, p.service)
RETURN elementId(p) AS eid
`;

const UPSERT_SOFTWARE = `
MERGE (s:Software {cpe: $cpe})
ON CREATE SET s.first_seen = date()
SET s.name = $name, s.vendor = $vendor, s.version = $version
RETURN elementId(s) AS eid
`;

const SET_HOST_FACTS = `
MATCH (ip:IP) WHERE elementId(ip) = $eid
SET ip.country = coalesce($country, ip.country),
    ip.org     = coalesce($org, ip.org),
    ip.last_scan = datetime()
RETURN elementId(ip) AS eid
`;

/** Ports we previously heard about from Shodan but that are gone this run. */
const PREVIOUS_PORTS = `
MATCH (ip:IP)-[:SUBJECT_OF]->(c:Claim {predicate: 'HAS_PORT'})-[:OBJECT_IS]->(p:Port)
WHERE elementId(ip) = $eid AND c.source IN ['shodan','internetdb'] AND c.retracted = false
RETURN p.key AS key, elementId(p) AS eid, c.source AS source
`;

const RECORD_RUN = `
CREATE (r:SyncRun {
  source: 'shodan', started_at: datetime($started), finished_at: datetime(),
  status: $status, processed: $processed, upserted: $upserted,
  linked: $linked, pruned: $pruned, note: $note
})
RETURN elementId(r) AS eid
`;

const first = (rows, key) => rows[0]?.get(key) ?? null;
const plainRow = (r) => Object.fromEntries(r.keys.map((k) => [k, r.get(k)]));

/**
 * Scans one host and records what came back as claims.
 * Returns a per-host report rather than throwing, so one unreachable address
 * cannot abort a whole run.
 */
async function scanHost(host, { allowUnowned, reason, observedAt }) {
  const gate = ownershipGate(host, { allowUnowned, reason });
  if (!gate.allowed) return { address: host.address, skipped: true, why: gate.why };

  const res = await lookupHost(host.address);
  if (!res.ok) return { address: host.address, error: res.error, notFound: res.notFound ?? false };

  const scan = res.host;
  const source = scan.source; // 'shodan' or 'internetdb'
  const report = {
    address: host.address,
    source,
    basis: gate.basis,
    ports: 0,
    software: 0,
    retracted: 0,
    degraded: res.degraded ?? null,
  };

  await write(SET_HOST_FACTS, { eid: host.eid, country: scan.country, org: scan.org });

  const seenPorts = new Set();

  for (const svc of scan.services) {
    const key = portKey(host.address, svc.port, svc.transport);
    seenPorts.add(key);

    const portEid = first(
      await write(UPSERT_PORT, {
        key, number: svc.port, protocol: svc.transport, service: svc.service,
      }),
      'eid',
    );

    await assertClaim({
      subject: host.eid,
      object: portEid,
      predicate: 'HAS_PORT',
      source,
      value: svc.banner_hash ? `banner:${svc.banner_hash}` : null,
      observedAt: svc.observed_at || observedAt,
    });
    report.ports += 1;

    // Software is attributed to the port only when the scanner actually tied
    // them together. InternetDB does not, so its CPEs stay unattributed rather
    // than being guessed onto an arbitrary port.
    const candidates = [
      ...svc.cpes.map(softwareFromCpe),
      softwareFromBanner(svc),
    ].filter(Boolean);

    for (const sw of candidates) {
      if (!sw.cpe) continue; // no CPE means no stable identity to merge on
      const swEid = first(await write(UPSERT_SOFTWARE, sw), 'eid');
      await assertClaim({
        subject: portEid,
        object: swEid,
        predicate: 'RUNS_SOFTWARE',
        source: svc.cpes.length ? source : 'banner',
        value: sw.version,
        observedAt: svc.observed_at || observedAt,
      });
      report.software += 1;
    }
  }

  // Ports that vanished get their claim withdrawn, not deleted. If another
  // source still asserts the port, that surfaces as a retraction conflict for
  // a human to adjudicate.
  const previous = (await read(PREVIOUS_PORTS, { eid: host.eid })).map(plainRow);
  for (const prev of previous) {
    if (seenPorts.has(prev.key)) continue;
    await retractClaim({
      subject: host.eid,
      object: prev.eid,
      predicate: 'HAS_PORT',
      source: prev.source,
      reason: 'Not present in the latest scan.',
    });
    report.retracted += 1;
  }

  if (scan.unattributed_cpes?.length) {
    report.unattributed_cpes = scan.unattributed_cpes.length;
    report.note = 'CPEs reported without port attribution; not linked to any service.';
  }

  return report;
}

/** Scans every IP in the graph, or a named subset. */
export async function syncShodan({
  addresses = null,
  limit = 25,
  allowUnowned = false,
  reason = null,
} = {}) {
  const started = new Date().toISOString();
  const observedAt = started;

  let hosts;
  if (addresses?.length) {
    hosts = [];
    for (const address of addresses.slice(0, limit)) {
      const rows = await read(ONE_HOST, { address });
      if (rows.length) hosts.push(plainRow(rows[0]));
      else hosts.push({ address, skipped: true, missing: true });
    }
  } else {
    hosts = (await read(HOSTS_TO_SCAN, { limit })).map(plainRow);
  }

  const reports = [];
  for (const host of hosts) {
    if (host.missing) {
      reports.push({ address: host.address, skipped: true, why: 'Not in the graph.' });
      continue;
    }
    try {
      reports.push(await scanHost(host, { allowUnowned, reason, observedAt }));
    } catch (err) {
      reports.push({ address: host.address, error: err.message });
    }
  }

  const totals = reports.reduce(
    (acc, r) => ({
      ports: acc.ports + (r.ports ?? 0),
      software: acc.software + (r.software ?? 0),
      retracted: acc.retracted + (r.retracted ?? 0),
      skipped: acc.skipped + (r.skipped ? 1 : 0),
      failed: acc.failed + (r.error ? 1 : 0),
    }),
    { ports: 0, software: 0, retracted: 0, skipped: 0, failed: 0 },
  );

  await write(RECORD_RUN, {
    started,
    status: totals.failed ? 'completed_with_errors' : 'completed',
    processed: reports.length,
    upserted: totals.ports,
    linked: totals.software,
    pruned: totals.retracted,
    note: totals.skipped ? `${totals.skipped} host(s) skipped for unproven ownership` : null,
  }).catch(() => {});

  return { totals, hosts: reports };
}
