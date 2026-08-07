import { read, write } from '../db.js';
import { cvesForCpe } from '../sources/nvd.js';
import { fetchKev } from '../sources/kev.js';
import { toCpeName, matchSoftware } from '../sources/cpe.js';

// --- Cypher -------------------------------------------------------------

const LIST_SOFTWARE = `
MATCH (s:Software)
RETURN elementId(s) AS eid, s.cpe AS cpe, s.name AS name, s.vendor AS vendor, s.version AS version
ORDER BY s.name
LIMIT $limit
`;

const UPSERT_CVE = `
UNWIND $rows AS row
MERGE (c:CVE {id: row.id})
SET c.cvss          = coalesce(row.cvss, c.cvss),
    c.severity      = coalesce(row.severity, c.severity),
    c.vector        = coalesce(row.vector, c.vector),
    c.cvss_version  = coalesce(row.cvss_version, c.cvss_version),
    c.attack_vector = coalesce(row.attack_vector, c.attack_vector),
    c.description   = coalesce(row.description, c.description),
    c.cwe           = row.cwe,
    c.references    = row.references,
    c.published     = CASE WHEN row.published IS NULL THEN c.published ELSE date(row.published) END,
    c.last_modified = CASE WHEN row.last_modified IS NULL THEN c.last_modified ELSE date(row.last_modified) END,
    c.synced_at     = datetime(),
    c.kev           = coalesce(c.kev, false)
RETURN count(c) AS upserted
`;

const LINK_VULNERABLE = `
UNWIND $links AS link
MATCH (s:Software) WHERE elementId(s) = link.software_eid
MATCH (c:CVE {id: link.cve})
MERGE (s)-[v:VULNERABLE_TO]->(c)
ON CREATE SET v.first_seen = date()
SET v.method      = link.method,
    v.confidence  = link.confidence,
    v.matched_cpe = link.criteria,
    v.sources     = CASE
                      WHEN v.sources IS NULL THEN ['nvd']
                      WHEN 'nvd' IN v.sources THEN v.sources
                      ELSE v.sources + 'nvd'
                    END,
    v.last_seen   = date()
RETURN count(v) AS linked
`;

/** Drops edges we previously asserted from NVD but that no longer match. */
const PRUNE_STALE = `
MATCH (s:Software)-[v:VULNERABLE_TO]->(c:CVE)
WHERE elementId(s) = $software_eid
  AND v.sources = ['nvd']
  AND NOT c.id IN $keep
DELETE v
RETURN count(*) AS pruned
`;

const APPLY_KEV = `
UNWIND $rows AS row
MATCH (c:CVE {id: row.id})
SET c.kev        = true,
    c.kev_added  = CASE WHEN row.kev_added IS NULL THEN c.kev_added ELSE date(row.kev_added) END,
    c.kev_due    = CASE WHEN row.kev_due IS NULL THEN c.kev_due ELSE date(row.kev_due) END,
    c.kev_action = row.kev_action,
    c.ransomware = row.ransomware
RETURN count(c) AS flagged
`;

const RECORD_RUN = `
CREATE (r:SyncRun {
  source: $source, started_at: datetime($started), finished_at: datetime(),
  status: $status, processed: $processed, upserted: $upserted,
  linked: $linked, pruned: $pruned, note: $note
})
RETURN elementId(r) AS eid
`;

export const LAST_RUNS = `
MATCH (r:SyncRun)
RETURN r.source AS source, toString(r.finished_at) AS finished_at, r.status AS status,
       r.processed AS processed, r.upserted AS upserted, r.linked AS linked,
       r.pruned AS pruned, r.note AS note
ORDER BY r.finished_at DESC
LIMIT 20
`;

// --- job state (in-memory; Redis can take over in week 5) ----------------

const jobs = new Map();
export const getJob = (id) => jobs.get(id) ?? null;
export const listJobs = () => [...jobs.values()].slice(-10);

function newJob(source) {
  const id = `${source}-${Date.now().toString(36)}`;
  const job = {
    id,
    source,
    status: 'running',
    started: new Date().toISOString(),
    processed: 0,
    total: 0,
    upserted: 0,
    linked: 0,
    pruned: 0,
    current: null,
    errors: [],
  };
  jobs.set(id, job);
  return job;
}

// --- NVD sync -------------------------------------------------------------

/**
 * For each Software node: ask NVD what affects its CPE, upsert the CVEs, then
 * re-derive the VULNERABLE_TO edges from our own matcher rather than trusting
 * the query filter. NVD's cpeName filter is broad; the local match is what
 * decides whether an edge is exact, range-derived, or a weak wildcard.
 */
export async function syncNvd({ limit = 50, maxCvesPerSoftware = 200 } = {}) {
  const job = newJob('nvd');

  (async () => {
    try {
      const softwareRows = (await read(LIST_SOFTWARE, { limit })).map((r) =>
        Object.fromEntries(r.keys.map((k) => [k, r.get(k)])),
      );
      job.total = softwareRows.length;

      for (const sw of softwareRows) {
        job.current = `${sw.name} ${sw.version}`;
        try {
          const cpeName = sw.cpe || toCpeName(sw);
          const cves = await cvesForCpe(cpeName, { max: maxCvesPerSoftware });

          const links = [];
          for (const cve of cves) {
            let best = null;
            for (const m of cve.matches) {
              const res = matchSoftware(sw, m);
              if (res.matched && (!best || res.confidence > best.confidence)) {
                best = { ...res, criteria: m.criteria };
              }
            }
            if (best) {
              links.push({
                software_eid: sw.eid,
                cve: cve.id,
                method: best.method,
                confidence: best.confidence,
                criteria: best.criteria,
              });
            }
          }

          if (cves.length) {
            const rows = cves.map(({ matches, ...rest }) => rest);
            const res = await write(UPSERT_CVE, { rows });
            job.upserted += res[0]?.get('upserted')?.toNumber?.() ?? res[0]?.get('upserted') ?? 0;
          }

          if (links.length) {
            const res = await write(LINK_VULNERABLE, { links });
            job.linked += res[0]?.get('linked')?.toNumber?.() ?? res[0]?.get('linked') ?? 0;
          }

          const pruned = await write(PRUNE_STALE, {
            software_eid: sw.eid,
            keep: links.map((l) => l.cve),
          });
          job.pruned += pruned[0]?.get('pruned')?.toNumber?.() ?? 0;
        } catch (err) {
          // one bad package must not sink the whole run
          job.errors.push(`${sw.name}: ${err.message}`);
        }
        job.processed += 1;
      }

      job.status = job.errors.length ? 'completed_with_errors' : 'completed';
    } catch (err) {
      job.status = 'failed';
      job.errors.push(err.message);
    } finally {
      job.current = null;
      job.finished = new Date().toISOString();
      await write(RECORD_RUN, {
        source: 'nvd',
        started: job.started,
        status: job.status,
        processed: job.processed,
        upserted: job.upserted,
        linked: job.linked,
        pruned: job.pruned,
        note: job.errors.slice(0, 3).join(' | ') || null,
      }).catch(() => {});
    }
  })();

  return job;
}

// --- KEV sync --------------------------------------------------------------

/** Flags CVEs already in the graph. Cheap, so it runs synchronously. */
export async function syncKev() {
  const feed = await fetchKev();
  if (!feed.ok) return { ok: false, error: feed.error };

  let flagged = 0;
  for (let i = 0; i < feed.items.length; i += 500) {
    const chunk = feed.items.slice(i, i + 500);
    const res = await write(APPLY_KEV, { rows: chunk });
    flagged += res[0]?.get('flagged')?.toNumber?.() ?? 0;
  }

  await write(RECORD_RUN, {
    source: 'kev',
    started: new Date().toISOString(),
    status: 'completed',
    processed: feed.items.length,
    upserted: 0,
    linked: flagged,
    pruned: 0,
    note: `catalog ${feed.catalogVersion ?? 'unknown'}`,
  }).catch(() => {});

  return { ok: true, catalogVersion: feed.catalogVersion, in_catalog: feed.items.length, flagged };
}
