import { read, write } from '../db.js';
import { FEEDS, fetchFeed } from '../sources/feeds.js';
import { attentionScore } from '../risk.js';

// Coverage is stored as its own entity, never folded into the CVE node:
//
//   (:Report {url, outlet, published})-[:MENTIONS]->(:CVE)
//
// Two outlets writing about the same CVE is two rows here, and the CVE's
// own confidence is untouched — press coverage is not evidence that a
// vulnerability exists, only evidence that people are paying attention.

const UPSERT_REPORTS = `
UNWIND $rows AS row
MERGE (r:Report {url: row.url})
ON CREATE SET r.first_seen = datetime()
SET r.title     = row.title,
    r.outlet    = row.outlet,
    r.summary   = row.summary,
    r.published = CASE WHEN row.published IS NULL THEN r.published ELSE datetime(row.published) END,
    r.last_seen = datetime()
WITH r, row
UNWIND row.cves AS cveId
MATCH (c:CVE {id: cveId})
MERGE (r)-[m:MENTIONS]->(c)
ON CREATE SET m.first_seen = date()
SET m.sources = [row.outlet], m.last_seen = date(), m.derived = false
RETURN count(DISTINCT r) AS reports, count(m) AS mentions
`;

/** CVEs ranked by how much coverage they are getting and how recent it is. */
const TRENDING = `
MATCH (r:Report)-[:MENTIONS]->(c:CVE)
WHERE r.published IS NULL OR r.published > datetime() - duration({days: $windowDays})
WITH c,
     count(DISTINCT r) AS mentions,
     count(DISTINCT r.outlet) AS outlets,
     toString(max(r.published)) AS latest,
     collect(DISTINCT r.outlet)[0..5] AS outlet_names
OPTIONAL MATCH (sw:Software)-[:VULNERABLE_TO]->(c)
OPTIONAL MATCH (c)-[:HAS_EXPLOIT]->(ex:Exploit)
RETURN c.id AS cve, c.cvss AS cvss, c.severity AS severity, c.kev AS kev,
       mentions, outlets, latest, outlet_names,
       count(DISTINCT ex) AS exploits,
       collect(DISTINCT sw.name) AS affects_our_stack
ORDER BY mentions DESC, cvss DESC
LIMIT $limit
`;

const RECORD_RUN = `
CREATE (r:SyncRun {
  source: $source, started_at: datetime($started), finished_at: datetime(),
  status: $status, processed: $processed, upserted: $upserted,
  linked: $linked, pruned: 0, note: $note
})
RETURN elementId(r) AS eid
`;

const num = (v) => (typeof v?.toNumber === 'function' ? v.toNumber() : v);

/**
 * Reads every registered feed and records coverage for CVEs already in the
 * graph. Deliberately does not create CVE nodes: an article about a
 * vulnerability in software nobody here runs is noise, and letting the press
 * seed the graph would fill it with irrelevant entities.
 */
export async function syncFeeds({ outlets = Object.keys(FEEDS) } = {}) {
  const started = new Date().toISOString();
  const result = { outlets: [], reports: 0, mentions: 0, skipped: 0, errors: [] };

  for (const name of outlets) {
    const feed = await fetchFeed(name);
    if (!feed.ok) {
      result.errors.push(feed.error);
      continue;
    }

    const rows = feed.items
      .filter((i) => i.link)
      .map((i) => ({
        url: i.link,
        title: i.title,
        outlet: name,
        summary: i.summary,
        published: i.published,
        cves: i.cves,
      }));

    if (!rows.length) {
      result.outlets.push({ outlet: name, items: 0, matched: 0 });
      continue;
    }

    const res = await write(UPSERT_REPORTS, { rows });
    const reports = num(res[0]?.get('reports')) ?? 0;
    const mentions = num(res[0]?.get('mentions')) ?? 0;

    result.reports += reports;
    result.mentions += mentions;
    result.skipped += rows.length - reports;
    result.outlets.push({ outlet: name, items: rows.length, matched: reports, mentions });
  }

  await write(RECORD_RUN, {
    source: 'feeds',
    started,
    status: result.errors.length ? 'completed_with_errors' : 'completed',
    processed: result.outlets.reduce((a, o) => a + o.items, 0),
    upserted: result.reports,
    linked: result.mentions,
    note: result.errors.slice(0, 2).join(' | ') || null,
  }).catch(() => {});

  return result;
}

export async function trending({ windowDays = 30, limit = 50 } = {}) {
  const rows = await read(TRENDING, { windowDays, limit });
  return rows.map((r) => {
    const o = Object.fromEntries(r.keys.map((k) => [k, num(r.get(k))]));
    return {
      ...o,
      affects_our_stack: (o.affects_our_stack ?? []).filter(Boolean),
      attention: attentionScore(o),
    };
  });
}
