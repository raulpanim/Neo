import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { getSession, closeDriver } from './db.js';
import { toJSONSafe } from './serialize.js';
import * as queries from './queries.js';
import { getVulnerabilityChains, getChainsForHost } from './analysis/chains.js';
import { findConflicts, timeline } from './ingest/conflicts.js';

const app = new Hono();

// Frontend dev server (vite, port 5173) fetches this API from a different
// origin - allow it rather than proxying, since only GET is exposed here.
app.use('/api/*', cors());

function withSession(handler) {
  return async (c) => {
    const session = getSession();
    try {
      return await handler(c, session);
    } finally {
      await session.close();
    }
  };
}

app.get('/health', (c) => c.json({ status: 'ok' }));

app.get(
  '/api/domains',
  withSession(async (c, session) => c.json(toJSONSafe(await queries.listDomains(session))))
);

app.get(
  '/api/domains/:name',
  withSession(async (c, session) => {
    const domain = await queries.getDomain(session, c.req.param('name'));
    if (!domain) return c.json({ error: 'domain not found' }, 404);
    return c.json(toJSONSafe(domain));
  })
);

app.get(
  '/api/hosts',
  withSession(async (c, session) => c.json(toJSONSafe(await queries.listHosts(session))))
);

app.get(
  '/api/hosts/:ip',
  withSession(async (c, session) => {
    const host = await queries.getHost(session, c.req.param('ip'));
    if (!host) return c.json({ error: 'host not found' }, 404);
    return c.json(toJSONSafe(host));
  })
);

app.get(
  '/api/cves',
  withSession(async (c, session) => c.json(toJSONSafe(await queries.listCves(session))))
);

app.get(
  '/api/cves/:id',
  withSession(async (c, session) => {
    const cve = await queries.getCve(session, c.req.param('id'));
    if (!cve) return c.json({ error: 'cve not found' }, 404);
    return c.json(toJSONSafe(cve));
  })
);

app.get(
  '/api/vulnerabilities/domain/:domain',
  withSession(async (c, session) => {
    const domainName = c.req.param('domain');
    const domain = await queries.getDomain(session, domainName);
    if (!domain) return c.json({ error: 'domain not found' }, 404);
    const vulns = await queries.rankedVulnerabilitiesForDomain(session, domainName);
    return c.json(toJSONSafe(vulns));
  })
);

app.get(
  '/api/analysis/chains',
  withSession(async (c, session) => c.json(toJSONSafe(await getVulnerabilityChains(session))))
);

app.get(
  '/api/analysis/chains/host/:ip',
  withSession(async (c, session) => {
    const elementId = await queries.getHostElementId(session, c.req.param('ip'));
    if (!elementId) return c.json({ error: 'host not found' }, 404);
    return c.json(toJSONSafe(await getChainsForHost(session, elementId)));
  })
);

app.get(
  '/api/intel/conflicts',
  withSession(async (c, session) => c.json(toJSONSafe(await findConflicts(session))))
);

const TIMELINE_LABELS = { domain: 'Domain', host: 'Host', cve: 'CVE' };

app.get(
  '/api/intel/timeline/:subjectType/:subjectKey',
  withSession(async (c, session) => {
    const label = TIMELINE_LABELS[c.req.param('subjectType').toLowerCase()];
    if (!label) return c.json({ error: `unknown subject type: ${c.req.param('subjectType')}` }, 400);
    const events = await timeline(session, { label, value: c.req.param('subjectKey') });
    return c.json(toJSONSafe(events));
  })
);

app.get(
  '/api/graph',
  withSession(async (c, session) => c.json(toJSONSafe(await queries.getGraph(session))))
);

app.notFound((c) => c.json({ error: 'not found' }, 404));

app.onError((err, c) => {
  console.error(err);
  return c.json({ error: err.message }, 500);
});

const port = process.env.PORT ? Number(process.env.PORT) : 3000;
serve({ fetch: app.fetch, port }, (info) => {
  console.log(`nexus API listening on http://localhost:${info.port}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, async () => {
    await closeDriver();
    process.exit(0);
  });
}

export default app;
