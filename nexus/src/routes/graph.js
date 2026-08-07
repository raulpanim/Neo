import { Hono } from 'hono';
import { read } from '../db.js';
import { toCytoscape, plain } from '../serialize.js';
import * as Q from '../queries.js';

const MAX_LIMIT = 100; // Cytoscape starts choking well before 500 nodes

const clampLimit = (raw) => {
  const n = Number.parseInt(raw ?? '', 10);
  return Number.isFinite(n) && n > 0 ? Math.min(n, MAX_LIMIT) : MAX_LIMIT;
};

const app = new Hono();

// GET /api/graph/search?q=example&limit=50
app.get('/search', async (c) => {
  const q = (c.req.query('q') || '').trim();
  if (q.length < 2) {
    return c.json({ error: 'Query must be at least 2 characters.', elements: { nodes: [], edges: [] } }, 400);
  }
  // escape lucene specials, then prefix-match
  const safe = q.replace(/([+\-!(){}\[\]^"~*?:\\/]|&&|\|\|)/g, '\\$1');
  const records = await read(Q.SEARCH, { q: `${safe}*`, limit: clampLimit(c.req.query('limit')) });
  return c.json({
    query: q,
    count: records.length,
    elements: toCytoscape(records),
  });
});

// GET /api/graph/node/:id
app.get('/node/:id', async (c) => {
  const records = await read(Q.NODE_BY_ID, { id: c.req.param('id') });
  if (!records.length) return c.json({ error: 'Node not found.' }, 404);
  return c.json({ elements: toCytoscape(records) });
});

// GET /api/graph/expand/:id?depth=2
app.get('/expand/:id', async (c) => {
  const raw = Number.parseInt(c.req.query('depth') ?? '1', 10);
  const depth = Number.isFinite(raw) ? Math.min(Math.max(raw, 1), 3) : 1;
  const records = await read(Q.EXPAND(depth), {
    id: c.req.param('id'),
    limit: clampLimit(c.req.query('limit')),
  });
  const elements = toCytoscape(records);
  return c.json({
    depth,
    truncated: elements.nodes.length >= MAX_LIMIT,
    elements,
  });
});

// GET /api/graph/attack-surface/:domain
app.get('/attack-surface/:domain', async (c) => {
  const domain = c.req.param('domain').toLowerCase();
  const records = await read(Q.ATTACK_SURFACE, { domain, limit: clampLimit(c.req.query('limit')) });
  if (!records.length) return c.json({ error: `Domain "${domain}" is not in the graph yet.` }, 404);

  const elements = toCytoscape(records);
  const root = elements.nodes.find((n) => n.data.type === 'Domain' && n.data.name === domain);
  if (root && root.data.owned !== true) {
    // Legal guard-rail: surface it in the payload so the UI can badge it.
    root.data.warning = 'Ownership not proven — passive data only.';
  }
  return c.json({ domain, elements });
});

// GET /api/graph/chains
app.get('/chains', async (c) => {
  const records = await read(Q.ATTACK_CHAINS, { limit: clampLimit(c.req.query('limit')) });
  return c.json({ elements: toCytoscape(records) });
});

// GET /api/graph/stats
app.get('/stats', async (c) => {
  const records = await read(Q.STATS, {});
  if (!records.length) return c.json({ nodes: [], edges: [], exploitable_cves: 0 });
  const r = records[0];
  return c.json({
    nodes: plain(r.get('nodeCounts')),
    edges: plain(r.get('edgeCounts')),
    exploitable_cves: plain(r.get('exploitable_cves')),
  });
});

export default app;
