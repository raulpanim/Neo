import { Hono } from 'hono';
import { detectChains, persistChains, listChains } from '../analysis/chains.js';

const app = new Hono();

const clampLimit = (raw) => {
  const n = Number.parseInt(raw ?? '', 10);
  return Number.isFinite(n) && n > 0 ? Math.min(n, 100) : 100;
};

// GET /api/analysis/chains?depth=3 — read-only inference
app.get('/chains', async (c) => {
  const raw = Number.parseInt(c.req.query('depth') ?? '3', 10);
  const maxDepth = Number.isFinite(raw) ? Math.min(Math.max(raw, 2), 4) : 3;
  const res = await detectChains({ limit: clampLimit(c.req.query('limit')), maxDepth });
  return c.json({ ...res, max_depth: maxDepth });
});

// GET /api/analysis/chains/recorded — what is already in the graph
app.get('/chains/recorded', async (c) => {
  const chains = await listChains({ limit: clampLimit(c.req.query('limit')) });
  return c.json({ count: chains.length, chains });
});

// POST /api/analysis/chains/persist — writes CHAINS_TO edges as inferences
app.post('/chains/persist', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const raw = Number.parseInt(body.depth ?? 3, 10);
  const maxDepth = Number.isFinite(raw) ? Math.min(Math.max(raw, 2), 4) : 3;
  const res = await persistChains({ limit: clampLimit(body.limit), maxDepth });
  return c.json({
    ...res,
    note: 'Written as inferences from the "guess" source, not as analyst assertions.',
  });
});

export default app;
