import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import graph from './routes/graph.js';
import vulnerabilities from './routes/vulnerabilities.js';
import sources from './routes/sources.js';
import intel from './routes/intel.js';
import analysis from './routes/analysis.js';
import { healthcheck, shutdown } from './db.js';

const app = new Hono();

// --- CORS (hand-rolled, no extra deps) -----------------------------
const ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:5173';
app.use('*', async (c, next) => {
  c.header('Access-Control-Allow-Origin', ORIGIN);
  c.header('Access-Control-Allow-Headers', 'Content-Type');
  c.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (c.req.method === 'OPTIONS') return c.body(null, 204);
  await next();
});

// --- request log ---------------------------------------------------
app.use('*', async (c, next) => {
  const t0 = Date.now();
  await next();
  console.log(`${c.req.method} ${c.req.path} -> ${c.res.status} ${Date.now() - t0}ms`);
});

// --- routes ---------------------------------------------------------
app.get('/api/health', async (c) => {
  const db = await healthcheck();
  return c.json({ status: db.ok ? 'ok' : 'degraded', neo4j: db }, db.ok ? 200 : 503);
});

app.route('/api/graph', graph);
app.route('/api/vulnerabilities', vulnerabilities);
app.route('/api/sources', sources);
app.route('/api/intel', intel);
app.route('/api/analysis', analysis);

app.notFound((c) => c.json({ error: `No route for ${c.req.path}` }, 404));

// --- never crash ----------------------------------------------------
app.onError((err, c) => {
  console.error('[nexus]', err);
  const isDbDown = /ServiceUnavailable|ECONNREFUSED|SessionExpired/i.test(err.message || '');
  return c.json(
    {
      error: isDbDown
        ? 'Graph database is unreachable. Check that the Neo4j container is running.'
        : 'Query failed. The request was rejected before anything was changed.',
      detail: process.env.NODE_ENV === 'production' ? undefined : err.message,
    },
    isDbDown ? 503 : 500,
  );
});

const port = Number(process.env.PORT) || 3000;
const server = serve({ fetch: app.fetch, port }, (info) => {
  console.log(`NEXUS api :: http://localhost:${info.port}`);
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, async () => {
    server.close();
    await shutdown();
    process.exit(0);
  });
}

process.on('unhandledRejection', (e) => console.error('[nexus] unhandled rejection:', e));

export default app;
