import { Hono } from 'hono';
import { read } from '../db.js';
import { plain } from '../serialize.js';
import { syncNvd, syncKev, getJob, listJobs, LAST_RUNS } from '../ingest/nvdSync.js';
import { nvdConfig } from '../sources/nvd.js';
import { syncFeeds, trending } from '../ingest/feedSync.js';
import { syncShodan } from '../ingest/shodanSync.js';
import { shodanConfig } from '../sources/shodan.js';
import { FEEDS } from '../sources/feeds.js';

const app = new Hono();

const clampLimit = (raw) => {
  const n = Number.parseInt(raw ?? '', 10);
  return Number.isFinite(n) && n > 0 ? Math.min(n, 100) : 100;
};

let nvdRunning = null;

// POST /api/sources/nvd/sync  { limit }
app.post('/nvd/sync', async (c) => {
  const running = nvdRunning ? await getJob(nvdRunning) : null;
  if (running?.status === 'running') {
    return c.json({ error: 'An NVD sync is already running.', job: plain(running) }, 409);
  }

  const body = await c.req.json().catch(() => ({}));
  const limit = Math.min(Math.max(Number(body.limit) || 50, 1), 200);

  const job = await syncNvd({ limit });
  nvdRunning = job.id;

  return c.json(
    {
      job,
      note: nvdConfig.hasKey
        ? 'Running with an API key.'
        : 'Running without NVD_API_KEY — one request every 6.5s. Expect this to take a while.',
    },
    202,
  );
});

// POST /api/sources/kev/sync
app.post('/kev/sync', async (c) => {
  const res = await syncKev();
  if (!res.ok) return c.json({ error: res.error }, 502);
  return c.json(res);
});

// POST /api/sources/shodan/sync  { addresses?, limit?, allow_unowned?, reason? }
app.post('/shodan/sync', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const limit = Math.min(Math.max(Number(body.limit) || 25, 1), 100);

  const res = await syncShodan({
    addresses: Array.isArray(body.addresses) ? body.addresses : null,
    limit,
    allowUnowned: Boolean(body.allow_unowned),
    reason: body.reason ?? null,
  });

  return c.json({
    ...res,
    backend: shodanConfig.backend,
    note: shodanConfig.note,
  });
});

// POST /api/sources/feeds/sync — press coverage, not vulnerability data
app.post('/feeds/sync', async (c) => {
  const res = await syncFeeds();
  if (res.errors.length && !res.reports) return c.json({ error: res.errors[0], detail: res }, 502);
  return c.json(res);
});

// GET /api/sources/trending?days=30
app.get('/trending', async (c) => {
  const days = Math.min(Math.max(Number(c.req.query('days')) || 30, 1), 365);
  const items = await trending({ windowDays: days, limit: clampLimit(c.req.query('limit')) });
  return c.json({ window_days: days, count: items.length, items });
});

// GET /api/sources/jobs/:id
app.get('/jobs/:id', async (c) => {
  const job = await getJob(c.req.param('id'));
  if (!job) return c.json({ error: 'No job with that id.' }, 404);
  return c.json(job);
});

// GET /api/sources/status
app.get('/status', async (c) => {
  const runs = await read(LAST_RUNS, {});
  return c.json({
    nvd: { configured: true, api_key: nvdConfig.hasKey, request_gap_ms: nvdConfig.minGapMs },
    kev: { configured: true, api_key: false },
    shodan: {
      configured: true,
      api_key: shodanConfig.hasKey,
      backend: shodanConfig.backend,
      request_gap_ms: shodanConfig.minGapMs,
      note: shodanConfig.note,
    },
    feeds: {
      configured: true,
      api_key: false,
      outlets: Object.entries(FEEDS).map(([name, f]) => ({ name, label: f.label, url: f.url })),
    },
    active_jobs: (await listJobs()).filter((j) => j.status === 'running'),
    history: runs.map((r) => Object.fromEntries(r.keys.map((k) => [k, plain(r.get(k))]))),
  });
});

export default app;
