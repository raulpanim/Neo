import { Hono } from 'hono';
import { matrix, PREDICATES } from '../sources/reliability.js';
import { detectConflicts, timelineFor } from '../ingest/conflicts.js';
import { assertClaim, retractClaim } from '../ingest/claims.js';

const app = new Hono();

const clampLimit = (raw) => {
  const n = Number.parseInt(raw ?? '', 10);
  return Number.isFinite(n) && n > 0 ? Math.min(n, 100) : 100;
};

// GET /api/intel/sources — the reliability matrix, for the UI legend
app.get('/sources', (c) =>
  c.json({
    sources: matrix(),
    predicates: Object.entries(PREDICATES).map(([name, meta]) => ({ name, ...meta })),
    scale: 'Admiralty: letter = source reliability (A best, F unknown), number = credibility of the claim (1 best, 6 improbable).',
  }),
);

// GET /api/intel/conflicts
app.get('/conflicts', async (c) => {
  const res = await detectConflicts({ limit: clampLimit(c.req.query('limit')) });
  return c.json(res);
});

// GET /api/intel/timeline/:id
app.get('/timeline/:id', async (c) => {
  const events = await timelineFor(c.req.param('id'), { limit: clampLimit(c.req.query('limit')) });
  if (!events.length) {
    return c.json({ events: [], note: 'No recorded observations for this entity yet.' });
  }
  return c.json({ count: events.length, events });
});

// POST /api/intel/claims — an analyst asserting something by hand
app.post('/claims', async (c) => {
  const body = await c.req.json().catch(() => null);
  if (!body?.subject || !body?.object || !body?.predicate) {
    return c.json({ error: 'subject, object and predicate are required.' }, 400);
  }
  try {
    const result = await assertClaim({
      subject: body.subject,
      object: body.object,
      predicate: body.predicate,
      source: body.source || 'analyst',
      value: body.value ?? null,
      note: body.note ?? null,
      observedAt: body.observed_at || new Date().toISOString(),
    });
    return c.json(result, 201);
  } catch (err) {
    return c.json({ error: err.message }, 400);
  }
});

// POST /api/intel/claims/retract
app.post('/claims/retract', async (c) => {
  const body = await c.req.json().catch(() => null);
  if (!body?.subject || !body?.object || !body?.predicate || !body?.source) {
    return c.json({ error: 'subject, object, predicate and source are required.' }, 400);
  }
  try {
    const result = await retractClaim({ ...body, reason: body.reason ?? null });
    return c.json(result);
  } catch (err) {
    return c.json({ error: err.message }, 400);
  }
});

export default app;
