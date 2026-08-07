import { Hono } from 'hono';
import { read } from '../db.js';
import { plain } from '../serialize.js';
import { riskScore, riskBand, explainRisk } from '../risk.js';
import * as Q from '../queries.js';

const MAX_LIMIT = 100;
const clampLimit = (raw) => {
  const n = Number.parseInt(raw ?? '', 10);
  return Number.isFinite(n) && n > 0 ? Math.min(n, MAX_LIMIT) : MAX_LIMIT;
};

const app = new Hono();

// GET /api/vulnerabilities/domain/:domain
app.get('/domain/:domain', async (c) => {
  const domain = c.req.param('domain').toLowerCase();
  const records = await read(Q.VULNS_FOR_DOMAIN, { domain, limit: clampLimit(c.req.query('limit')) });

  const findings = records.map((r) => {
    const row = Object.fromEntries(r.keys.map((k) => [k, plain(r.get(k))]));
    const score = riskScore(row);
    return { ...row, risk_score: score, risk: riskBand(score), why: explainRisk(row) };
  });

  const summary = findings.reduce(
    (acc, f) => {
      acc.total += 1;
      acc[f.risk] += 1;
      if (f.exploits.length) acc.with_exploits += 1;
      return acc;
    },
    { total: 0, high: 0, medium: 0, low: 0, with_exploits: 0 },
  );

  return c.json({ domain, summary, findings });
});

// GET /api/vulnerabilities/exploitable
app.get('/exploitable', async (c) => {
  const records = await read(Q.EXPLOITABLE, { limit: clampLimit(c.req.query('limit')) });
  const items = records
    .map((r) => {
      const row = Object.fromEntries(r.keys.map((k) => [k, plain(r.get(k))]));
      const score = riskScore({
        ...row,
        exploits: (row.exploit_sources || []).map((s) => ({ source: s, verified: s === 'exploit-db' })),
      });
      return { ...row, risk_score: score, risk: riskBand(score), why: explainRisk(row) };
    })
    .sort((a, b) => b.risk_score - a.risk_score);

  return c.json({ count: items.length, items });
});

export default app;
