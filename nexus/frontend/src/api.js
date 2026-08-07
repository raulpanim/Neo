import axios from 'axios';

const client = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  timeout: 15_000,
});

/** Turns any failure into a short line the status bar can print verbatim. */
function explain(err) {
  if (err.code === 'ECONNABORTED') return 'Query timed out after 15s.';
  const status = err.response?.status;
  const fromServer = err.response?.data?.error;
  if (fromServer) return fromServer;
  if (status === 404) return 'Nothing in the graph matches that.';
  if (!err.response) return 'API unreachable. Is the Hono server running on :3000?';
  return `Request failed (${status}).`;
}

async function get(path, params) {
  try {
    const { data } = await client.get(path, { params });
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: explain(err) };
  }
}

async function post(path, body) {
  try {
    const { data } = await client.post(path, body ?? {});
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: explain(err) };
  }
}

export const api = {
  health: () => get('/health'),
  stats: () => get('/graph/stats'),
  search: (q) => get('/graph/search', { q }),
  expand: (id, depth = 1) => get(`/graph/expand/${encodeURIComponent(id)}`, { depth }),
  attackSurface: (domain) => get(`/graph/attack-surface/${encodeURIComponent(domain)}`),
  chains: () => get('/graph/chains'),
  vulnsForDomain: (domain) => get(`/vulnerabilities/domain/${encodeURIComponent(domain)}`),
  exploitable: () => get('/vulnerabilities/exploitable'),

  // week 7: inference
  detectChains: (depth = 3) => get('/analysis/chains', { depth }),
  persistChains: (depth = 3) => post('/analysis/chains/persist', { depth }),

  // week 5-6: provenance
  reliability: () => get('/intel/sources'),
  conflicts: () => get('/intel/conflicts'),
  timeline: (id) => get(`/intel/timeline/${encodeURIComponent(id)}`),

  // week 3-4: collectors
  sourceStatus: () => get('/sources/status'),
  syncNvd: (limit = 25) => post('/sources/nvd/sync', { limit }),
  syncKev: () => post('/sources/kev/sync'),
  syncShodan: (limit = 10) => post('/sources/shodan/sync', { limit }),
  syncFeeds: () => post('/sources/feeds/sync'),
};
