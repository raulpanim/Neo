import axios from 'axios';

/**
 * Thin wrapper over the local Hono API. Every method resolves (never
 * throws) with { ok, data } or { ok: false, error, status } - the bot loop
 * shouldn't need a try/catch around every command handler to stay alive.
 */
export function createNexusClient(baseURL = process.env.NEXUS_API_URL || 'http://localhost:3000') {
  const http = axios.create({ baseURL, timeout: 15_000 });

  async function get(path, params) {
    try {
      const { data } = await http.get(path, { params });
      return { ok: true, data };
    } catch (err) {
      const status = err.response?.status;
      const error = err.response?.data?.error || (status ? `Request failed (${status}).` : 'nexus API unreachable.');
      return { ok: false, error, status };
    }
  }

  return {
    health: () => get('/api/health'),
    vulnsForDomain: (domain) => get(`/api/vulnerabilities/domain/${encodeURIComponent(domain)}`),
    exploitable: () => get('/api/vulnerabilities/exploitable'),
    chains: () => get('/api/analysis/chains'),
    conflicts: () => get('/api/intel/conflicts'),
    search: (q) => get('/api/graph/search', { q }),
  };
}
