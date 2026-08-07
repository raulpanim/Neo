import axios from 'axios';
import { normalizeHostApi, normalizeInternetDb } from './shodanParser.js';

const KEY = process.env.SHODAN_API_KEY || null;

// Shodan's paid API is rate-limited to roughly one request per second.
// InternetDB is free and keyless but returns far less: ports and CPEs, no
// versions, no port-to-software mapping. We use whichever is available and
// record which one answered, because the two deserve different trust.
const MIN_GAP_MS = 1100;

const hostApi = axios.create({ baseURL: 'https://api.shodan.io', timeout: 20_000 });
const internetDb = axios.create({ baseURL: 'https://internetdb.shodan.io', timeout: 15_000 });

let lastCall = 0;
let gate = Promise.resolve();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function throttled(fn) {
  const next = gate.then(async () => {
    const wait = MIN_GAP_MS - (Date.now() - lastCall);
    if (wait > 0) await sleep(wait);
    lastCall = Date.now();
    return fn();
  });
  gate = next.catch(() => {});
  return next;
}

function explain(err, api) {
  const status = err.response?.status;
  if (status === 401) return 'Shodan rejected the API key.';
  if (status === 403) return 'Shodan denied the request — the plan may not cover this endpoint.';
  if (status === 404) return 'No scan data for that address.';
  if (status === 429) return 'Shodan rate limit hit.';
  return `${api} request failed (${status ?? err.code}).`;
}

/** One host. Uses the keyed API when configured, InternetDB otherwise. */
export async function lookupHost(ip) {
  if (KEY) {
    try {
      const { data } = await throttled(() =>
        hostApi.get(`/shodan/host/${encodeURIComponent(ip)}`, { params: { key: KEY, minify: false } }),
      );
      return { ok: true, host: normalizeHostApi(data) };
    } catch (err) {
      // 404 means genuinely unscanned; anything else is worth falling back for
      if (err.response?.status === 404) return { ok: false, error: explain(err, 'Shodan'), notFound: true };
      const fallback = await lookupInternetDb(ip);
      if (fallback.ok) return { ...fallback, degraded: explain(err, 'Shodan') };
      return { ok: false, error: explain(err, 'Shodan') };
    }
  }
  return lookupInternetDb(ip);
}

export async function lookupInternetDb(ip) {
  try {
    const { data } = await throttled(() => internetDb.get(`/${encodeURIComponent(ip)}`));
    return { ok: true, host: normalizeInternetDb(data) };
  } catch (err) {
    return {
      ok: false,
      error: explain(err, 'InternetDB'),
      notFound: err.response?.status === 404,
    };
  }
}

export const shodanConfig = {
  hasKey: Boolean(KEY),
  backend: KEY ? 'shodan-host-api' : 'internetdb',
  minGapMs: MIN_GAP_MS,
  note: KEY
    ? 'Full host API: per-port products, versions and CPEs.'
    : 'Keyless InternetDB: open ports and CPEs only, with no port attribution and no versions.',
};
