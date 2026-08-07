import axios from 'axios';
import { flattenConfigurations } from './cpe.js';

const BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const KEY = process.env.NVD_API_KEY || null;

// NVD allows 5 requests / 30s without a key, 50 / 30s with one.
// Stay under it deliberately: getting throttled costs far more than waiting.
const MIN_GAP_MS = KEY ? 700 : 6500;
const PAGE_SIZE = KEY ? 2000 : 200;

const http = axios.create({
  baseURL: BASE,
  timeout: 30_000,
  headers: KEY ? { apiKey: KEY } : {},
});

let lastCall = 0;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Serialises every call through one gate so parallel callers can't burst. */
let gate = Promise.resolve();
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

/** GET with exponential backoff on 403/429/5xx — NVD returns these under load. */
async function request(params, attempt = 0) {
  try {
    const { data } = await throttled(() => http.get('', { params }));
    return data;
  } catch (err) {
    const status = err.response?.status;
    const retryable = !status || status === 403 || status === 429 || status >= 500;
    if (retryable && attempt < 4) {
      const backoff = 2 ** attempt * 4000 + Math.random() * 1000;
      console.warn(`[nvd] ${status ?? err.code} — retry ${attempt + 1} in ${Math.round(backoff)}ms`);
      await sleep(backoff);
      return request(params, attempt + 1);
    }
    const reason =
      status === 404
        ? 'NVD has no record for that query.'
        : status === 403
          ? 'NVD rejected the request. Set NVD_API_KEY to raise the rate limit.'
          : `NVD request failed (${status ?? err.code}).`;
    throw new Error(reason);
  }
}

/** Reshapes an NVD vulnerability into the properties our CVE nodes carry. */
export function normalize(item) {
  const cve = item.cve ?? item;
  const metrics = cve.metrics ?? {};
  const primary =
    metrics.cvssMetricV31?.[0] ??
    metrics.cvssMetricV30?.[0] ??
    metrics.cvssMetricV2?.[0] ??
    null;
  const data = primary?.cvssData ?? {};

  const english = (cve.descriptions || []).find((d) => d.lang === 'en');

  return {
    id: cve.id,
    cvss: typeof data.baseScore === 'number' ? data.baseScore : null,
    severity: (data.baseSeverity || primary?.baseSeverity || 'UNKNOWN').toUpperCase(),
    vector: data.vectorString ?? null,
    cvss_version: data.version ?? null,
    attack_vector: data.attackVector ?? null,
    published: (cve.published || '').slice(0, 10) || null,
    last_modified: (cve.lastModified || '').slice(0, 10) || null,
    status: cve.vulnStatus ?? null,
    description: (english?.value ?? '').slice(0, 600),
    cwe: (cve.weaknesses || [])
      .flatMap((w) => w.description || [])
      .map((d) => d.value)
      .filter((v) => v?.startsWith('CWE-'))
      .slice(0, 3),
    references: (cve.references || []).slice(0, 5).map((r) => r.url),
    matches: flattenConfigurations(cve.configurations),
  };
}

/** Every CVE affecting one CPE name. Paginates until NVD stops handing pages. */
export async function cvesForCpe(cpeName, { max = 200 } = {}) {
  const out = [];
  let startIndex = 0;

  for (;;) {
    const page = await request({
      cpeName,
      resultsPerPage: Math.min(PAGE_SIZE, max - out.length),
      startIndex,
    });
    const items = page.vulnerabilities ?? [];
    out.push(...items.map(normalize));

    startIndex += items.length;
    const done = items.length === 0 || startIndex >= (page.totalResults ?? 0) || out.length >= max;
    if (done) break;
  }
  return out;
}

/** Delta sync window. NVD caps lastMod ranges at 120 days. */
export async function cvesModifiedSince(sinceIso, { max = 2000 } = {}) {
  const start = new Date(sinceIso);
  const end = new Date();
  const maxSpanMs = 119 * 24 * 60 * 60 * 1000;
  if (end - start > maxSpanMs) throw new Error('Delta window exceeds the 120-day NVD limit.');

  const out = [];
  let startIndex = 0;
  for (;;) {
    const page = await request({
      lastModStartDate: start.toISOString(),
      lastModEndDate: end.toISOString(),
      resultsPerPage: PAGE_SIZE,
      startIndex,
    });
    const items = page.vulnerabilities ?? [];
    out.push(...items.map(normalize));
    startIndex += items.length;
    if (!items.length || startIndex >= (page.totalResults ?? 0) || out.length >= max) break;
  }
  return out;
}

export const nvdConfig = { hasKey: Boolean(KEY), minGapMs: MIN_GAP_MS, pageSize: PAGE_SIZE };
