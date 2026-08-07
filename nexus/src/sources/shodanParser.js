// Pure shaping of Shodan responses. Two different APIs return the same facts in
// different shapes, and the ingest layer should not have to care which one
// answered. No I/O here so the mapping stays testable offline.

import { parseCpe23 } from './cpe.js';

/** Shodan's full host object: /shodan/host/{ip} */
export function normalizeHostApi(raw = {}) {
  const services = (raw.data ?? []).map((d) => ({
    port: d.port,
    transport: (d.transport || 'tcp').toLowerCase(),
    service: d._shodan?.module ?? d.product ?? null,
    product: d.product ?? null,
    version: d.version ?? null,
    cpes: [].concat(d.cpe23 ?? d.cpe ?? []),
    observed_at: d.timestamp ?? null,
    // Banners can carry credentials and personal data. We keep a hash for
    // change detection and drop the body — storing raw banners in a graph
    // people share is an easy way to leak something you never meant to keep.
    banner_hash: d.hash != null ? String(d.hash) : null,
  }));

  return {
    ip: raw.ip_str ?? raw.ip ?? null,
    source: 'shodan',
    hostnames: raw.hostnames ?? [],
    asn: raw.asn ?? null,
    org: raw.org ?? raw.isp ?? null,
    country: raw.location?.country_code ?? raw.country_code ?? null,
    last_update: raw.last_update ?? null,
    services,
    vulns: Array.isArray(raw.vulns) ? raw.vulns : Object.keys(raw.vulns ?? {}),
  };
}

/** InternetDB: https://internetdb.shodan.io/{ip} — free, keyless, much thinner. */
export function normalizeInternetDb(raw = {}) {
  const cpes = raw.cpes ?? [];
  const services = (raw.ports ?? []).map((port) => ({
    port,
    transport: 'tcp',
    service: null,
    product: null,
    version: null,
    // InternetDB gives no port-to-CPE mapping, so software can't be attributed
    // to a specific port. That ambiguity is carried forward, not invented away.
    cpes: [],
    observed_at: null,
    banner_hash: null,
  }));

  return {
    ip: raw.ip ?? null,
    source: 'internetdb',
    hostnames: raw.hostnames ?? [],
    asn: null,
    org: null,
    country: null,
    last_update: null,
    services,
    unattributed_cpes: cpes,
    vulns: raw.vulns ?? [],
    tags: raw.tags ?? [],
  };
}

/** Turns a CPE string into the properties a Software node needs. */
export function softwareFromCpe(cpe) {
  const parsed = parseCpe23(cpe);
  if (!parsed) return null;
  const clean = (s) => (s === '*' || s === '-' ? null : String(s).replace(/\\/g, '').replace(/_/g, ' '));
  const name = clean(parsed.product);
  if (!name) return null;
  return {
    cpe,
    name,
    vendor: clean(parsed.vendor) ?? 'unknown',
    version: clean(parsed.version) ?? 'unknown',
  };
}

/** Falls back to the banner when there is no CPE. Weaker, and marked as such. */
export function softwareFromBanner(service) {
  if (!service?.product) return null;
  return {
    cpe: null,
    name: service.product,
    vendor: 'unknown',
    version: service.version ?? 'unknown',
  };
}

export const portKey = (ip, port, transport = 'tcp') => `${ip}:${port}/${transport}`;

/**
 * Legal guard-rail. Shodan data is passive — their scanners did the touching,
 * not us — but the graph is still a map of someone's infrastructure, and the
 * project rule is that entities carry proof of ownership. Unowned hosts are
 * skipped unless the caller explicitly opts in and says why.
 */
export function ownershipGate(host, { allowUnowned = false, reason = null } = {}) {
  if (host?.owned) return { allowed: true, basis: 'ownership proven' };
  if (allowUnowned && reason) return { allowed: true, basis: `override: ${reason}` };
  if (allowUnowned) {
    return { allowed: false, why: 'Override requires a stated reason.' };
  }
  return {
    allowed: false,
    why: `${host?.address ?? 'This host'} has no proven owner in the graph. Add proof of ownership, or pass an explicit override with a reason.`,
  };
}
