// CPE 2.3 handling. Everything here is pure — no I/O — so the matching rules
// stay unit-testable and auditable. Getting this wrong means false positives
// in a vulnerability report, which is worse than missing a CVE.

const WFN_ANY = '*';
const WFN_NA = '-';

/**
 * cpe:2.3:a:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:other
 * Returns null rather than throwing — callers treat unparseable CPEs as unmatched.
 */
export function parseCpe23(str) {
  if (typeof str !== 'string' || !str.startsWith('cpe:2.3:')) return null;
  // split on ':' but keep escaped '\:' intact
  const parts = str.slice(8).split(/(?<!\\):/);
  if (parts.length < 4) return null;
  const [part, vendor, product, version, update, edition, lang, swEdition, targetSw, targetHw, other] =
    parts;
  return {
    raw: str,
    part, // a = application, o = os, h = hardware
    vendor: (vendor || WFN_ANY).toLowerCase(),
    product: (product || WFN_ANY).toLowerCase(),
    version: version || WFN_ANY,
    update: update || WFN_ANY,
    edition,
    lang,
    swEdition,
    targetSw,
    targetHw,
    other,
  };
}

/** Builds the cpeName used to query NVD for a Software node. */
export function toCpeName({ vendor, name, version, part = 'a' }) {
  const esc = (s) => String(s || WFN_ANY).toLowerCase().replace(/\s+/g, '_').replace(/:/g, '\\:');
  return `cpe:2.3:${part}:${esc(vendor)}:${esc(name)}:${esc(version)}:*:*:*:*:*:*:*`;
}

/**
 * Version comparison that survives real-world strings: 1.18.0, 8.2p1, 2.14.1,
 * 1.0.2k, 10.0.0-rc1. Numeric chunks compare numerically, alpha chunks
 * lexically, and a pre-release suffix sorts below the bare version.
 */
export function compareVersions(a, b) {
  if (a === b) return 0;
  const tok = (v) =>
    String(v)
      .toLowerCase()
      .split(/[._\-+]/)
      .flatMap((chunk) => chunk.match(/\d+|[a-z]+/g) ?? []);

  const A = tok(a);
  const B = tok(b);
  const len = Math.max(A.length, B.length);

  for (let i = 0; i < len; i++) {
    const x = A[i];
    const y = B[i];
    if (x === undefined) return isPreRelease(y) ? 1 : -1;
    if (y === undefined) return isPreRelease(x) ? -1 : 1;

    const xNum = /^\d+$/.test(x);
    const yNum = /^\d+$/.test(y);
    if (xNum && yNum) {
      const d = Number(x) - Number(y);
      if (d !== 0) return Math.sign(d);
    } else if (xNum !== yNum) {
      // 1.0 > 1.0rc — a numeric chunk outranks an alpha one at the same position
      return xNum ? 1 : -1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

const isPreRelease = (t) => /^(rc|alpha|beta|pre|dev|snapshot)$/.test(String(t));

/**
 * Does `version` fall inside an NVD cpeMatch range?
 * range = { versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding }
 */
export function inVersionRange(version, range = {}) {
  if (!version || version === WFN_ANY || version === WFN_NA) return false;
  const {
    versionStartIncluding: gte,
    versionStartExcluding: gt,
    versionEndIncluding: lte,
    versionEndExcluding: lt,
  } = range;

  if (gte && compareVersions(version, gte) < 0) return false;
  if (gt && compareVersions(version, gt) <= 0) return false;
  if (lte && compareVersions(version, lte) > 0) return false;
  if (lt && compareVersions(version, lt) >= 0) return false;
  return Boolean(gte || gt || lte || lt);
}

/**
 * Decides whether a Software node is affected by one NVD cpeMatch entry.
 * Returns { matched, method, confidence } — method feeds the graph edge so an
 * analyst can tell an exact CPE hit from an inferred range hit.
 */
export function matchSoftware(software, cpeMatch) {
  const target = parseCpe23(cpeMatch.criteria);
  if (!target) return { matched: false };

  const vendor = String(software.vendor || '').toLowerCase().replace(/\s+/g, '_');
  const product = String(software.name || '').toLowerCase().replace(/\s+/g, '_');

  const vendorOk = target.vendor === WFN_ANY || target.vendor === vendor;
  const productOk = target.product === WFN_ANY || target.product === product;
  if (!vendorOk || !productOk) return { matched: false };

  // exact version pinned in the CPE itself
  if (target.version !== WFN_ANY && target.version !== WFN_NA) {
    const same = compareVersions(software.version, target.version) === 0;
    return same
      ? { matched: true, method: 'cpe-exact', confidence: 0.95 }
      : { matched: false };
  }

  // version range attached to the match
  if (inVersionRange(software.version, cpeMatch)) {
    return { matched: true, method: 'cpe-range', confidence: 0.85 };
  }

  // wildcard version and no range: every version of the product is affected.
  // Real, but weak enough that the UI should show it dashed.
  const wildcard = !cpeMatch.versionStartIncluding && !cpeMatch.versionStartExcluding &&
    !cpeMatch.versionEndIncluding && !cpeMatch.versionEndExcluding;
  if (wildcard) return { matched: true, method: 'cpe-wildcard', confidence: 0.5 };

  return { matched: false };
}

/** Flattens NVD's nested configuration tree into a list of cpeMatch objects. */
export function flattenConfigurations(configurations = []) {
  const out = [];
  const walk = (node) => {
    if (!node) return;
    (node.cpeMatch || []).forEach((m) => m.vulnerable && out.push(m));
    (node.nodes || []).forEach(walk);
  };
  configurations.forEach((cfg) => (cfg.nodes || []).forEach(walk));
  return out;
}
