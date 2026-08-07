// Source reliability, graded on the Admiralty scale that intelligence analysts
// already use: a letter for how much we trust the source itself, a number for
// how credible this particular kind of claim from it is.
//
//   A/1 = completely reliable, confirmed      E/5 = unreliable, improbable
//
// `weight` is what the maths actually uses; the letter/number pair is what an
// analyst reads. Keep them consistent when tuning.

export const SOURCES = {
  dns: {
    label: 'Live DNS',
    reliability: 'A', credibility: 1, weight: 0.95,
    ttlDays: 1,
    note: 'Queried directly. Authoritative at the moment of lookup, stale within hours.',
  },
  crtsh: {
    label: 'Certificate Transparency',
    reliability: 'A', credibility: 2, weight: 0.9,
    ttlDays: 90,
    note: 'Append-only public log. Proves a certificate existed, not that the host still does.',
  },
  'passive-dns': {
    label: 'Passive DNS',
    reliability: 'C', credibility: 3, weight: 0.55,
    ttlDays: 30,
    note: 'Historical observations from third parties. Often describes infrastructure long gone.',
  },
  whois: {
    label: 'WHOIS / RDAP',
    reliability: 'B', credibility: 2, weight: 0.75,
    ttlDays: 30,
    note: 'Registrant data is frequently privacy-redacted or simply wrong.',
  },
  bgp: {
    label: 'BGP / RIR',
    reliability: 'A', credibility: 1, weight: 0.92,
    ttlDays: 7,
    note: 'Routing table observation. Solid for IP-to-ASN.',
  },
  shodan: {
    label: 'Shodan',
    reliability: 'B', credibility: 2, weight: 0.8,
    ttlDays: 7,
    note: 'Scan data. Accurate when fresh; ports close without the record updating.',
  },
  internetdb: {
    label: 'Shodan InternetDB',
    reliability: 'B', credibility: 3, weight: 0.6,
    ttlDays: 7,
    derivesFrom: 'shodan',
    note: 'Free tier of the same scan data. Ports and CPEs only — no versions, no port attribution.',
  },
  banner: {
    label: 'Service banner',
    reliability: 'B', credibility: 2, weight: 0.78,
    ttlDays: 7,
    note: 'Self-reported by the service. Trivially spoofed, routinely wrong after patching.',
  },
  'http-headers': {
    label: 'HTTP headers',
    reliability: 'C', credibility: 3, weight: 0.55,
    ttlDays: 7,
    note: 'Weaker than a banner. Often stripped or set by a proxy in front of the real service.',
  },
  nvd: {
    label: 'NVD',
    reliability: 'A', credibility: 1, weight: 0.95,
    ttlDays: 7,
    note: 'Authoritative for CVE metadata. CPE applicability data lags real-world packaging.',
  },
  'exploit-db': {
    label: 'Exploit-DB',
    reliability: 'B', credibility: 2, weight: 0.88,
    ttlDays: 365,
    note: 'Curated and usually verified.',
  },
  github: {
    label: 'GitHub PoC',
    reliability: 'C', credibility: 3, weight: 0.5,
    ttlDays: 180,
    note: 'Unreviewed. A repository named for a CVE frequently contains nothing that works.',
  },
  analyst: {
    label: 'Analyst assertion',
    reliability: 'B', credibility: 1, weight: 0.85,
    ttlDays: 365,
    note: 'Human judgement. Never pruned automatically.',
  },
  thehackerwire: {
    label: 'TheHackerWire',
    reliability: 'C', credibility: 3, weight: 0.5,
    ttlDays: 30,
    derivesFrom: 'nvd',
    note: 'Editorial coverage built on NVD data. Useful as an attention signal, not as independent confirmation.',
  },
  guess: {
    label: 'Inference',
    reliability: 'E', credibility: 5, weight: 0.3,
    ttlDays: 14,
    note: 'Derived, not observed. Present so weak links stay visible rather than invisible.',
  },
};

export const UNKNOWN_SOURCE = {
  label: 'Unknown source',
  reliability: 'F', credibility: 6, weight: 0.25,
  ttlDays: 14,
  note: 'Not in the reliability matrix. Treated as barely better than a guess.',
};

export const sourceInfo = (name) => SOURCES[name] ?? { ...UNKNOWN_SOURCE, label: name };

/**
 * Predicate rules. `cardinality: 'one'` means a subject can only truthfully
 * have a single object — two live claims there is a genuine contradiction, not
 * just two facts. RESOLVES_TO is 'many' precisely because round-robin DNS is
 * normal and flagging it would drown the analyst in noise.
 */
export const PREDICATES = {
  RESOLVES_TO: { cardinality: 'many', ttlDays: 7 },
  SUBDOMAIN_OF: { cardinality: 'one', ttlDays: 365 },
  HAS_PORT: { cardinality: 'many', ttlDays: 14 },
  RUNS_SOFTWARE: { cardinality: 'one', ttlDays: 14, note: 'One service per port at a time.' },
  VULNERABLE_TO: { cardinality: 'many', ttlDays: 30 },
  HAS_EXPLOIT: { cardinality: 'many', ttlDays: 365 },
  OWNED_BY: { cardinality: 'one', ttlDays: 90 },
  ANNOUNCED_BY: { cardinality: 'one', ttlDays: 30 },
  HAS_CONTACT: { cardinality: 'many', ttlDays: 90 },
  CHAINS_TO: { cardinality: 'many', ttlDays: 365 },
  MENTIONS: { cardinality: 'many', ttlDays: 180 },
};

export const predicateInfo = (p) => PREDICATES[p] ?? { cardinality: 'many', ttlDays: 30 };

/**
 * Strips sources that only restate an upstream we already have. A site that
 * republishes NVD is not a second opinion, and treating it as one is how a
 * confidence score quietly becomes a lie: two "independent" sources at 0.95
 * would combine to 0.9975 while resting on exactly one observation.
 */
export function independentSources(sourceNames = []) {
  const unique = [...new Set(sourceNames)];
  return unique.filter((s) => {
    const parent = sourceInfo(s).derivesFrom;
    return !parent || !unique.includes(parent);
  });
}

/**
 * Noisy-OR over independent sources: two mediocre sources agreeing is worth
 * more than either alone, but agreement never reaches certainty.
 * Three sources at 0.55 -> 0.909, not 1.65.
 */
export function combineConfidence(sourceNames = []) {
  const unique = independentSources(sourceNames);
  if (!unique.length) return 0;
  const doubt = unique.reduce((acc, s) => acc * (1 - sourceInfo(s).weight), 1);
  return Math.round(Math.min(0.99, 1 - doubt) * 100) / 100;
}

/** Best single source in a set — used to label an edge's provenance tier. */
export function bestSource(sourceNames = []) {
  return [...sourceNames].sort((a, b) => sourceInfo(b).weight - sourceInfo(a).weight)[0] ?? null;
}

/** Days since observation, against that source's own shelf life. */
export function staleness(sourceName, observedAt, predicate) {
  if (!observedAt) return { stale: true, ageDays: null, ttlDays: null };
  const ttl = Math.min(sourceInfo(sourceName).ttlDays, predicateInfo(predicate).ttlDays);
  const ageDays = Math.floor((Date.now() - new Date(observedAt).getTime()) / 86_400_000);
  return { stale: ageDays > ttl, ageDays, ttlDays: ttl };
}

/** Flat matrix for the UI, sorted strongest first. */
export function matrix() {
  return Object.entries(SOURCES)
    .map(([name, meta]) => ({ name, ...meta, grade: `${meta.reliability}${meta.credibility}` }))
    .sort((a, b) => b.weight - a.weight);
}
