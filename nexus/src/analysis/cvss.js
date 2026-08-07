// Pure CVSS reasoning. No I/O — chain logic is the easiest place in this
// codebase to produce confident nonsense, so it stays directly testable.

const METRIC_NAMES = {
  AV: 'attackVector',
  AC: 'attackComplexity',
  PR: 'privilegesRequired',
  UI: 'userInteraction',
  S: 'scope',
  C: 'confidentiality',
  I: 'integrity',
  A: 'availability',
};

/** 'CVSS:3.1/AV:N/AC:L/...' -> { AV: 'N', AC: 'L', ... }. Null if unparseable. */
export function parseVector(vector) {
  if (typeof vector !== 'string' || !vector.includes('/')) return null;
  const out = {};
  for (const part of vector.split('/')) {
    const [k, v] = part.split(':');
    if (k && v && METRIC_NAMES[k]) out[k] = v.toUpperCase();
  }
  return Object.keys(out).length ? out : null;
}

// CWE families that tell us what an attacker actually gets. CVSS alone can't:
// C:H/I:H/A:H describes impact, not mechanism, and "full impact" covers both
// remote code execution and a total-disclosure read primitive.
const CWE_CODE_EXECUTION = new Set([
  77, 78, 88, 94, 95, 502, 917, 1336, // injection / deserialisation / template
  119, 120, 121, 122, 787, 416, 415, // memory corruption
  434, 98, // upload / file inclusion
]);

const CWE_PRIVILEGE_ESCALATION = new Set([
  269, 250, 266, 267, 268, 271, 274, // privilege management
  732, 276, 281, // permissions
  284, 285, 862, 863, // access control
  367, 59, // TOCTOU / link following, the classic local privesc primitives
]);

const CWE_CREDENTIAL_ACCESS = new Set([200, 209, 532, 522, 256, 257, 798, 259]);

const cweNumbers = (cwe = []) =>
  cwe.map((c) => Number(String(c).replace(/\D/g, ''))).filter((n) => Number.isFinite(n));

const PRIVILEGE_RANK = { none: 0, low: 1, high: 2 };
const PR_TO_LEVEL = { N: 'none', L: 'low', H: 'high' };
const AV_TO_REACH = { N: 'network', A: 'adjacent', L: 'local', P: 'physical' };

/**
 * What a CVE needs, and what it hands over.
 *
 * `privilegeAfter` is the deliberately conservative part: code execution
 * through a service lands as that service's account, which is 'low'. It only
 * becomes 'high' when the vulnerability is a privilege-management flaw or CVSS
 * says the scope changed — meaning impact escaped the vulnerable component.
 */
export function capabilities(cve = {}) {
  const v = parseVector(cve.vector) ?? {};
  const cwes = cweNumbers(cve.cwe);

  const reach = AV_TO_REACH[v.AV] ?? (cve.attack_vector ? cve.attack_vector.toLowerCase().split('_')[0] : 'network');
  const requiresPrivilege = PR_TO_LEVEL[v.PR] ?? 'none';
  const requiresUser = v.UI === 'R';
  const scopeChanged = v.S === 'C';

  const isCodeExec = cwes.some((n) => CWE_CODE_EXECUTION.has(n));
  const isPrivEsc = cwes.some((n) => CWE_PRIVILEGE_ESCALATION.has(n));
  const isCredAccess = cwes.some((n) => CWE_CREDENTIAL_ACCESS.has(n));

  const highIntegrity = v.I === 'H';
  const highConfidentiality = v.C === 'H';

  const grants = [];
  if (isCodeExec && highIntegrity) grants.push('code_execution');
  if (isPrivEsc || scopeChanged) grants.push('privilege_escalation');
  if (isCredAccess || highConfidentiality) grants.push('credential_access');
  if (highIntegrity && !grants.includes('code_execution')) grants.push('integrity_compromise');

  let privilegeAfter = 'none';
  if (grants.includes('code_execution')) privilegeAfter = 'low';
  if (isPrivEsc || scopeChanged) privilegeAfter = 'high';

  return {
    id: cve.id,
    reach,
    requiresPrivilege,
    requiresUser,
    scopeChanged,
    grants,
    privilegeAfter,
    // Unauthenticated, no user interaction, reachable over the network: the
    // only shape that can begin a chain without a foothold already in place.
    isEntryPoint: reach === 'network' && requiresPrivilege === 'none' && !requiresUser,
    cvss: cve.cvss ?? null,
    confidence: parseVector(cve.vector) ? 0.9 : 0.5, // no vector means we inferred a lot
  };
}

/**
 * Can `next` follow `prev` on the same host?
 * Returns a reason string when it can, null when it can't — the reason is what
 * gets written onto the edge, so an analyst can argue with the machine.
 */
export function canFollow(prev, next) {
  if (!prev || !next || prev.id === next.id) return null;

  // the follower must need at most what the predecessor obtained
  if (PRIVILEGE_RANK[next.requiresPrivilege] > PRIVILEGE_RANK[prev.privilegeAfter]) return null;

  // a foothold makes local-only bugs reachable, but not adjacent-network or physical ones
  const footholdOnHost = prev.grants.includes('code_execution');
  if (next.reach === 'physical') return null;
  if (next.reach === 'adjacent' && !footholdOnHost) return null;
  if (next.reach === 'local' && !footholdOnHost) return null;

  // user interaction can't be assumed from an automated foothold
  if (next.requiresUser) return null;

  // the step has to actually gain something
  const gainsPrivilege = PRIVILEGE_RANK[next.privilegeAfter] > PRIVILEGE_RANK[prev.privilegeAfter];
  const gainsNewCapability = next.grants.some((g) => !prev.grants.includes(g));
  if (!gainsPrivilege && !gainsNewCapability) return null;

  if (gainsPrivilege) {
    return `${prev.id} lands as ${prev.privilegeAfter === 'none' ? 'an unprivileged context' : prev.privilegeAfter + '-privilege'}; ${next.id} escalates to ${next.privilegeAfter}.`;
  }
  return `${prev.id} provides the foothold; ${next.id} adds ${next.grants.filter((g) => !prev.grants.includes(g)).join(', ')}.`;
}

/**
 * Chain severity, 0..100. A chain is worth more than its steps individually —
 * that is the whole point — but the weakest link caps it, because a chain is
 * only as real as its least certain hop.
 */
export function chainScore(steps = []) {
  if (steps.length < 2) return 0;
  const peak = Math.max(...steps.map((s) => s.cvss ?? 0));
  const reachesRoot = steps.at(-1).privilegeAfter === 'high';
  const startsUnauthenticated = steps[0].isEntryPoint;
  const weakestLink = Math.min(...steps.map((s) => s.confidence));

  let score = peak * 7;
  if (startsUnauthenticated) score += 15;
  if (reachesRoot) score += 15;
  score += (steps.length - 2) * 5; // longer chains are more capable, mildly

  return Math.round(Math.min(100, score) * weakestLink);
}

export { PRIVILEGE_RANK };
