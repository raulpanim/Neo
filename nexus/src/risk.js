// Single source of truth for prioritisation. Kept apart from routes so the
// weights can be argued about, tuned, and tested without touching HTTP code.

export const WEIGHTS = {
  cvss: 7, // 0..10 -> 0..70
  verifiedExploit: 22,
  unverifiedExploit: 12,
  kev: 12,
  ransomware: 6,
  networkVector: 5,
  // Press coverage is a tiebreaker, never a driver. Capped low on purpose:
  // attention tracks what is interesting, exploitation tracks what is dangerous,
  // and the two diverge often enough that weighting this heavily would misrank.
  attention: 4,
  // Uncertainty should demote a finding, not bury it. A straight multiply by
  // confidence turned a CVSS 9.8 on 45%-confident software into a "low", which
  // is exactly the finding an analyst most wants to go verify. Half the score
  // is unconditional; only the other half is scaled by how sure we are.
  confidenceFloor: 0.5,
};

/** 0.5..1.0 — never zeroes out a critical on weak fingerprinting alone. */
function confidenceFactor(confidence) {
  const c = Math.max(0, Math.min(1, confidence ?? 1));
  return WEIGHTS.confidenceFloor + (1 - WEIGHTS.confidenceFloor) * c;
}

/**
 * 0..100. Deliberately not just CVSS: a 9.8 on software we're 45% sure is even
 * installed should not outrank a 7.5 with a working public exploit on a host we
 * fingerprinted directly.
 *
 * @param {object} f
 * @param {number}  f.cvss
 * @param {boolean} f.kev             listed by CISA as exploited in the wild
 * @param {boolean} f.ransomware      used in known ransomware campaigns
 * @param {string}  f.attack_vector   NETWORK | ADJACENT_NETWORK | LOCAL | PHYSICAL
 * @param {Array}   f.exploits        [{ source, verified }]
 * @param {number}  f.confidence      0..1 — how sure we are the software is there
 */
export function riskScore(f = {}) {
  const exploits = f.exploits ?? [];
  let score = (f.cvss ?? 0) * WEIGHTS.cvss;

  if (exploits.some((e) => e?.verified)) score += WEIGHTS.verifiedExploit;
  else if (exploits.length) score += WEIGHTS.unverifiedExploit;

  if (f.kev) score += WEIGHTS.kev;
  if (f.ransomware) score += WEIGHTS.ransomware;
  if (f.attack_vector === 'NETWORK') score += WEIGHTS.networkVector;
  if (f.attention) score += WEIGHTS.attention * Math.min(1, f.attention);

  const confidence = confidenceFactor(f.confidence);
  return Math.round(Math.min(100, score * confidence));
}

export const riskBand = (s) => (s >= 70 ? 'high' : s >= 40 ? 'medium' : 'low');

/** Short human sentence explaining why something ranked where it did. */
export function explainRisk(f = {}) {
  const bits = [];
  if (f.cvss) bits.push(`CVSS ${f.cvss}`);
  if (f.kev) bits.push('exploited in the wild');
  const verified = (f.exploits ?? []).some((e) => e?.verified);
  if (verified) bits.push('verified public exploit');
  else if ((f.exploits ?? []).length) bits.push('unverified PoC');
  if (f.attack_vector === 'NETWORK') bits.push('reachable over the network');
  if ((f.attention ?? 0) >= 0.6) bits.push('widely covered right now');
  if ((f.confidence ?? 1) < 0.6) bits.push('software presence unconfirmed');
  return bits.join(' · ') || 'no scoring signals';
}

/**
 * 0..1. Distinct outlets matter more than raw article count — one site
 * publishing five follow-ups is one outlet's opinion, five sites is a signal.
 */
export function attentionScore({ outlets = 0, mentions = 0, latest = null }) {
  const breadth = Math.min(1, outlets / 3);
  const volume = Math.min(1, mentions / 6);

  // Recency multiplies rather than adds. As a separate term it handed every
  // fresh item a quarter of the score for free, so one blog posting six
  // follow-ups outscored a genuinely broad story that was a month old.
  let recency = 0.5;
  if (latest) {
    const days = (Date.now() - new Date(latest).getTime()) / 86_400_000;
    recency = days <= 7 ? 1 : days <= 30 ? 0.8 : 0.5;
  }

  return Math.round((breadth * 0.65 + volume * 0.35) * recency * 100) / 100;
}
