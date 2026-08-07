// Pure command parsing + Telegram message formatting. No network, no state -
// takes the same JSON shapes the HTTP routes already return and turns them
// into Markdown text a chat client can render. Kept separate from bot.js so
// it can be unit-tested without a bot token or a live API.

const TELEGRAM_MAX = 4096;
const SAFE_MAX = 3800; // headroom for the "+N more" footer

const RISK_EMOJI = { high: '🔴', medium: '🟠', low: '🟢' };
const emoji = (risk) => RISK_EMOJI[risk] ?? '⚪';

/** Truncates to Telegram's message cap rather than letting sendMessage 400. */
export function capMessage(text) {
  if (text.length <= TELEGRAM_MAX) return text;
  return `${text.slice(0, SAFE_MAX)}\n\n_(truncated — narrow your query)_`;
}

/** "/vulns example.com" -> { command: 'vulns', args: 'example.com' }. Not a
 *  command (no leading slash, not a string) -> null. */
export function parseCommand(text) {
  if (typeof text !== 'string') return null;
  const trimmed = text.trim();
  if (!trimmed.startsWith('/')) return null;
  const [rawCommand, ...rest] = trimmed.split(/\s+/);
  // Telegram appends "@BotName" to commands in group chats.
  const command = rawCommand.slice(1).split('@')[0].toLowerCase();
  if (!command) return null;
  return { command, args: rest.join(' ').trim() };
}

export function formatHelp() {
  return [
    '*NEXUS* — vulnerability graph, from chat.',
    '',
    '/vulns `<domain>` — ranked findings for a domain',
    '/chains — inferred exploit chains',
    '/conflicts — live intel disagreements',
    '/exploitable — everything with a known exploit',
    '/search `<query>` — full-text graph search',
    '/health — API + Neo4j status',
  ].join('\n');
}

export function formatHealth(data) {
  if (data?.status === 'ok') return '✅ API ok — Neo4j reachable.';
  return `⚠️ API degraded — ${data?.neo4j?.error ?? 'Neo4j unreachable.'}`;
}

export function formatVulns(domain, data) {
  const { summary, findings } = data;
  if (!findings.length) return `No vulnerabilities recorded for *${domain}*.`;

  const header =
    `*${domain}* — ${summary.total} finding${summary.total === 1 ? '' : 's'} ` +
    `(${summary.high} high, ${summary.medium} medium, ${summary.low} low, ${summary.with_exploits} with exploits)`;

  const lines = findings
    .slice(0, 10)
    .map((f) => `${emoji(f.risk)} *${f.cve}* (${f.cvss ?? '?'}) — ${f.software ?? '?'} ${f.version ?? ''}\n   ${f.why}`);

  const footer = findings.length > 10 ? `\n…and ${findings.length - 10} more.` : '';
  return capMessage([header, '', ...lines].join('\n') + footer);
}

export function formatChains(data) {
  const { count, chains, note } = data;
  if (!chains.length) return note || 'No chains found.';

  const lines = chains.slice(0, 5).map((c) => {
    const path = c.steps.map((s) => `${s.cve}${s.kev ? '⚡' : ''}`).join(' → ');
    return `*${c.score}* ${c.host} — ${c.length} steps\n   ${path}`;
  });

  const footer = chains.length > 5 ? `\n…and ${chains.length - 5} more.` : '';
  return capMessage([`${count} inferred chain${count === 1 ? '' : 's'}:`, '', ...lines].join('\n') + footer);
}

export function formatConflicts(data) {
  const { total, by_kind, conflicts } = data;
  if (!total) return 'No live conflicts. 🎉';

  const kinds = Object.entries(by_kind)
    .map(([k, v]) => `${k}: ${v}`)
    .join(', ');

  const lines = conflicts
    .slice(0, 8)
    .map((c) => `${emoji(c.severity)} *${c.kind}* — ${c.subject} ${c.predicate}\n   ${c.detail}`);

  const footer = conflicts.length > 8 ? `\n…and ${conflicts.length - 8} more.` : '';
  return capMessage([`${total} conflict${total === 1 ? '' : 's'} (${kinds}):`, '', ...lines].join('\n') + footer);
}

export function formatExploitable(data) {
  const { count, items } = data;
  if (!count) return 'Nothing currently exploitable in the graph.';

  const lines = items
    .slice(0, 10)
    .map(
      (i) =>
        `${emoji(i.risk)} *${i.cve}* (${i.cvss ?? '?'}) — ${i.software ?? '?'} · ${(i.domains ?? []).filter(Boolean).join(', ') || 'no domain on record'}`,
    );

  const footer = count > 10 ? `\n…and ${count - 10} more.` : '';
  return capMessage([`${count} exploitable finding${count === 1 ? '' : 's'}:`, '', ...lines].join('\n') + footer);
}

export function formatSearch(query, data) {
  const nodes = data.elements?.nodes ?? [];
  if (!data.count) return `No matches for "${query}".`;

  const lines = nodes.slice(0, 10).map((n) => `• *${n.data.type}* ${n.data.label}`);
  const footer = nodes.length > 10 ? `\n…and ${nodes.length - 10} more.` : '';
  return capMessage([`${data.count} match${data.count === 1 ? '' : 'es'} for "${query}":`, '', ...lines].join('\n') + footer);
}
