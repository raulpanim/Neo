import {
  parseCommand, capMessage, formatHelp, formatHealth,
  formatVulns, formatChains, formatConflicts, formatExploitable, formatSearch,
  formatConflictAlert, formatExploitableAlert,
} from '../src/telegram/format.js';
import { diffNew, conflictKey, exploitableKey } from '../src/telegram/alerts.js';

let fails = 0;
const eq = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) { fails++; console.log(`FAIL ${label}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`); }
  else console.log(`ok   ${label}`);
};
const ok = (label, cond) => eq(label, Boolean(cond), true);

// --- command parsing ---
eq('parses a bare command', parseCommand('/help'), { command: 'help', args: '' });
eq('parses a command with args', parseCommand('/vulns example.com'), { command: 'vulns', args: 'example.com' });
eq('trims surrounding whitespace', parseCommand('  /health  '), { command: 'health', args: '' });
eq('collapses multi-word args', parseCommand('/search log4j rce'), { command: 'search', args: 'log4j rce' });
eq('strips @BotName in group chats', parseCommand('/help@NexusBot'), { command: 'help', args: '' });
eq('lowercases the command', parseCommand('/HELP'), { command: 'help', args: '' });
eq('plain text is not a command', parseCommand('hello there'), null);
eq('empty string is not a command', parseCommand(''), null);
eq('non-string input is not a command', parseCommand(undefined), null);
eq('bare slash has no command', parseCommand('/'), null);

// --- message capping ---
eq('short text passes through unchanged', capMessage('hello'), 'hello');
const long = 'x'.repeat(5000);
ok('long text gets truncated', capMessage(long).length < 5000);
ok('truncated text stays under the Telegram cap', capMessage(long).length <= 4096);
ok('truncated text explains itself', capMessage(long).includes('truncated'));

// --- static formatting ---
ok('help lists /vulns', formatHelp().includes('/vulns'));
ok('help lists /chains', formatHelp().includes('/chains'));

eq('healthy status', formatHealth({ status: 'ok', neo4j: { ok: true } }), '✅ API ok — Neo4j reachable.');
ok('degraded status mentions the error', formatHealth({ status: 'degraded', neo4j: { ok: false, error: 'ECONNREFUSED' } }).includes('ECONNREFUSED'));

// --- vulns ---
eq('no findings for a clean domain', formatVulns('clean.example', { summary: {}, findings: [] }),
   'No vulnerabilities recorded for *clean.example*.');

const vulnsData = {
  summary: { total: 2, high: 1, medium: 1, low: 0, with_exploits: 1 },
  findings: [
    { cve: 'CVE-2021-44228', cvss: 10, risk: 'high', software: 'Log4j', version: '2.14.1', why: 'CVSS 10 · exploited in the wild' },
    { cve: 'CVE-2021-23017', cvss: 9.4, risk: 'medium', software: 'nginx', version: '1.18.0', why: 'CVSS 9.4' },
  ],
};
const vulnsMsg = formatVulns('example.com', vulnsData);
ok('vulns message names the domain', vulnsMsg.includes('example.com'));
ok('vulns message includes the summary counts', vulnsMsg.includes('2 findings') && vulnsMsg.includes('1 high'));
ok('vulns message includes each CVE', vulnsMsg.includes('CVE-2021-44228') && vulnsMsg.includes('CVE-2021-23017'));
ok('high risk gets the red marker', vulnsMsg.includes('🔴 *CVE-2021-44228*'));
ok('medium risk gets the orange marker', vulnsMsg.includes('🟠 *CVE-2021-23017*'));

const manyFindings = Array.from({ length: 15 }, (_, i) => ({
  cve: `CVE-2020-${1000 + i}`, cvss: 5, risk: 'low', software: 'x', version: '1', why: 'x',
}));
const cappedVulns = formatVulns('big.example', { summary: { total: 15, high: 0, medium: 0, low: 15, with_exploits: 0 }, findings: manyFindings });
ok('long finding lists say how many more', cappedVulns.includes('and 5 more'));

// --- chains ---
eq('no chains falls back to the note', formatChains({ count: 0, chains: [], note: 'No chain found.' }), 'No chain found.');

const chainsData = {
  count: 1,
  chains: [{
    host: '1.2.3.4', score: 90, length: 2,
    steps: [
      { cve: 'CVE-2021-44228', kev: true, privilege_after: 'high' },
      { cve: 'CVE-2021-41617', kev: false, privilege_after: 'high' },
    ],
  }],
};
const chainsMsg = formatChains(chainsData);
ok('chains message names the host', chainsMsg.includes('1.2.3.4'));
ok('chains message shows the full path', chainsMsg.includes('CVE-2021-44228⚡ → CVE-2021-41617'));
eq('non-kev step has no lightning marker', chainsMsg.includes('CVE-2021-41617⚡'), false);

// --- conflicts ---
eq('no conflicts is good news', formatConflicts({ total: 0, by_kind: {}, conflicts: [] }), 'No live conflicts. 🎉');

const conflictsData = {
  total: 1,
  by_kind: { stale: 1 },
  conflicts: [{ kind: 'stale', severity: 'medium', subject: 'example.com', predicate: 'RESOLVES_TO', detail: 'Last observed 6d ago.' }],
};
const conflictsMsg = formatConflicts(conflictsData);
ok('conflicts message includes the subject', conflictsMsg.includes('example.com'));
ok('conflicts message includes the detail', conflictsMsg.includes('Last observed 6d ago.'));

// --- exploitable ---
eq('nothing exploitable', formatExploitable({ count: 0, items: [] }), 'Nothing currently exploitable in the graph.');

const exploitableMsg = formatExploitable({
  count: 1,
  items: [{ cve: 'CVE-2021-44228', cvss: 10, risk: 'high', software: 'Log4j', domains: ['example.com', null] }],
});
ok('exploitable message includes the cve', exploitableMsg.includes('CVE-2021-44228'));
ok('exploitable message filters null domains', !exploitableMsg.includes('null'));

// --- search ---
eq('no matches', formatSearch('zzz', { count: 0, elements: { nodes: [] } }), 'No matches for "zzz".');

const searchMsg = formatSearch('example', {
  count: 1,
  elements: { nodes: [{ data: { type: 'Domain', label: 'example.com' } }] },
});
ok('search message includes the match', searchMsg.includes('example.com'));

// --- alert formatting ---
ok('conflict alert names the kind and subject', formatConflictAlert(conflictsData.conflicts[0]).includes('stale') && formatConflictAlert(conflictsData.conflicts[0]).includes('example.com'));
ok('exploitable alert names the cve', formatExploitableAlert({ cve: 'CVE-2021-44228', cvss: 10, software: 'Log4j', domains: [] }).includes('CVE-2021-44228'));

// --- alert keys ---
eq('conflict key is stable across identical conflicts', conflictKey({ kind: 'stale', subject_id: 'a', predicate: 'RESOLVES_TO', object_id: null }),
   conflictKey({ kind: 'stale', subject_id: 'a', predicate: 'RESOLVES_TO', object_id: null }));
ok('conflict key differs by kind', conflictKey({ kind: 'stale', subject_id: 'a', predicate: 'RESOLVES_TO' }) !== conflictKey({ kind: 'weak_support', subject_id: 'a', predicate: 'RESOLVES_TO' }));
eq('exploitable key is just the cve', exploitableKey({ cve: 'CVE-2021-44228' }), 'exploitable|CVE-2021-44228');

// --- diffNew: the actual alerting logic ---
const items = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];
const keyOf = (i) => i.id;

const firstRun = diffNew([], items, keyOf);
eq('everything is new against an empty seen set', firstRun.fresh.length, 3);
eq('seen set grows to cover every item', firstRun.seen.length, 3);

const secondRun = diffNew(firstRun.seen, items, keyOf);
eq('nothing is new once everything has been seen', secondRun.fresh, []);
eq('seen set is unchanged when nothing is new', secondRun.seen, firstRun.seen);

const withOneNew = diffNew(firstRun.seen, [...items, { id: 'd' }], keyOf);
eq('only the genuinely new item is reported', withOneNew.fresh, [{ id: 'd' }]);
eq('seen set grows by exactly the new item', withOneNew.seen.length, 4);

const afterRetraction = diffNew(firstRun.seen, [{ id: 'a' }], keyOf);
eq('an item missing from the current list is not reported as new', afterRetraction.fresh, []);
ok('seen set is not shrunk just because an item is temporarily absent', afterRetraction.seen.includes('b') && afterRetraction.seen.includes('c'));

console.log(fails ? `\n${fails} failing` : '\nall passing');
process.exit(fails ? 1 : 0);
