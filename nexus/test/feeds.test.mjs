import { parseFeed, extractCveIds } from '../src/sources/feedParser.js';
import { combineConfidence, independentSources } from '../src/sources/reliability.js';
import { riskScore, riskBand, attentionScore } from '../src/risk.js';

let fails = 0;
const eq = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) { fails++; console.log(`FAIL ${label}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`); }
  else console.log(`ok   ${label}`);
};

// --- CVE extraction ---
eq('finds cve in title', extractCveIds('Critical SSRF in SharePoint (CVE-2026-70332)'), ['CVE-2026-70332']);
eq('dedupes and upcases', extractCveIds('cve-2021-44228 and CVE-2021-44228'), ['CVE-2021-44228']);
eq('ignores non-cve text', extractCveIds('no identifiers here'), []);
eq('handles 7-digit ids', extractCveIds('CVE-2026-1234567').length, 1);

// --- RSS parsing ---
const xml = `<rss><channel>
<item><title><![CDATA[Azure Confidential Ledger RCE (CVE-2026-68823)]]></title>
<link>https://example.test/a/</link><pubDate>Fri, 07 Aug 2026 09:00:00 +0000</pubDate>
<description><![CDATA[<p>Exposed dangerous method.</p>]]></description>
<category>CVE</category></item>
<item><title>Weekly roundup</title><link>https://example.test/b/</link>
<description>No identifiers.</description></item>
</channel></rss>`;
const items = parseFeed(xml);
eq('parses both items', items.length, 2);
eq('strips cdata and html', items[0].description ?? items[0].summary, 'Exposed dangerous method.');
eq('extracts cve from item', items[0].cves, ['CVE-2026-68823']);
eq('roundup has no cves', items[1].cves, []);
eq('parses date to iso', items[0].published.slice(0, 10), '2026-08-07');
eq('reads categories', items[0].categories, ['CVE']);

// --- derivative sources must not double-count ---
eq('derivative dropped when parent present', independentSources(['nvd','thehackerwire']), ['nvd']);
eq('derivative counts alone', independentSources(['thehackerwire']), ['thehackerwire']);
eq('nvd + derivative == nvd alone', combineConfidence(['nvd','thehackerwire']), combineConfidence(['nvd']));
eq('genuinely independent still combines', combineConfidence(['nvd','shodan']) > combineConfidence(['nvd']), true);

// --- attention scoring ---
eq('three outlets this week is loud', attentionScore({outlets:3, mentions:4, latest:new Date().toISOString()}) >= 0.85, true);
eq('one outlet spamming stays modest', attentionScore({outlets:1, mentions:6, latest:new Date().toISOString()}) < 0.6, true);
eq('breadth beats volume',
   attentionScore({outlets:3, mentions:3, latest:new Date().toISOString()}) >
   attentionScore({outlets:1, mentions:6, latest:new Date().toISOString()}), true);

// --- attention must not outrank an exploit ---
const loudButQuiet = riskScore({cvss:7.5, attention:1, exploits:[], confidence:1});
const quietButExploited = riskScore({cvss:7.5, attention:0, exploits:[{verified:true}], confidence:1});
eq('exploit outranks press', quietButExploited > loudButQuiet, true);
eq('press cannot lift low to high', riskBand(riskScore({cvss:4, attention:1, confidence:1})), 'low');

console.log(fails ? `\n${fails} failing` : '\nall passing');
process.exit(fails ? 1 : 0);
