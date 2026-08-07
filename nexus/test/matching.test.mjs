import { compareVersions, inVersionRange, matchSoftware, parseCpe23 } from '../src/sources/cpe.js';
import { riskScore, riskBand } from '../src/risk.js';

let fails = 0;
const eq = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) { fails++; console.log(`FAIL ${label}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`); }
  else console.log(`ok   ${label}`);
};

// version comparison
eq('1.18.0 < 1.18.1', Math.sign(compareVersions('1.18.0','1.18.1')), -1);
eq('1.9 < 1.10', Math.sign(compareVersions('1.9','1.10')), -1);
eq('8.2p1 > 8.2', Math.sign(compareVersions('8.2p1','8.2')), 1);
eq('2.14.1 == 2.14.1', compareVersions('2.14.1','2.14.1'), 0);
eq('1.0.0-rc1 < 1.0.0', Math.sign(compareVersions('1.0.0-rc1','1.0.0')), -1);
eq('1.0.2k > 1.0.2b', Math.sign(compareVersions('1.0.2k','1.0.2b')), 1);

// ranges
eq('in [2.0,2.15)', inVersionRange('2.14.1', {versionStartIncluding:'2.0', versionEndExcluding:'2.15.0'}), true);
eq('out of range', inVersionRange('2.16.0', {versionStartIncluding:'2.0', versionEndExcluding:'2.15.0'}), false);
eq('no bounds -> false', inVersionRange('2.14.1', {}), false);

// cpe parse
eq('parse vendor', parseCpe23('cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*').vendor, 'apache');

// software matching
const log4j = { name:'Log4j', vendor:'apache', version:'2.14.1' };
eq('range match', matchSoftware(log4j, {criteria:'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*', versionStartIncluding:'2.0', versionEndExcluding:'2.15.0'}).method, 'cpe-range');
eq('exact match', matchSoftware(log4j, {criteria:'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'}).method, 'cpe-exact');
eq('wrong vendor', matchSoftware(log4j, {criteria:'cpe:2.3:a:nginx:log4j:2.14.1:*:*:*:*:*:*:*'}).matched, false);
eq('wildcard weak', matchSoftware(log4j, {criteria:'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*'}).confidence, 0.5);

// risk model
const shell = riskScore({cvss:10, kev:true, attack_vector:'NETWORK', exploits:[{verified:true}], confidence:1});
const quiet = riskScore({cvss:9.8, exploits:[], confidence:0.45});
eq('log4shell -> 100', shell, 100);
eq('unconfirmed high stays medium', riskBand(quiet), 'medium');
eq('confident exploited outranks unconfirmed', shell > quiet, true);

console.log(fails ? `\n${fails} failing` : '\nall passing');
process.exit(fails ? 1 : 0);
