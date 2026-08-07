import {
  normalizeHostApi, normalizeInternetDb, softwareFromCpe, softwareFromBanner,
  portKey, ownershipGate,
} from '../src/sources/shodanParser.js';
import { combineConfidence, independentSources } from '../src/sources/reliability.js';

let fails = 0;
const eq = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) { fails++; console.log(`FAIL ${label}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`); }
  else console.log(`ok   ${label}`);
};

// --- full host API ---
const hostApi = normalizeHostApi({
  ip_str: '1.2.3.4',
  hostnames: ['www.example.com'],
  asn: 'AS64500', org: 'Example Corp',
  location: { country_code: 'US' },
  vulns: { 'CVE-2021-23017': {} },
  data: [
    { port: 443, transport: 'tcp', product: 'nginx', version: '1.18.0',
      cpe23: ['cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*'],
      timestamp: '2026-08-01T10:00:00.000000', hash: -12345,
      _shodan: { module: 'https' },
      banner: 'HTTP/1.1 200 OK\nSet-Cookie: session=secret' },
    { port: 22, transport: 'tcp', product: 'OpenSSH', version: '8.2p1', _shodan: { module: 'ssh' } },
  ],
});

eq('reads ip', hostApi.ip, '1.2.3.4');
eq('reads two services', hostApi.services.length, 2);
eq('reads product and version', [hostApi.services[0].product, hostApi.services[0].version], ['nginx','1.18.0']);
eq('vulns object becomes a list', hostApi.vulns, ['CVE-2021-23017']);
eq('keeps a banner hash', hostApi.services[0].banner_hash, '-12345');
eq('never stores the raw banner', JSON.stringify(hostApi).includes('session=secret'), false);
eq('marks its own source', hostApi.source, 'shodan');

// --- InternetDB ---
const idb = normalizeInternetDb({
  ip: '1.2.3.4', ports: [22, 443],
  cpes: ['cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*'],
  hostnames: ['www.example.com'], vulns: ['CVE-2021-23017'], tags: ['cdn'],
});
eq('internetdb ports', idb.services.map((s) => s.port), [22, 443]);
eq('internetdb attributes no software to ports', idb.services.every((s) => s.cpes.length === 0), true);
eq('internetdb keeps cpes unattributed', idb.unattributed_cpes.length, 1);
eq('internetdb has no versions', idb.services[0].version, null);

// derivative: internetdb must not double-count against shodan
eq('internetdb collapses into shodan', independentSources(['shodan','internetdb']), ['shodan']);
eq('combined equals shodan alone', combineConfidence(['shodan','internetdb']), combineConfidence(['shodan']));

// --- software mapping ---
eq('cpe to software', softwareFromCpe('cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'),
   { cpe: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*', name: 'log4j', vendor: 'apache', version: '2.14.1' });
eq('wildcard version becomes unknown', softwareFromCpe('cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*').version, 'unknown');
eq('junk cpe rejected', softwareFromCpe('nginx 1.18'), null);
eq('banner fallback works', softwareFromBanner({ product: 'OpenSSH', version: '8.2p1' }).name, 'OpenSSH');
eq('banner fallback needs a product', softwareFromBanner({ version: '1.0' }), null);
eq('port key format', portKey('1.2.3.4', 443, 'tcp'), '1.2.3.4:443/tcp');

// --- ownership gate ---
eq('owned host allowed', ownershipGate({ address: '1.2.3.4', owned: true }).allowed, true);
eq('unowned host blocked', ownershipGate({ address: '9.9.9.9', owned: false }).allowed, false);
eq('override without reason blocked', ownershipGate({ owned: false }, { allowUnowned: true }).allowed, false);
eq('override with reason allowed', ownershipGate({ owned: false }, { allowUnowned: true, reason: 'client engagement 4412' }).allowed, true);
eq('basis records the override', ownershipGate({ owned: false }, { allowUnowned: true, reason: 'engagement 4412' }).basis.includes('engagement 4412'), true);

console.log(fails ? `\n${fails} failing` : '\nall passing');
process.exit(fails ? 1 : 0);
