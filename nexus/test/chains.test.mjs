import { parseVector, capabilities, canFollow, chainScore } from '../src/analysis/cvss.js';

let fails = 0;
const eq = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) { fails++; console.log(`FAIL ${label}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`); }
  else console.log(`ok   ${label}`);
};

// --- vector parsing ---
eq('parses 3.1 vector', parseVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').AV, 'N');
eq('ignores junk', parseVector('not a vector'), null);
eq('scope read', parseVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H').S, 'C');

// --- real-world CVEs ---
const log4shell = capabilities({
  id: 'CVE-2021-44228', cvss: 10.0, cwe: ['CWE-502','CWE-917'],
  vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
});
const sshPrivesc = capabilities({
  id: 'CVE-2021-41617', cvss: 7.0, cwe: ['CWE-269'],
  vector: 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H',
});
const infoLeak = capabilities({
  id: 'CVE-2020-0000', cvss: 5.3, cwe: ['CWE-200'],
  vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
});
const phishy = capabilities({
  id: 'CVE-2020-1111', cvss: 8.8, cwe: ['CWE-94'],
  vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
});

eq('log4shell is an entry point', log4shell.isEntryPoint, true);
eq('log4shell grants code execution', log4shell.grants.includes('code_execution'), true);
eq('ssh privesc is local', sshPrivesc.reach, 'local');
eq('ssh privesc needs a foothold', sshPrivesc.requiresPrivilege, 'low');
eq('ssh privesc reaches high', sshPrivesc.privilegeAfter, 'high');
eq('user-interaction bug is not an entry point', phishy.isEntryPoint, false);

// --- composition rules ---
eq('rce then privesc chains', Boolean(canFollow(log4shell, sshPrivesc)), true);
eq('privesc cannot start the chain', sshPrivesc.isEntryPoint, false);
eq('local bug needs code exec first', canFollow(infoLeak, sshPrivesc), null);
eq('no self-chaining', canFollow(log4shell, log4shell), null);
eq('no chaining without gain', canFollow(log4shell, {...log4shell, id:'CVE-X'}), null);
eq('will not assume user interaction', canFollow(log4shell, phishy), null);
eq('rationale names both ends', canFollow(log4shell, sshPrivesc).includes('CVE-2021-41617'), true);

// --- scoring ---
const full = chainScore([log4shell, sshPrivesc]);
eq('two-step chain scores high', full >= 70, true);
eq('single step scores nothing', chainScore([log4shell]), 0);
const vague = chainScore([{...log4shell, confidence: 0.5}, sshPrivesc]);
eq('weakest link caps the chain', vague < full, true);

// --- missing vector must degrade, not crash ---
const noVector = capabilities({ id: 'CVE-2019-9999', cvss: 9.8, cwe: ['CWE-78'], attack_vector: 'NETWORK' });
eq('survives a missing vector', noVector.reach, 'network');
eq('missing vector lowers confidence', noVector.confidence, 0.5);
eq('handles an empty cve object', capabilities({}).grants, []);

console.log(fails ? `\n${fails} failing` : '\nall passing');
process.exit(fails ? 1 : 0);
