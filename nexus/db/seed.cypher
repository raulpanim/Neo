// ==========================================================
// NEXUS :: sample dataset (MVP week 1-2)
// Public / synthetic data only. example.com is IANA-reserved.
// ==========================================================

MATCH (n) DETACH DELETE n;

// --- entities ----------------------------------------------------
CREATE (d1:Domain {name:'example.com', confidence:1.0, owned:true,
                   ownership_proof:'dns-txt:nexus-verify=8f21c', first_seen:date('2024-01-10'), last_seen:date('2026-08-01')})
CREATE (d2:Domain {name:'api.example.com', confidence:0.95, owned:true,
                   ownership_proof:'dns-txt:nexus-verify=8f21c', first_seen:date('2024-03-02'), last_seen:date('2026-08-01')})
CREATE (d3:Domain {name:'legacy.example.com', confidence:0.7, owned:false,
                   ownership_proof:null, first_seen:date('2023-05-19'), last_seen:date('2026-06-14')})

CREATE (ip1:IP {address:'1.2.3.4', country:'US', confidence:0.98, first_seen:date('2024-01-10'), last_seen:date('2026-08-01')})
CREATE (ip2:IP {address:'1.2.3.9', country:'DE', confidence:0.82, first_seen:date('2024-03-02'), last_seen:date('2026-07-28')})

CREATE (as1:ASN {number:'AS64500', name:'EXAMPLE-TRANSIT', confidence:0.9})
CREATE (co1:Company {name:'Example Corp', country:'US', confidence:0.85})
CREATE (em1:Email {address:'noc@example.com', source:'whois', confidence:0.6})

CREATE (p1:Port {key:'1.2.3.4:443/tcp',  number:443,  protocol:'tcp', service:'https', confidence:0.98})
CREATE (p2:Port {key:'1.2.3.4:22/tcp',   number:22,   protocol:'tcp', service:'ssh',   confidence:0.98})
CREATE (p3:Port {key:'1.2.3.9:8080/tcp', number:8080, protocol:'tcp', service:'http',  confidence:0.75})
CREATE (p4:Port {key:'1.2.3.4:8009/tcp', number:8009, protocol:'tcp', service:'ajp',   confidence:0.7})

CREATE (s1:Software {cpe:'cpe:2.3:a:nginx:nginx:1.18.0', name:'nginx', vendor:'nginx', version:'1.18.0', confidence:0.9})
CREATE (s2:Software {cpe:'cpe:2.3:a:openbsd:openssh:8.2p1', name:'OpenSSH', vendor:'openbsd', version:'8.2p1', confidence:0.88})
CREATE (s3:Software {cpe:'cpe:2.3:a:apache:log4j:2.14.1', name:'Log4j', vendor:'apache', version:'2.14.1', confidence:0.65})

CREATE (c1:CVE {id:'CVE-2021-44228', cvss:10.0, severity:'CRITICAL', kev:true, ransomware:true,
                attack_vector:'NETWORK', cwe:['CWE-502','CWE-917'],
                vector:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
                published:date('2021-12-10'), description:'Remote code execution via JNDI lookup in Log4j 2.'})
CREATE (c2:CVE {id:'CVE-2021-23017', cvss:9.4, severity:'CRITICAL', kev:false,
                attack_vector:'NETWORK', cwe:['CWE-193','CWE-787'],
                vector:'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
                published:date('2021-05-25'), description:'Off-by-one in the nginx resolver, memory corruption.'})
CREATE (c3:CVE {id:'CVE-2020-15778', cvss:7.8, severity:'HIGH', kev:false,
                attack_vector:'NETWORK', cwe:['CWE-78'],
                vector:'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
                published:date('2020-07-24'), description:'Command injection via scp in OpenSSH.'})
CREATE (c4:CVE {id:'CVE-2021-41617', cvss:7.0, severity:'HIGH', kev:false,
                attack_vector:'LOCAL', cwe:['CWE-269'],
                vector:'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H',
                published:date('2021-09-26'), description:'Privilege escalation through unsanitised supplemental groups.'})

CREATE (e1:Exploit {id:'EDB-50592', source:'exploit-db', title:'Log4Shell JNDI RCE', type:'remote',
                    verified:true, url:'https://www.exploit-db.com/exploits/50592', published:date('2021-12-14')})
CREATE (e2:Exploit {id:'GH-PoC-log4shell', source:'github', title:'Public PoC repository', type:'remote',
                    verified:false, url:'https://github.com/search?q=log4shell+poc', published:date('2021-12-11')})

// --- relationships ------------------------------------------------
CREATE (d1)-[:RESOLVES_TO {sources:['dns','crtsh'], confidence:0.98, first_seen:date('2024-01-10'), last_seen:date('2026-08-01')}]->(ip1)
CREATE (d2)-[:RESOLVES_TO {sources:['dns'], confidence:0.95, first_seen:date('2024-03-02'), last_seen:date('2026-07-28')}]->(ip2)
CREATE (d3)-[:RESOLVES_TO {sources:['passive-dns'], confidence:0.6,  first_seen:date('2023-05-19'), last_seen:date('2026-06-14')}]->(ip1)
CREATE (d2)-[:SUBDOMAIN_OF {sources:['dns'], confidence:1.0}]->(d1)
CREATE (d3)-[:SUBDOMAIN_OF {sources:['dns'], confidence:1.0}]->(d1)

CREATE (ip1)-[:ANNOUNCED_BY {sources:['bgp'], confidence:0.99}]->(as1)
CREATE (ip2)-[:ANNOUNCED_BY {sources:['bgp'], confidence:0.99}]->(as1)
CREATE (d1)-[:OWNED_BY {sources:['whois'], confidence:0.85}]->(co1)
CREATE (co1)-[:HAS_CONTACT {sources:['whois'], confidence:0.6}]->(em1)

CREATE (ip1)-[:HAS_PORT {sources:['shodan'], confidence:0.98, last_seen:date('2026-08-01')}]->(p1)
CREATE (ip1)-[:HAS_PORT {sources:['shodan'], confidence:0.98, last_seen:date('2026-08-01')}]->(p2)
CREATE (ip2)-[:HAS_PORT {sources:['shodan'], confidence:0.75, last_seen:date('2026-07-28')}]->(p3)
CREATE (ip1)-[:HAS_PORT {sources:['shodan'], confidence:0.7,  last_seen:date('2026-08-01')}]->(p4)
CREATE (p4)-[:RUNS_SOFTWARE {sources:['banner'], confidence:0.6, last_seen:date('2026-08-01')}]->(s3)

CREATE (p1)-[:RUNS_SOFTWARE {sources:['banner'], confidence:0.9,  last_seen:date('2026-08-01')}]->(s1)
CREATE (p2)-[:RUNS_SOFTWARE {sources:['banner'], confidence:0.88, last_seen:date('2026-08-01')}]->(s2)
CREATE (p3)-[:RUNS_SOFTWARE {sources:['http-headers','guess'], confidence:0.45, last_seen:date('2026-07-28')}]->(s3)

CREATE (s1)-[:VULNERABLE_TO {sources:['nvd'], confidence:0.9, method:'cpe-match'}]->(c2)
CREATE (s2)-[:VULNERABLE_TO {sources:['nvd'], confidence:0.9, method:'cpe-match'}]->(c3)
CREATE (s2)-[:VULNERABLE_TO {sources:['nvd'], confidence:0.9, method:'cpe-match'}]->(c4)
CREATE (s3)-[:VULNERABLE_TO {sources:['nvd'], confidence:0.5, method:'version-guess'}]->(c1)

CREATE (c1)-[:HAS_EXPLOIT {sources:['exploit-db'], confidence:1.0}]->(e1)
CREATE (c1)-[:HAS_EXPLOIT {sources:['github'], confidence:0.7}]->(e2)

// attack chain: RCE as low-priv user -> local privesc
CREATE (c1)-[:CHAINS_TO {sources:['analyst'], confidence:0.6, rationale:'RCE lands as service account, then local privesc'}]->(c4);
