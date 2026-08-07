// nexus seed data.
// Entities carry only business-key identity here; every fact about how they
// relate, and the mutable `exploited` property on CVE, is asserted via a
// (:Claim) node and materialized by backfill-claims.cypher / claims.js.
// Never set relationships or the `exploited`/derived fields directly here.

// ---- Entities ----

CREATE (:Domain {name: 'example.com'});
CREATE (:Domain {name: 'staging.example.com'});

CREATE (:Host {ip: '93.184.216.34', hostname: 'example.com'});
CREATE (:Host {ip: '10.0.0.5', hostname: 'staging.example.com'});

CREATE (:CVE {id: 'CVE-2021-44228', description: 'Apache Log4j2 JNDI lookup RCE (Log4Shell)', cvss: 10.0, kev: true});
CREATE (:CVE {id: 'CVE-2021-41617', description: 'OpenSSH privilege escalation via supplemental group misconfiguration', cvss: 7.0, kev: false});
CREATE (:CVE {id: 'CVE-2020-0601', description: 'Windows CryptoAPI ECC certificate spoofing (CurveBall)', cvss: 8.1, kev: true});
CREATE (:CVE {id: 'CVE-2022-1234', description: 'Example product information disclosure via verbose error messages', cvss: 3.1, kev: false});

// ---- Claims: Domain -RESOLVES_TO-> Host ----

MATCH (s:Domain {name: 'example.com'}), (o:Host {ip: '93.184.216.34'})
CREATE (cl:Claim {id: randomUUID(), predicate: 'RESOLVES_TO', source: 'dns', confidence: 0.95,
                   assertedAt: datetime('2024-01-10T00:00:00Z'), retracted: false})
CREATE (cl)-[:SUBJECT]->(s)
CREATE (cl)-[:OBJECT]->(o);

MATCH (s:Domain {name: 'staging.example.com'}), (o:Host {ip: '10.0.0.5'})
CREATE (cl:Claim {id: randomUUID(), predicate: 'RESOLVES_TO', source: 'dns', confidence: 0.95,
                   assertedAt: datetime('2024-01-10T00:00:00Z'), retracted: false})
CREATE (cl)-[:SUBJECT]->(s)
CREATE (cl)-[:OBJECT]->(o);

// ---- Claims: Host -HAS_VULNERABILITY-> CVE ----

MATCH (s:Host {ip: '93.184.216.34'}), (o:CVE {id: 'CVE-2021-44228'})
CREATE (cl:Claim {id: randomUUID(), predicate: 'HAS_VULNERABILITY', source: 'shodan', confidence: 0.9,
                   assertedAt: datetime('2024-01-01T00:00:00Z'), retracted: false})
CREATE (cl)-[:SUBJECT]->(s)
CREATE (cl)-[:OBJECT]->(o);

MATCH (s:Host {ip: '93.184.216.34'}), (o:CVE {id: 'CVE-2021-41617'})
CREATE (cl:Claim {id: randomUUID(), predicate: 'HAS_VULNERABILITY', source: 'nvd-scan', confidence: 0.8,
                   assertedAt: datetime('2024-01-02T00:00:00Z'), retracted: false})
CREATE (cl)-[:SUBJECT]->(s)
CREATE (cl)-[:OBJECT]->(o);

MATCH (s:Host {ip: '93.184.216.34'}), (o:CVE {id: 'CVE-2020-0601'})
CREATE (cl:Claim {id: randomUUID(), predicate: 'HAS_VULNERABILITY', source: 'qualys', confidence: 0.85,
                   assertedAt: datetime('2024-01-03T00:00:00Z'), retracted: false})
CREATE (cl)-[:SUBJECT]->(s)
CREATE (cl)-[:OBJECT]->(o);

MATCH (s:Host {ip: '93.184.216.34'}), (o:CVE {id: 'CVE-2022-1234'})
CREATE (cl:Claim {id: randomUUID(), predicate: 'HAS_VULNERABILITY', source: 'nessus', confidence: 0.5,
                   assertedAt: datetime('2024-01-04T00:00:00Z'), retracted: false})
CREATE (cl)-[:SUBJECT]->(s)
CREATE (cl)-[:OBJECT]->(o);

// Retracted false-positive: staging host was auto-flagged for Log4Shell by a
// banner-matching scanner, then an analyst retracted it. Since this is the
// ONLY claim for this (host, CVE) pair and it is retracted, no derived
// HAS_VULNERABILITY edge should exist between staging host and CVE-2021-44228.
MATCH (s:Host {ip: '10.0.0.5'}), (o:CVE {id: 'CVE-2021-44228'})
CREATE (cl:Claim {id: randomUUID(), predicate: 'HAS_VULNERABILITY', source: 'auto-scanner', confidence: 0.4,
                   assertedAt: datetime('2024-01-05T00:00:00Z'), retracted: true,
                   retractedAt: datetime('2024-01-06T00:00:00Z'),
                   retractedReason: 'false positive - banner string match only, service is not Log4j'})
CREATE (cl)-[:SUBJECT]->(s)
CREATE (cl)-[:OBJECT]->(o);

// ---- Claim: CVE -CHAINS_TO-> CVE ----
// Initial RCE via Log4Shell can be used to reach a local account, from which
// the OpenSSH supplemental-groups bug escalates to root.
MATCH (s:CVE {id: 'CVE-2021-44228'}), (o:CVE {id: 'CVE-2021-41617'})
CREATE (cl:Claim {id: randomUUID(), predicate: 'CHAINS_TO', source: 'analyst:redteam', confidence: 0.75,
                   assertedAt: datetime('2024-02-10T00:00:00Z'), retracted: false})
CREATE (cl)-[:SUBJECT]->(s)
CREATE (cl)-[:OBJECT]->(o);

// ---- Property claims: CVE.exploited ----
// KEV/actively-exploited status, contested for CVE-2022-1234 to exercise the
// conflicts pipeline (two live, disagreeing sources).

MATCH (s:CVE {id: 'CVE-2021-44228'})
CREATE (cl:Claim {id: randomUUID(), predicate: 'PROPERTY', property: 'exploited', value: true,
                   source: 'cisa-kev', confidence: 0.99,
                   assertedAt: datetime('2024-01-01T00:00:00Z'), retracted: false})
CREATE (cl)-[:SUBJECT]->(s);

MATCH (s:CVE {id: 'CVE-2020-0601'})
CREATE (cl:Claim {id: randomUUID(), predicate: 'PROPERTY', property: 'exploited', value: true,
                   source: 'cisa-kev', confidence: 0.99,
                   assertedAt: datetime('2024-01-01T00:00:00Z'), retracted: false})
CREATE (cl)-[:SUBJECT]->(s);

MATCH (s:CVE {id: 'CVE-2021-41617'})
CREATE (cl:Claim {id: randomUUID(), predicate: 'PROPERTY', property: 'exploited', value: false,
                   source: 'nvd', confidence: 0.7,
                   assertedAt: datetime('2024-01-01T00:00:00Z'), retracted: false})
CREATE (cl)-[:SUBJECT]->(s);

MATCH (s:CVE {id: 'CVE-2022-1234'})
CREATE (cl:Claim {id: randomUUID(), predicate: 'PROPERTY', property: 'exploited', value: false,
                   source: 'nvd', confidence: 0.9,
                   assertedAt: datetime('2024-02-01T00:00:00Z'), retracted: false})
CREATE (cl)-[:SUBJECT]->(s);

MATCH (s:CVE {id: 'CVE-2022-1234'})
CREATE (cl:Claim {id: randomUUID(), predicate: 'PROPERTY', property: 'exploited', value: true,
                   source: 'greynoise', confidence: 0.6,
                   assertedAt: datetime('2024-03-15T00:00:00Z'), retracted: false})
CREATE (cl)-[:SUBJECT]->(s);
