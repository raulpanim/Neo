// ==========================================================
// NEXUS :: graph schema (constraints + indexes)
// run:  cat db/schema.cypher | docker exec -i nexus-neo4j cypher-shell -u neo4j -p nexus_dev_pass
// ==========================================================

// --- uniqueness -------------------------------------------------
CREATE CONSTRAINT domain_name IF NOT EXISTS
  FOR (d:Domain)   REQUIRE d.name    IS UNIQUE;
CREATE CONSTRAINT ip_address IF NOT EXISTS
  FOR (i:IP)       REQUIRE i.address IS UNIQUE;
CREATE CONSTRAINT software_cpe IF NOT EXISTS
  FOR (s:Software) REQUIRE s.cpe     IS UNIQUE;
CREATE CONSTRAINT cve_id IF NOT EXISTS
  FOR (c:CVE)      REQUIRE c.id      IS UNIQUE;
CREATE CONSTRAINT exploit_id IF NOT EXISTS
  FOR (e:Exploit)  REQUIRE e.id      IS UNIQUE;
CREATE CONSTRAINT company_name IF NOT EXISTS
  FOR (o:Company)  REQUIRE o.name    IS UNIQUE;
CREATE CONSTRAINT email_addr IF NOT EXISTS
  FOR (m:Email)    REQUIRE m.address IS UNIQUE;
CREATE CONSTRAINT asn_number IF NOT EXISTS
  FOR (a:ASN)      REQUIRE a.number  IS UNIQUE;
CREATE CONSTRAINT port_key IF NOT EXISTS
  FOR (p:Port)     REQUIRE p.key     IS UNIQUE;   // "1.2.3.4:443/tcp"

CREATE CONSTRAINT report_url IF NOT EXISTS
  FOR (r:Report)   REQUIRE r.url     IS UNIQUE;
CREATE CONSTRAINT claim_key IF NOT EXISTS
  FOR (c:Claim)    REQUIRE c.key     IS UNIQUE;

// --- lookup indexes ---------------------------------------------
CREATE INDEX cve_cvss       IF NOT EXISTS FOR (c:CVE)      ON (c.cvss);
CREATE INDEX cve_severity   IF NOT EXISTS FOR (c:CVE)      ON (c.severity);
CREATE INDEX cve_published  IF NOT EXISTS FOR (c:CVE)      ON (c.published);
CREATE INDEX sw_name        IF NOT EXISTS FOR (s:Software) ON (s.name);
CREATE INDEX domain_seen    IF NOT EXISTS FOR (d:Domain)   ON (d.last_seen);
CREATE INDEX claim_predicate IF NOT EXISTS FOR (c:Claim)   ON (c.predicate);
CREATE INDEX claim_observed  IF NOT EXISTS FOR (c:Claim)   ON (c.observed_at);
CREATE INDEX claim_source    IF NOT EXISTS FOR (c:Claim)   ON (c.source);

// --- full-text search (powers /api/graph/search) -----------------
CREATE FULLTEXT INDEX nexus_search IF NOT EXISTS
FOR (n:Domain|IP|Software|CVE|Exploit|Company|Email|ASN|Report)
ON EACH [n.name, n.address, n.id, n.cpe, n.description, n.title, n.number];
