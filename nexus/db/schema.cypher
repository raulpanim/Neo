// nexus schema: uniqueness constraints on business keys.
// Claims are the only source of truth for edges/properties (see claims.js);
// nothing here creates derived relationships.

CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE;
CREATE CONSTRAINT host_ip IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE;
CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE;
CREATE CONSTRAINT claim_id IF NOT EXISTS FOR (cl:Claim) REQUIRE cl.id IS UNIQUE;
