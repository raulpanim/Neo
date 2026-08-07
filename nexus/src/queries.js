// All Cypher lives here so queries stay reviewable and LIMIT-capped.
// Hard cap: Cytoscape degrades past ~500 nodes, so nothing returns more than 100 rows.

export const SEARCH = `
CALL db.index.fulltext.queryNodes('nexus_search', $q) YIELD node, score
RETURN node, score
ORDER BY score DESC
LIMIT $limit
`;

export const NODE_BY_ID = `
MATCH (n) WHERE elementId(n) = $id
RETURN n
`;

/**
 * Neighbourhood expansion. `depth` is interpolated, never user input —
 * the route validates it to an integer in 1..3 before calling.
 */
export const EXPAND = (depth) => `
MATCH (n) WHERE elementId(n) = $id
MATCH path = (n)-[*1..${depth}]-(m)
RETURN path
LIMIT $limit
`;

/** Full attack surface of a domain: domain -> ip -> port -> software -> cve -> exploit. */
export const ATTACK_SURFACE = `
MATCH (d:Domain {name: $domain})
OPTIONAL MATCH p1 = (d)-[:RESOLVES_TO]->(ip:IP)
OPTIONAL MATCH p2 = (d)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:RUNS_SOFTWARE]->(:Software)
OPTIONAL MATCH p3 = (d)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:RUNS_SOFTWARE]->(:Software)-[:VULNERABLE_TO]->(:CVE)
OPTIONAL MATCH p4 = (d)-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:RUNS_SOFTWARE]->(:Software)-[:VULNERABLE_TO]->(:CVE)-[:HAS_EXPLOIT]->(:Exploit)
OPTIONAL MATCH p5 = (d)-[:OWNED_BY]->(:Company)
RETURN d, p1, p2, p3, p4, p5
LIMIT $limit
`;

/** Flat vulnerability list for a domain, sorted by exploitability then CVSS. */
export const VULNS_FOR_DOMAIN = `
MATCH (d:Domain {name: $domain})-[:RESOLVES_TO]->(ip:IP)
      -[:HAS_PORT]->(port:Port)-[r:RUNS_SOFTWARE]->(sw:Software)
MATCH (sw)-[v:VULNERABLE_TO]->(cve:CVE)
OPTIONAL MATCH (cve)-[:HAS_EXPLOIT]->(ex:Exploit)
WITH ip, port, sw, cve, v, collect(DISTINCT {
       id: ex.id, source: ex.source, title: ex.title, verified: ex.verified, url: ex.url
     }) AS exploits,
     (r.confidence * v.confidence) AS chain_confidence
RETURN cve.id           AS cve,
       cve.cvss         AS cvss,
       cve.severity     AS severity,
       cve.kev          AS kev,
       cve.ransomware   AS ransomware,
       cve.attack_vector AS attack_vector,
       cve.description  AS description,
       sw.name          AS software,
       sw.version       AS version,
       ip.address       AS ip,
       port.number      AS port,
       v.method         AS match_method,
       chain_confidence AS confidence,
       [e IN exploits WHERE e.id IS NOT NULL] AS exploits
ORDER BY size([e IN exploits WHERE e.id IS NOT NULL]) DESC, cvss DESC
LIMIT $limit
`;

/** Everything currently exploitable across the whole graph. */
export const EXPLOITABLE = `
MATCH (sw:Software)-[v:VULNERABLE_TO]->(cve:CVE)-[:HAS_EXPLOIT]->(ex:Exploit)
OPTIONAL MATCH (ip:IP)-[:HAS_PORT]->(:Port)-[:RUNS_SOFTWARE]->(sw)
OPTIONAL MATCH (d:Domain)-[:RESOLVES_TO]->(ip)
WITH cve, sw, collect(DISTINCT ex.source) AS exploit_sources,
     collect(DISTINCT ip.address) AS ips, collect(DISTINCT d.name) AS domains,
     max(v.confidence) AS confidence
RETURN cve.id AS cve, cve.cvss AS cvss, cve.severity AS severity, cve.kev AS kev,
       cve.ransomware AS ransomware, cve.attack_vector AS attack_vector,
       sw.name AS software, sw.version AS version,
       exploit_sources, ips, domains, confidence
ORDER BY cvss DESC
LIMIT $limit
`;

/** Analyst-asserted privilege-escalation / pivot chains. */
export const ATTACK_CHAINS = `
MATCH path = (a:CVE)-[:CHAINS_TO*1..3]->(b:CVE)
RETURN path
LIMIT $limit
`;

/** Graph-wide counters for the header bar. */
export const STATS = `
MATCH (n)
WITH labels(n)[0] AS label, count(*) AS c
WITH collect({label: label, count: c}) AS nodeCounts
MATCH ()-[r]->()
WITH nodeCounts, type(r) AS rel, count(*) AS rc
WITH nodeCounts, collect({type: rel, count: rc}) AS edgeCounts
OPTIONAL MATCH (c:CVE) WHERE (c)<-[:VULNERABLE_TO]-() AND (c)-[:HAS_EXPLOIT]->()
RETURN nodeCounts, edgeCounts, count(DISTINCT c) AS exploitable_cves
`;
