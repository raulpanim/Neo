// Read queries backing the list/detail HTTP endpoints. These only ever read
// derived edges/properties (RESOLVES_TO, HAS_VULNERABILITY, CHAINS_TO,
// CVE.exploited) - the claim model in ingest/claims.js is what maintains
// them, this module never writes.

export async function listDomains(session) {
  const result = await session.run(`
    MATCH (d:Domain)
    OPTIONAL MATCH (d)-[:RESOLVES_TO]->(h:Host)
    WITH d, [ip IN collect(DISTINCT h.ip) WHERE ip IS NOT NULL] AS hosts
    RETURN d.name AS name, hosts
    ORDER BY d.name
  `);
  return result.records.map((r) => ({ name: r.get('name'), hosts: r.get('hosts') }));
}

export async function getDomain(session, name) {
  const result = await session.run(
    `
    MATCH (d:Domain {name: $name})
    OPTIONAL MATCH (d)-[:RESOLVES_TO]->(h:Host)
    WITH d, [ip IN collect(DISTINCT h.ip) WHERE ip IS NOT NULL] AS hosts
    RETURN d.name AS name, hosts
    `,
    { name }
  );
  if (result.records.length === 0) return null;
  const r = result.records[0];
  return { name: r.get('name'), hosts: r.get('hosts') };
}

export async function listHosts(session) {
  const result = await session.run(`
    MATCH (h:Host)
    OPTIONAL MATCH (h)-[:HAS_VULNERABILITY]->(c:CVE)
    RETURN h.ip AS ip, h.hostname AS hostname, count(DISTINCT c) AS vulnerabilityCount
    ORDER BY h.ip
  `);
  return result.records.map((r) => ({
    ip: r.get('ip'),
    hostname: r.get('hostname'),
    vulnerabilityCount: r.get('vulnerabilityCount'),
  }));
}

export async function getHostElementId(session, ip) {
  const result = await session.run(`MATCH (h:Host {ip: $ip}) RETURN elementId(h) AS id`, { ip });
  if (result.records.length === 0) return null;
  return result.records[0].get('id');
}

export async function getHost(session, ip) {
  const result = await session.run(
    `
    MATCH (h:Host {ip: $ip})
    OPTIONAL MATCH (h)-[r:HAS_VULNERABILITY]->(c:CVE)
    WITH h, collect(CASE WHEN c IS NULL THEN null
      ELSE {id: c.id, cvss: c.cvss, kev: c.kev, exploited: c.exploited, confidence: r.confidence} END) AS raw
    RETURN h.ip AS ip, h.hostname AS hostname, [x IN raw WHERE x IS NOT NULL] AS vulnerabilities
    `,
    { ip }
  );
  if (result.records.length === 0) return null;
  const r = result.records[0];
  return { ip: r.get('ip'), hostname: r.get('hostname'), vulnerabilities: r.get('vulnerabilities') };
}

export async function listCves(session) {
  const result = await session.run(`
    MATCH (c:CVE)
    RETURN c.id AS id, c.description AS description, c.cvss AS cvss, c.kev AS kev, c.exploited AS exploited
    ORDER BY c.cvss DESC
  `);
  return result.records.map((r) => ({
    id: r.get('id'),
    description: r.get('description'),
    cvss: r.get('cvss'),
    kev: r.get('kev'),
    exploited: r.get('exploited') ?? null,
  }));
}

export async function getCve(session, id) {
  const result = await session.run(
    `
    MATCH (c:CVE {id: $id})
    OPTIONAL MATCH (h:Host)-[:HAS_VULNERABILITY]->(c)
    OPTIONAL MATCH (c)-[:CHAINS_TO]->(next:CVE)
    OPTIONAL MATCH (prev:CVE)-[:CHAINS_TO]->(c)
    WITH c,
         [ip IN collect(DISTINCT h.ip) WHERE ip IS NOT NULL] AS affectedHosts,
         [x IN collect(DISTINCT next.id) WHERE x IS NOT NULL] AS chainsTo,
         [x IN collect(DISTINCT prev.id) WHERE x IS NOT NULL] AS chainsFrom
    RETURN c.id AS id, c.description AS description, c.cvss AS cvss, c.kev AS kev, c.exploited AS exploited,
           affectedHosts, chainsTo, chainsFrom
    `,
    { id }
  );
  if (result.records.length === 0) return null;
  const r = result.records[0];
  return {
    id: r.get('id'),
    description: r.get('description'),
    cvss: r.get('cvss'),
    kev: r.get('kev'),
    exploited: r.get('exploited') ?? null,
    affectedHosts: r.get('affectedHosts'),
    chainsTo: r.get('chainsTo'),
    chainsFrom: r.get('chainsFrom'),
  };
}

/**
 * CVEs reachable from a domain's resolved hosts, KEV/actively-exploited
 * ones ranked first, then by CVSS descending within each group.
 */
export async function rankedVulnerabilitiesForDomain(session, domainName) {
  const result = await session.run(
    `
    MATCH (d:Domain {name: $domainName})-[:RESOLVES_TO]->(h:Host)-[r:HAS_VULNERABILITY]->(c:CVE)
    RETURN DISTINCT c.id AS id, c.description AS description, c.cvss AS cvss, c.kev AS kev,
           c.exploited AS exploited, h.ip AS hostIp, r.confidence AS confidence
    ORDER BY (CASE WHEN c.kev = true OR c.exploited = true THEN 0 ELSE 1 END), c.cvss DESC
    `,
    { domainName }
  );
  return result.records.map((r) => ({
    id: r.get('id'),
    description: r.get('description'),
    cvss: r.get('cvss'),
    kev: r.get('kev'),
    exploited: r.get('exploited') ?? null,
    hostIp: r.get('hostIp'),
    confidence: r.get('confidence'),
  }));
}

/**
 * Full node/edge set for the cytoscape graph view.
 */
export async function getGraph(session) {
  const nodesResult = await session.run(`
    MATCH (n)
    WHERE n:Domain OR n:Host OR n:CVE
    RETURN elementId(n) AS id, labels(n)[0] AS label, properties(n) AS properties
  `);
  const edgesResult = await session.run(`
    MATCH (a)-[r]->(b)
    WHERE type(r) IN ['RESOLVES_TO', 'HAS_VULNERABILITY', 'CHAINS_TO']
    RETURN elementId(r) AS id, elementId(a) AS source, elementId(b) AS target,
           type(r) AS type, properties(r) AS properties
  `);
  return {
    nodes: nodesResult.records.map((r) => ({
      id: r.get('id'),
      label: r.get('label'),
      properties: r.get('properties'),
    })),
    edges: edgesResult.records.map((r) => ({
      id: r.get('id'),
      source: r.get('source'),
      target: r.get('target'),
      type: r.get('type'),
      properties: r.get('properties'),
    })),
  };
}
