// Exploit-chain analysis over the derived CHAINS_TO edges between CVEs
// (materialized from CHAINS_TO claims - see claims.js). A "chain" here is a
// maximal path: it starts at a CVE nothing else chains into and ends at a
// CVE that chains into nothing else, so multi-hop chains aren't reported
// redundantly as every one of their own sub-paths too.

/**
 * All maximal CVE -> CVE exploit chains in the graph.
 */
export async function getVulnerabilityChains(session) {
  const result = await session.run(`
    MATCH p = (root:CVE)-[:CHAINS_TO*1..6]->(leaf:CVE)
    WHERE NOT ()-[:CHAINS_TO]->(root) AND NOT (leaf)-[:CHAINS_TO]->()
    WITH p, [n IN nodes(p) | n.id] AS cveIds,
         [rel IN relationships(p) | {confidence: rel.confidence, sources: rel.sources}] AS hops
    RETURN cveIds, hops
    ORDER BY size(cveIds) DESC
  `);
  return result.records.map((record) => ({
    cves: record.get('cveIds'),
    hops: record.get('hops'),
  }));
}

/**
 * CVES_BY_HOST: for a given host (identified by the elementId the frontend
 * got when it fetched /api/graph and the user clicked the node), find every
 * CVE it's vulnerable to and, for each, the maximal chain reachable from it
 * (just itself if it doesn't chain anywhere).
 */
export async function getChainsForHost(session, hostElementId) {
  const result = await session.run(
    `
    MATCH (h) WHERE elementId(h) = $hostElementId
    MATCH (h)-[:HAS_VULNERABILITY]->(root:CVE)
    CALL (root) {
      OPTIONAL MATCH p = (root)-[:CHAINS_TO*0..6]->(leaf:CVE)
      WHERE NOT (leaf)-[:CHAINS_TO]->()
      RETURN collect(DISTINCT [n IN nodes(p) | n.id]) AS chains
    }
    RETURN root.id AS rootCve, chains
    ORDER BY rootCve
    `,
    { hostElementId }
  );
  return result.records.map((record) => ({
    rootCve: record.get('rootCve'),
    chains: record.get('chains'),
  }));
}
