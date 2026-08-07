import neo4j from 'neo4j-driver';

const URI = process.env.NEO4J_URI || 'bolt://localhost:7687';
const USER = process.env.NEO4J_USER || 'neo4j';
const PASS = process.env.NEO4J_PASSWORD || 'nexus_dev_pass';

export const driver = neo4j.driver(URI, neo4j.auth.basic(USER, PASS), {
  maxConnectionPoolSize: 50,
  connectionAcquisitionTimeout: 10_000,
  disableLosslessIntegers: true,
});

// The driver sends a plain JS number as a Cypher Float, but LIMIT (and any
// other integer-typed parameter) requires an actual Integer - Neo4j rejects
// "LIMIT $limit" with 100.0. Routes pass `limit` as a plain number because
// they also do JS-side math/slicing with it, so the coercion belongs here,
// at the one place every query actually talks to the driver.
function coerceIntParams(params) {
  if (typeof params.limit !== 'number') return params;
  return { ...params, limit: neo4j.int(params.limit) };
}

/** Read-only query. Always closes the session, never throws raw driver noise. */
export async function read(cypher, params = {}) {
  const session = driver.session({ defaultAccessMode: neo4j.session.READ });
  try {
    const { records } = await session.run(cypher, coerceIntParams(params));
    return records;
  } finally {
    await session.close();
  }
}

/** Write query. */
export async function write(cypher, params = {}) {
  const session = driver.session({ defaultAccessMode: neo4j.session.WRITE });
  try {
    const { records } = await session.run(cypher, coerceIntParams(params));
    return records;
  } finally {
    await session.close();
  }
}

export async function healthcheck() {
  try {
    await driver.verifyConnectivity();
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

export async function shutdown() {
  await driver.close();
}
