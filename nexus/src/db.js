import neo4j from 'neo4j-driver';

const URI = process.env.NEO4J_URI || 'bolt://localhost:7687';
const USER = process.env.NEO4J_USER || 'neo4j';
const PASSWORD = process.env.NEO4J_PASSWORD || 'nexuspassword';

// disableLosslessIntegers: our counts/scores are all well within safe JS
// integer range, so return plain numbers instead of neo4j Integer wrapper
// objects - avoids a whole class of ".low/.high leaked into JSON" bugs.
export const driver = neo4j.driver(URI, neo4j.auth.basic(USER, PASSWORD), {
  disableLosslessIntegers: true,
});

export function getSession() {
  return driver.session();
}

export async function closeDriver() {
  await driver.close();
}
