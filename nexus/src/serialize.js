// Recursively converts neo4j-driver value types (temporal types, Node/
// Relationship wrappers) into plain JSON-safe values. Applied once at the
// HTTP boundary so query modules can return raw driver values.
import neo4j from 'neo4j-driver';

export function toJSONSafe(value) {
  if (value === null || value === undefined) return value;
  if (neo4j.isInt(value)) return value.toNumber();
  if (
    neo4j.isDate(value) ||
    neo4j.isDateTime(value) ||
    neo4j.isLocalDateTime(value) ||
    neo4j.isTime(value) ||
    neo4j.isLocalTime(value) ||
    neo4j.isDuration(value)
  ) {
    return value.toString();
  }
  if (Array.isArray(value)) return value.map(toJSONSafe);
  if (value instanceof neo4j.types.Node) {
    return { elementId: value.elementId, label: value.labels[0], properties: toJSONSafe(value.properties) };
  }
  if (value instanceof neo4j.types.Relationship) {
    return { elementId: value.elementId, type: value.type, properties: toJSONSafe(value.properties) };
  }
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = toJSONSafe(v);
    return out;
  }
  return value;
}
