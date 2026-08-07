import neo4j from 'neo4j-driver';

const NODE_COLORS = {
  Domain: '#3b82f6',   // blue
  IP: '#22c55e',       // green
  CVE: '#ef4444',      // red
  Software: '#d946ef', // magenta
  Exploit: '#f97316',  // orange
  Port: '#14b8a6',
  Company: '#a78bfa',
  Email: '#eab308',
  ASN: '#64748b',
  Report: '#94a3b8',
};

const RISK_COLORS = { high: '#ef4444', medium: '#eab308', low: '#22c55e' };

/** Neo4j temporal/int values -> plain JS. */
function plain(value) {
  if (value === null || value === undefined) return null;
  if (neo4j.isInt(value)) return value.toNumber();
  if (Array.isArray(value)) return value.map(plain);
  if (typeof value === 'object') {
    if (typeof value.toString === 'function' && value.year !== undefined) return value.toString();
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = plain(v);
    return out;
  }
  return value;
}

function props(entity) {
  const out = {};
  for (const [k, v] of Object.entries(entity.properties || {})) out[k] = plain(v);
  return out;
}

/** Human-readable label per node type. */
function labelOf(type, p) {
  return p.name || p.address || p.id || p.key || p.number || p.title || type;
}

/** Node size 20..60 driven by confidence (0..1). */
function sizeOf(p) {
  const c = typeof p.confidence === 'number' ? p.confidence : 0.5;
  return Math.round(20 + Math.max(0, Math.min(1, c)) * 40);
}

/**
 * Risk for VULNERABLE_TO / HAS_EXPLOIT edges:
 *   high   = CVE has a public exploit, or CVSS >= 9, or listed in KEV
 *   medium = CVSS >= 7, or link confidence below 0.6 (unconfirmed)
 *   low    = everything else
 */
function riskOf(edgeType, edgeProps, targetNode) {
  if (edgeType === 'HAS_EXPLOIT') return 'high';
  if (edgeType !== 'VULNERABLE_TO' || !targetNode) {
    return (edgeProps.confidence ?? 1) < 0.6 ? 'medium' : 'low';
  }
  const t = targetNode.data;
  if (t.has_exploit || t.kev || (t.cvss ?? 0) >= 9) return 'high';
  if ((t.cvss ?? 0) >= 7 || (edgeProps.confidence ?? 1) < 0.6) return 'medium';
  return 'low';
}

/**
 * Walks arbitrary record values, collecting every node / relationship / path
 * into a deduplicated Cytoscape `{ nodes, edges }` payload.
 */
export function toCytoscape(records) {
  const nodes = new Map();
  const edges = new Map();

  const collect = (value) => {
    if (value === null || value === undefined) return;
    if (Array.isArray(value)) return value.forEach(collect);

    if (value instanceof neo4j.types.Node) {
      const id = value.elementId;
      if (nodes.has(id)) return;
      const p = props(value);
      const type = value.labels[0] || 'Unknown';
      // `...p` must come first: CVE/Exploit nodes carry their own `id`
      // property (the CVE/exploit id string), and spreading it after the
      // structural fields silently overwrote Cytoscape's `id`, leaving
      // edges pointing at an elementId no node was ever registered under.
      nodes.set(id, {
        data: {
          ...p,
          id,
          type,
          labels: value.labels,
          label: String(labelOf(type, p)),
          color: NODE_COLORS[type] || '#94a3b8',
          size: sizeOf(p),
        },
      });
      return;
    }

    if (value instanceof neo4j.types.Relationship) {
      const id = value.elementId;
      if (edges.has(id)) return;
      // Same ordering fix as the node branch above, for relationship
      // properties that happen to collide with a structural field name.
      edges.set(id, {
        _raw: value,
        data: {
          ...props(value),
          id,
          source: value.startNodeElementId,
          target: value.endNodeElementId,
          type: value.type,
          label: value.type,
        },
      });
      return;
    }

    if (value instanceof neo4j.types.Path) {
      collect(value.start);
      collect(value.end);
      value.segments.forEach((s) => {
        collect(s.start);
        collect(s.relationship);
        collect(s.end);
      });
      return;
    }

    if (typeof value === 'object' && !neo4j.isInt(value)) {
      Object.values(value).forEach(collect);
    }
  };

  for (const record of records) record.keys.forEach((k) => collect(record.get(k)));

  // second pass: risk colouring needs both endpoints resolved
  const edgeList = [...edges.values()].map(({ _raw, data }) => {
    const risk = riskOf(data.type, data, nodes.get(data.target));
    return { data: { ...data, risk, color: RISK_COLORS[risk] } };
  });

  return { nodes: [...nodes.values()], edges: edgeList };
}

export { plain };
