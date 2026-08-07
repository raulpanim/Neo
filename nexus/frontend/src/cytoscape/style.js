// Visual language for the graph itself. Node colour/size and edge risk colour
// arrive precomputed from the API (src/serialize.js) — this file only decides
// how those values are drawn.

export const stylesheet = [
  {
    selector: 'node',
    style: {
      'background-color': 'data(color)',
      'background-opacity': 0.14,
      'border-width': 1.5,
      'border-color': 'data(color)',
      width: 'data(size)',
      height: 'data(size)',
      shape: 'round-rectangle',
      label: 'data(label)',
      color: '#b7ccc4',
      'font-family': 'JetBrains Mono, monospace',
      'font-size': 9,
      'font-weight': 400,
      'text-valign': 'bottom',
      'text-margin-y': 5,
      'text-max-width': 120,
      'text-wrap': 'ellipsis',
      'text-background-color': '#070b0a',
      'text-background-opacity': 0.85,
      'text-background-padding': 2,
      'transition-property': 'border-width, background-opacity',
      'transition-duration': '120ms',
    },
  },

  // entity shapes carry type at a glance, so colour isn't the only channel
  { selector: 'node[type = "Domain"]', style: { shape: 'round-rectangle' } },
  { selector: 'node[type = "IP"]', style: { shape: 'rectangle' } },
  { selector: 'node[type = "Port"]', style: { shape: 'round-tag' } },
  { selector: 'node[type = "Software"]', style: { shape: 'round-diamond' } },
  { selector: 'node[type = "CVE"]', style: { shape: 'octagon' } },
  { selector: 'node[type = "Exploit"]', style: { shape: 'star' } },
  { selector: 'node[type = "Company"]', style: { shape: 'round-hexagon' } },
  { selector: 'node[type = "Email"]', style: { shape: 'ellipse' } },
  { selector: 'node[type = "ASN"]', style: { shape: 'barrel' } },

  // known-exploited vulnerabilities burn hotter than the rest
  {
    selector: 'node[type = "CVE"][?kev]',
    style: { 'border-width': 3, 'background-opacity': 0.3 },
  },
  // unproven ownership: dashed outline, per the legal guard-rail
  {
    selector: 'node[type = "Domain"][!owned]',
    style: { 'border-style': 'dashed', 'border-opacity': 0.7 },
  },

  {
    selector: 'edge',
    style: {
      width: 1,
      'line-color': 'data(color)',
      'line-opacity': 0.55,
      'curve-style': 'bezier',
      'target-arrow-color': 'data(color)',
      'target-arrow-shape': 'triangle',
      'arrow-scale': 0.7,
      label: 'data(label)',
      color: '#3f5c52',
      'font-family': 'JetBrains Mono, monospace',
      'font-size': 7,
      'text-rotation': 'autorotate',
      'text-background-color': '#070b0a',
      'text-background-opacity': 0.9,
      'text-background-padding': 1,
    },
  },
  { selector: 'edge[risk = "high"]', style: { width: 2.2, 'line-opacity': 0.95 } },
  { selector: 'edge[risk = "medium"]', style: { width: 1.4, 'line-style': 'dashed' } },
  { selector: 'edge[type = "CHAINS_TO"]', style: { 'line-style': 'dotted', width: 2, 'line-opacity': 0.9 } },

  // interaction states
  {
    selector: 'node:selected',
    style: { 'border-width': 3, 'background-opacity': 0.4, 'z-index': 20 },
  },
  { selector: '.dim', style: { opacity: 0.12 } },
  { selector: '.trace', style: { 'line-opacity': 1, width: 3, 'z-index': 30 } },
  { selector: 'node.trace', style: { 'background-opacity': 0.45, 'border-width': 3 } },
  { selector: '.hidden', style: { display: 'none' } },
];

export const layouts = {
  // organic — good for "what is connected to what"
  force: {
    name: 'cose',
    animate: true,
    animationDuration: 420,
    nodeRepulsion: 9000,
    idealEdgeLength: 95,
    nodeDimensionsIncludeLabels: true,
    padding: 40,
    randomize: false,
  },
  // hierarchical — reads the attack surface top-down: domain → ip → port → sw → cve
  chain: {
    name: 'breadthfirst',
    directed: true,
    animate: true,
    animationDuration: 420,
    spacingFactor: 1.35,
    nodeDimensionsIncludeLabels: true,
    padding: 40,
  },
  // rings by degree — hubs pop to the centre
  radial: {
    name: 'concentric',
    animate: true,
    animationDuration: 420,
    concentric: (n) => n.degree(),
    levelWidth: () => 1,
    minNodeSpacing: 26,
    padding: 40,
  },
};

export const layoutOrder = ['force', 'chain', 'radial'];
