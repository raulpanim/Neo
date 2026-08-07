import { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import { api } from './api';

const COLORS = { Domain: '#3b82f6', Host: '#f59e0b', CVE: '#ef4444' };

function nodeLabel(n) {
  if (n.label === 'Domain') return n.properties.name;
  if (n.label === 'Host') return n.properties.ip;
  if (n.label === 'CVE') return n.properties.id;
  return n.id;
}

export default function GraphView() {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    api
      .getGraph()
      .then((graph) => {
        if (cancelled || !containerRef.current) return;
        const elements = [
          ...graph.nodes.map((n) => ({
            data: {
              id: n.id,
              label: nodeLabel(n),
              type: n.label,
              kev: !!n.properties.kev,
              exploited: !!n.properties.exploited,
            },
          })),
          ...graph.edges.map((e) => ({
            data: { id: e.id, source: e.source, target: e.target, label: e.type, type: e.type },
          })),
        ];

        cyRef.current = cytoscape({
          container: containerRef.current,
          elements,
          style: [
            {
              selector: 'node',
              style: {
                'background-color': (ele) => COLORS[ele.data('type')] || '#6b7280',
                'border-width': (ele) => (ele.data('kev') || ele.data('exploited') ? 3 : 0),
                'border-color': '#dc2626',
                label: 'data(label)',
                color: '#e5e7eb',
                'font-size': 10,
                'text-valign': 'bottom',
                'text-margin-y': 6,
                width: 28,
                height: 28,
              },
            },
            {
              selector: 'edge',
              style: {
                width: 2,
                'line-color': '#4b5563',
                'target-arrow-color': '#4b5563',
                'target-arrow-shape': 'triangle',
                'curve-style': 'bezier',
                label: 'data(label)',
                'font-size': 8,
                color: '#9ca3af',
                'text-rotation': 'autorotate',
              },
            },
            {
              selector: 'edge[type = "CHAINS_TO"]',
              style: { 'line-color': '#dc2626', 'target-arrow-color': '#dc2626', width: 3 },
            },
          ],
          layout: { name: 'cose', animate: false },
        });
        setLoading(false);
      })
      .catch((err) => {
        if (!cancelled) setError(err.message);
      });

    return () => {
      cancelled = true;
      cyRef.current?.destroy();
    };
  }, []);

  return (
    <div className="relative h-full w-full">
      {loading && !error && (
        <div className="absolute inset-0 flex items-center justify-center text-gray-400">Loading graph…</div>
      )}
      {error && (
        <div className="absolute inset-0 flex items-center justify-center text-red-400">
          Failed to load graph: {error}
        </div>
      )}
      <div ref={containerRef} className="h-full w-full" />
    </div>
  );
}
