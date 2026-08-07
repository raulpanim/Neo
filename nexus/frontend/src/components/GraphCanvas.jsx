import { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
import { stylesheet, layouts } from '../cytoscape/style.js';

/**
 * Owns the Cytoscape instance. React never re-renders the graph — it hands
 * down elements and the instance reconciles them, which keeps pan/zoom stable.
 */
export default function GraphCanvas({ elements, layout, hiddenTypes, onSelect, onCyReady }) {
  const hostRef = useRef(null);
  const cyRef = useRef(null);

  // --- init once ---------------------------------------------------
  useEffect(() => {
    const cy = cytoscape({
      container: hostRef.current,
      style: stylesheet,
      minZoom: 0.15,
      maxZoom: 3,
      wheelSensitivity: 0.25,
      boxSelectionEnabled: false,
    });
    cyRef.current = cy;

    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      cy.elements().removeClass('trace dim');
      cy.elements().difference(node.closedNeighborhood()).addClass('dim');
      node.closedNeighborhood().addClass('trace');
      onSelect?.(node.data());
    });

    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        cy.elements().removeClass('trace dim');
        onSelect?.(null);
      }
    });

    onCyReady?.(cy);
    return () => cy.destroy();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // --- swap elements ------------------------------------------------
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const next = [...(elements?.nodes ?? []), ...(elements?.edges ?? [])];

    cy.batch(() => {
      cy.elements().remove();
      if (next.length) cy.add(next);
    });

    if (next.length) {
      cy.layout(layouts[layout] ?? layouts.force).run();
      cy.fit(undefined, 48);
    }
  }, [elements, layout]);

  // --- type filters --------------------------------------------------
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.nodes().forEach((n) => n.toggleClass('hidden', hiddenTypes.includes(n.data('type'))));
    });
  }, [hiddenTypes, elements]);

  return (
    <div className="crt relative h-full w-full overflow-hidden">
      <div ref={hostRef} className="h-full w-full" />
      {/* slow phosphor sweep — the only ambient motion on the page */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="h-24 w-full animate-sweep bg-gradient-to-b from-transparent via-green/[0.035] to-transparent" />
      </div>
    </div>
  );
}
