import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from './api.js';
import GraphCanvas from './components/GraphCanvas.jsx';
import CommandRail from './components/CommandRail.jsx';
import Inspector from './components/Inspector.jsx';
import FindingsPanel from './components/FindingsPanel.jsx';
import StatusBar from './components/StatusBar.jsx';
import { layoutOrder } from './cytoscape/style.js';

const EMPTY = { nodes: [], edges: [] };

export default function App() {
  const [elements, setElements] = useState(EMPTY);
  const [truncated, setTruncated] = useState(false);
  const [selected, setSelected] = useState(null);
  const [layout, setLayout] = useState('force');
  const [hiddenTypes, setHiddenTypes] = useState([]);
  const [findings, setFindings] = useState({ items: [], summary: null, title: 'nothing loaded' });
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerTab, setDrawerTab] = useState('findings');
  const [health, setHealth] = useState('unknown');
  const [stats, setStats] = useState(null);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const cyRef = useRef(null);

  const say = (text) => setMessage(text);
  const fail = (text) => setMessage(`! ${text}`);

  // --- boot -------------------------------------------------------
  useEffect(() => {
    (async () => {
      const h = await api.health();
      setHealth(h.ok ? 'ok' : 'down');
      if (!h.ok) return fail(h.error);
      const s = await api.stats();
      if (s.ok) setStats(s.data);
      run({ kind: 'surface', arg: 'example.com' });
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const load = (payload, note, nextLayout) => {
    setElements(payload.elements ?? EMPTY);
    setTruncated(Boolean(payload.truncated));
    setSelected(null);
    if (nextLayout) setLayout(nextLayout);
    say(note);
  };

  // --- command dispatch --------------------------------------------
  const run = useCallback(async (cmd) => {
    setBusy(true);
    try {
      if (cmd.kind === 'search') {
        const res = await api.search(cmd.arg);
        if (!res.ok) return fail(res.error);
        if (!res.data.count) return say(`no match for "${cmd.arg}"`);
        load(res.data, `${res.data.count} match${res.data.count === 1 ? '' : 'es'}`, 'force');
      }

      if (cmd.kind === 'surface') {
        const [graph, vulns] = await Promise.all([
          api.attackSurface(cmd.arg),
          api.vulnsForDomain(cmd.arg),
        ]);
        if (!graph.ok) return fail(graph.error);
        load(graph.data, `surface of ${cmd.arg}`, 'chain');
        if (vulns.ok) {
          setFindings({
            items: vulns.data.findings,
            summary: vulns.data.summary,
            title: cmd.arg,
          });
          setDrawerOpen(vulns.data.findings.length > 0);
        }
      }

      if (cmd.kind === 'exploitable') {
        const res = await api.exploitable();
        if (!res.ok) return fail(res.error);
        setFindings({ items: res.data.items, summary: null, title: 'everything exploitable' });
        setDrawerOpen(true);
        say(`${res.data.count} exploitable finding${res.data.count === 1 ? '' : 's'}`);
      }

      if (cmd.kind === 'chains') {
        setDrawerTab('chains');
        setDrawerOpen(true);
        const res = await api.chains();
        if (res.ok && res.data.elements.nodes.length) {
          load(res.data, 'recorded chains', 'chain');
        } else {
          say('no chains recorded yet — see the chains tab for inferred paths');
        }
      }

      if (cmd.kind === 'expand') {
        const res = await api.expand(cmd.arg, cmd.depth);
        if (!res.ok) return fail(res.error);
        load(res.data, `expanded depth ${res.data.depth}`, 'force');
        if (res.data.truncated) say('expanded — result capped at 100 nodes');
      }
    } finally {
      setBusy(false);
    }
  }, []);

  // --- keyboard ------------------------------------------------------
  useEffect(() => {
    const onKey = (e) => {
      if (e.target.tagName === 'INPUT') {
        if (e.key === 'Escape') e.target.blur();
        return;
      }
      if (e.key === 'Escape') {
        setSelected(null);
        cyRef.current?.elements().removeClass('trace dim');
      }
      const idx = Number(e.key) - 1;
      if (idx >= 0 && idx < layoutOrder.length) setLayout(layoutOrder[idx]);
      if (e.key === 'f') setDrawerOpen((v) => !v);
      if (e.key === 'a') { setDrawerTab('chains'); setDrawerOpen(true); }
      if (e.key === 'c') { setDrawerTab('conflicts'); setDrawerOpen(true); }
      if (e.key === 's') { setDrawerTab('collectors'); setDrawerOpen(true); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  /** Centres an element id that a conflict points at, pulling it in if absent. */
  const focusNode = (elementId) => {
    const cy = cyRef.current;
    if (!cy) return;
    const node = cy.getElementById(elementId);
    if (!node?.length) return run({ kind: 'expand', arg: elementId, depth: 1 });
    cy.animate({ center: { eles: node }, zoom: 1.3 }, { duration: 240 });
    node.emit('tap');
  };

  const focusCve = (cveId) => {
    const cy = cyRef.current;
    if (!cy) return;
    const node = cy.nodes().filter((n) => n.data('id') === cveId || n.data('label') === cveId);
    if (!node.length) return say(`${cveId} is not on the canvas — expand its software first`);
    cy.animate({ center: { eles: node }, zoom: 1.4 }, { duration: 240 });
    node.emit('tap');
  };

  return (
    <div className="flex h-full flex-col">
      <StatusBar
        health={health}
        stats={stats}
        counts={{ nodes: elements.nodes.length, edges: elements.edges.length, truncated }}
        layout={layout}
        onLayout={setLayout}
        message={message}
        busy={busy}
      />

      <div className="flex min-h-0 flex-1">
        <CommandRail
          onCommand={run}
          busy={busy}
          hiddenTypes={hiddenTypes}
          onToggleType={(t) =>
            setHiddenTypes((prev) => (prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t]))
          }
        />

        <main className="flex min-w-0 flex-1 flex-col">
          <div className="min-h-0 flex-1">
            <GraphCanvas
              elements={elements}
              layout={layout}
              hiddenTypes={hiddenTypes}
              onSelect={setSelected}
              onCyReady={(cy) => (cyRef.current = cy)}
            />
          </div>

          <FindingsPanel
            findings={findings.items}
            summary={findings.summary}
            title={findings.title}
            open={drawerOpen}
            onToggle={() => setDrawerOpen((v) => !v)}
            onFocus={focusCve}
            onFocusNode={focusNode}
            onMessage={say}
            tab={drawerTab}
            onTab={setDrawerTab}
          />
        </main>

        <Inspector
          node={selected}
          cy={cyRef.current}
          busy={busy}
          onExpand={(id, depth) => run({ kind: 'expand', arg: id, depth })}
        />
      </div>
    </div>
  );
}
