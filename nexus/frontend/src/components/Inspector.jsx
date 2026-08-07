import { useEffect, useState } from 'react';
import { api } from '../api.js';

const HIDE = new Set(['id', 'label', 'color', 'size', 'labels', 'type', 'source', 'target', 'risk']);

const RISK_TONE = {
  high: 'text-alert border-alert/40',
  medium: 'text-warn border-warn/40',
  low: 'text-ip border-ip/40',
};

/** Walks the graph back to the nearest domain so a CVE always has provenance. */
function tracePath(cy, id) {
  if (!cy) return [];
  const node = cy.getElementById(id);
  if (!node?.length) return [];
  if (node.data('type') === 'Domain') return [node.data()];
  const { found, path } = cy.elements().bfs({
    roots: node,
    goal: 'node[type = "Domain"]',
    directed: false,
  });
  if (!found) return [];
  return path.nodes().map((n) => n.data()).reverse();
}

/** Observation history for the selected entity, newest first. */
function Timeline({ id }) {
  const [state, setState] = useState({ loading: true, events: [], error: null });

  useEffect(() => {
    let live = true;
    setState({ loading: true, events: [], error: null });
    api.timeline(id).then((res) => {
      if (!live) return;
      setState({
        loading: false,
        events: res.ok ? res.data.events ?? [] : [],
        error: res.ok ? null : res.error,
      });
    });
    return () => { live = false; };
  }, [id]);

  if (state.loading) return <p className="text-tiny text-green-dim">Loading history…</p>;
  if (state.error) return <p className="text-tiny text-alert">{state.error}</p>;
  if (!state.events.length) {
    return (
      <p className="text-tiny leading-relaxed text-green-dim">
        No recorded observations. Run the backfill to convert existing edges into claims.
      </p>
    );
  }

  return (
    <ol className="space-y-2">
      {state.events.map((e, i) => (
        <li key={i} className="grid grid-cols-[52px_1fr] gap-2">
          <span className="text-micro tabular-nums text-green-ghost">
            {(e.observed_at ?? '').slice(0, 10)}
          </span>
          <div>
            <p className="text-tiny">
              <span className={e.retracted ? 'text-green-ghost line-through' : 'text-green-dim'}>
                {e.direction === 'outgoing' ? e.predicate : `${e.predicate} ←`}
              </span>{' '}
              <span className={e.retracted ? 'text-green-ghost line-through' : 'text-green'}>
                {e.direction === 'outgoing' ? e.object : e.subject}
              </span>
            </p>
            <p className="text-micro text-green-ghost">
              {e.source_label} · grade {e.grade}
              {e.observations > 1 && ` · seen ${e.observations}×`}
              {e.stale && <span className="text-warn"> · stale by {e.age_days - 0}d</span>}
              {e.retracted && <span className="text-alert"> · withdrawn</span>}
            </p>
          </div>
        </li>
      ))}
    </ol>
  );
}

export default function Inspector({ node, cy, onExpand, busy }) {
  if (!node) {
    return (
      <section className="flex w-80 shrink-0 flex-col border-l border-rule bg-panel">
        <Header title="inspector" />
        <div className="flex flex-1 items-center px-4">
          <p className="text-tiny leading-relaxed text-green-dim">
            Select a node to read its record, trace it back to a domain you own, and expand its
            neighbours.
          </p>
        </div>
      </section>
    );
  }

  const path = tracePath(cy, node.id);
  const isCve = node.type === 'CVE';
  const entries = Object.entries(node).filter(([k, v]) => !HIDE.has(k) && v !== null && v !== '');

  return (
    <section className="flex w-80 shrink-0 animate-boot flex-col border-l border-rule bg-panel">
      <Header title="inspector" />

      <div className="flex-1 overflow-y-auto">
        {/* identity */}
        <div className="border-b border-rule p-3">
          <p className="eyebrow">{node.type}</p>
          <h2 className="break-all pt-1 text-[15px] font-medium tracking-tight text-green">
            {node.label}
          </h2>

          {node.warning && (
            <p className="mt-2 border border-warn/40 bg-warn/5 px-2 py-1 text-micro leading-relaxed text-warn">
              {node.warning}
            </p>
          )}

          {isCve && (
            <div className="mt-2.5 flex items-center gap-2">
              <span
                className={`border px-1.5 py-0.5 text-micro uppercase ${
                  RISK_TONE[node.cvss >= 9 ? 'high' : node.cvss >= 7 ? 'medium' : 'low']
                }`}
              >
                cvss {node.cvss}
              </span>
              {node.kev && (
                <span className="border border-alert/40 bg-alert/10 px-1.5 py-0.5 text-micro uppercase text-alert">
                  exploited in the wild
                </span>
              )}
            </div>
          )}
        </div>

        {/* signature element: the provenance line */}
        {path.length > 1 && (
          <div className="border-b border-rule p-3">
            <p className="eyebrow pb-2">reached from</p>
            <ol className="space-y-1">
              {path.map((step, i) => (
                <li key={step.id} className="flex items-start gap-2 text-tiny">
                  <span
                    aria-hidden
                    className="mt-[3px] shrink-0 text-[9px]"
                    style={{ color: step.color }}
                  >
                    {i === 0 ? '┌' : i === path.length - 1 ? '└' : '├'}
                  </span>
                  <span className={i === path.length - 1 ? 'text-green' : 'text-green-dim'}>
                    {step.label}
                  </span>
                  <span className="ml-auto text-micro text-green-ghost">{step.type}</span>
                </li>
              ))}
            </ol>
          </div>
        )}

        {/* who says so */}
        {(node.sources?.length > 0 || node.best_source) && (
          <div className="border-b border-rule p-3">
            <p className="eyebrow pb-2">provenance</p>
            <p className="text-tiny text-green-dim">
              {(node.sources ?? []).join(', ')}
              {typeof node.confidence === 'number' && (
                <span className="text-green-ghost"> · combined {node.confidence.toFixed(2)}</span>
              )}
            </p>
          </div>
        )}

        {/* observation history */}
        <div className="border-b border-rule p-3">
          <p className="eyebrow pb-2">history</p>
          <Timeline id={node.id} />
        </div>

        {/* raw record */}
        <div className="border-b border-rule p-3">
          <p className="eyebrow pb-2">record</p>
          <dl className="space-y-1.5">
            {entries.map(([k, v]) => (
              <div key={k} className="grid grid-cols-[88px_1fr] gap-2">
                <dt className="text-micro uppercase text-green-ghost">{k.replace(/_/g, ' ')}</dt>
                <dd className="break-words text-tiny text-green-dim">
                  {Array.isArray(v) ? v.join(', ') : String(v)}
                </dd>
              </div>
            ))}
          </dl>
        </div>
      </div>

      <div className="flex gap-1 border-t border-rule p-3">
        <button className="btn flex-1" disabled={busy} onClick={() => onExpand(node.id, 1)}>
          expand 1
        </button>
        <button className="btn flex-1" disabled={busy} onClick={() => onExpand(node.id, 2)}>
          expand 2
        </button>
      </div>
    </section>
  );
}

function Header({ title }) {
  return (
    <div className="flex items-center justify-between border-b border-rule px-3 py-2">
      <span className="eyebrow">{title}</span>
    </div>
  );
}
