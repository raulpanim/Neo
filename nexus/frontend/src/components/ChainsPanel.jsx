import { useEffect, useState } from 'react';
import { api } from '../api.js';

const PRIV_TONE = { high: 'text-alert', low: 'text-warn', none: 'text-green-dim' };

/**
 * Chains read top-to-bottom as a ladder, because the order is the content:
 * step 2 only matters given step 1. A table would flatten exactly that.
 */
export default function ChainsPanel({ onFocusCve, onMessage }) {
  const [state, setState] = useState({ loading: true, data: null, error: null });
  const [saving, setSaving] = useState(false);

  const load = () =>
    api.detectChains(3).then((res) =>
      setState({ loading: false, data: res.ok ? res.data : null, error: res.ok ? null : res.error }),
    );

  useEffect(() => {
    load();
  }, []);

  const persist = async () => {
    setSaving(true);
    const res = await api.persistChains(3);
    onMessage?.(res.ok ? `wrote ${res.data.written.length} chain edges as inferences` : `! ${res.error}`);
    setSaving(false);
  };

  if (state.loading) return <p className="px-3 py-4 text-tiny text-green-dim">Composing paths…</p>;
  if (state.error) return <p className="px-3 py-4 text-tiny text-alert">{state.error}</p>;

  const { chains, note } = state.data;

  return (
    <div>
      <div className="flex items-center gap-3 border-b border-rule px-3 py-2">
        <button className="btn" onClick={load}>
          recompute
        </button>
        <button className="btn" onClick={persist} disabled={saving || !chains.length}>
          write to graph
        </button>
        <p className="text-micro leading-snug text-green-ghost">{note}</p>
      </div>

      {!chains.length ? null : (
        <ul className="divide-y divide-rule/60">
          {chains.map((chain, i) => (
            <li key={i} className="px-3 py-2">
              <div className="flex items-center gap-2 pb-1.5">
                <span
                  className={`border px-1.5 text-micro tabular-nums ${
                    chain.score >= 70 ? 'border-alert/40 text-alert' : 'border-warn/40 text-warn'
                  }`}
                >
                  {chain.score}
                </span>
                <span className="text-tiny text-green">{chain.host}</span>
                {chain.domains.length > 0 && (
                  <span className="text-micro text-green-ghost">{chain.domains.join(', ')}</span>
                )}
                <span className="ml-auto text-micro text-green-ghost">
                  {chain.length} steps
                  {chain.starts_unauthenticated && ' · unauthenticated start'}
                  {chain.reaches_privileged && ' · reaches privileged'}
                </span>
              </div>

              <ol className="space-y-1">
                {chain.steps.map((step) => (
                  <li key={step.position} className="grid grid-cols-[16px_1fr] gap-2">
                    <span aria-hidden className="pt-[3px] text-micro text-green-ghost">
                      {step.position === chain.steps.length ? '└' : '├'}
                    </span>
                    <div>
                      <p className="text-tiny">
                        <button
                          onClick={() => onFocusCve?.(step.cve)}
                          className="text-green underline decoration-green-ghost underline-offset-2 hover:decoration-green"
                        >
                          {step.cve}
                        </button>{' '}
                        <span className="text-green-dim">
                          {step.software} {step.version}
                          {step.port ? `:${step.port}` : ''}
                        </span>
                        {step.kev && <span className="pl-1 text-micro text-alert">KEV</span>}
                        <span className={`pl-2 text-micro ${PRIV_TONE[step.privilege_after]}`}>
                          → {step.privilege_after}
                        </span>
                      </p>
                      <p className="text-micro text-green-ghost">{step.rationale}</p>
                    </div>
                  </li>
                ))}
              </ol>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
