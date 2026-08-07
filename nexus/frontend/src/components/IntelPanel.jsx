import { useEffect, useState } from 'react';
import { api } from '../api.js';

const SEV = { high: 'text-alert border-alert/40', medium: 'text-warn border-warn/40', low: 'text-green-dim border-rule' };

const KIND_COPY = {
  cardinality: 'mutually exclusive',
  weak_support: 'thin evidence',
  stale: 'past its shelf life',
  retraction: 'withdrawn by one source',
};

export function ConflictsList({ onFocus }) {
  const [state, setState] = useState({ loading: true, data: null, error: null });

  useEffect(() => {
    api.conflicts().then((res) =>
      setState({ loading: false, data: res.ok ? res.data : null, error: res.ok ? null : res.error }),
    );
  }, []);

  if (state.loading) return <Note>Checking claims…</Note>;
  if (state.error) return <Note tone="alert">{state.error}</Note>;
  if (!state.data.total) {
    return <Note>No disagreements between sources. Every claim is backed and current.</Note>;
  }

  return (
    <div className="divide-y divide-rule/60">
      {state.data.conflicts.map((c, i) => (
        <button
          key={i}
          onClick={() => onFocus?.(c.subject_id)}
          className="block w-full px-3 py-2 text-left hover:bg-raised"
        >
          <div className="flex items-center gap-2">
            <span className={`border px-1.5 text-micro uppercase ${SEV[c.severity]}`}>
              {KIND_COPY[c.kind] ?? c.kind}
            </span>
            <span className="text-tiny text-green">{c.subject}</span>
            <span className="text-micro text-green-ghost">{c.predicate}</span>
            {c.object && <span className="text-tiny text-green-dim">→ {c.object}</span>}
          </div>
          <p className="pt-1 text-tiny text-green-dim">{c.detail}</p>

          {c.candidates && (
            <ul className="pt-1">
              {c.candidates.map((cand) => (
                <li key={cand.object_id} className="flex items-center gap-2 text-micro text-green-ghost">
                  <span className="tabular-nums text-green-dim">
                    {cand.confidence.toFixed(2)}
                  </span>
                  <span className="text-green-dim">{cand.object}</span>
                  <span>via {cand.sources.join(', ')}</span>
                </li>
              ))}
            </ul>
          )}

          <p className="pt-1 text-micro text-green-ghost">{c.suggestion}</p>
        </button>
      ))}
    </div>
  );
}

export function SourcesMatrix() {
  const [rows, setRows] = useState(null);

  useEffect(() => {
    api.reliability().then((res) => setRows(res.ok ? res.data : { error: res.error }));
  }, []);

  if (!rows) return <Note>Loading matrix…</Note>;
  if (rows.error) return <Note tone="alert">{rows.error}</Note>;

  return (
    <div>
      <p className="px-3 py-2 text-micro leading-relaxed text-green-ghost">{rows.scale}</p>
      <table className="w-full border-collapse text-tiny">
        <thead className="text-micro uppercase text-green-ghost">
          <tr className="border-y border-rule text-left">
            <th className="px-3 py-1.5 font-normal">grade</th>
            <th className="px-3 py-1.5 font-normal">source</th>
            <th className="px-3 py-1.5 font-normal">weight</th>
            <th className="px-3 py-1.5 font-normal">good for</th>
            <th className="px-3 py-1.5 font-normal">caveat</th>
          </tr>
        </thead>
        <tbody>
          {rows.sources.map((s) => (
            <tr key={s.name} className="border-b border-rule/60">
              <td className="px-3 py-1.5">
                <span
                  className={`border px-1 text-micro ${
                    s.weight >= 0.85 ? SEV.low.replace('text-green-dim', 'text-ip border-ip/40') :
                    s.weight >= 0.6 ? 'text-green-dim border-rule' : 'text-warn border-warn/40'
                  }`}
                >
                  {s.grade}
                </span>
              </td>
              <td className="px-3 py-1.5 text-green">{s.label}</td>
              <td className="px-3 py-1.5 tabular-nums text-green-dim">{s.weight.toFixed(2)}</td>
              <td className="px-3 py-1.5 text-green-dim">{s.ttlDays}d</td>
              <td className="px-3 py-1.5 text-green-ghost">{s.note}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Collectors({ onMessage }) {
  const [status, setStatus] = useState(null);
  const [busy, setBusy] = useState(null);

  const refresh = () => api.sourceStatus().then((res) => setStatus(res.ok ? res.data : { error: res.error }));
  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, []);

  const runNvd = async () => {
    setBusy('nvd');
    const res = await api.syncNvd(25);
    onMessage?.(res.ok ? res.data.note : `! ${res.error}`);
    setBusy(null);
    refresh();
  };

  const runShodan = async () => {
    setBusy('shodan');
    const res = await api.syncShodan(10);
    if (res.ok) {
      const t = res.data.totals;
      onMessage?.(
        `shodan: ${t.ports} ports, ${t.software} services` +
          (t.skipped ? ` · ${t.skipped} skipped for unproven ownership` : ''),
      );
    } else {
      onMessage?.(`! ${res.error}`);
    }
    setBusy(null);
    refresh();
  };

  const runFeeds = async () => {
    setBusy('feeds');
    const res = await api.syncFeeds();
    onMessage?.(res.ok ? `feeds: ${res.data.mentions} mentions across ${res.data.reports} articles` : `! ${res.error}`);
    setBusy(null);
    refresh();
  };

  const runKev = async () => {
    setBusy('kev');
    const res = await api.syncKev();
    onMessage?.(res.ok ? `KEV: ${res.data.flagged} of ${res.data.in_catalog} matched the graph` : `! ${res.error}`);
    setBusy(null);
    refresh();
  };

  if (!status) return <Note>Loading collectors…</Note>;
  if (status.error) return <Note tone="alert">{status.error}</Note>;

  const active = status.active_jobs ?? [];

  return (
    <div className="p-3">
      <div className="flex gap-2">
        <button className="btn" onClick={runNvd} disabled={busy || active.length}>
          sync nvd
        </button>
        <button className="btn" onClick={runKev} disabled={busy}>
          sync kev
        </button>
        <button className="btn" onClick={runShodan} disabled={busy}>
          scan hosts
        </button>
        <button className="btn" onClick={runFeeds} disabled={busy}>
          pull feeds
        </button>
      </div>

      <ul className="mt-2 space-y-0.5 text-micro text-green-ghost">
        {!status.nvd.api_key && (
          <li className="text-warn">
            no NVD_API_KEY — one request per {(status.nvd.request_gap_ms / 1000).toFixed(1)}s
          </li>
        )}
        {status.shodan && <li>{status.shodan.note}</li>}
      </ul>

      {active.map((job) => (
        <div key={job.id} className="mt-3 border border-rule bg-void p-2">
          <p className="text-tiny text-green">
            {job.source} · {job.processed}/{job.total} · {job.current ?? 'starting'}
          </p>
          <div className="mt-1 h-1 w-full bg-rule">
            <div
              className="h-full bg-green transition-[width] duration-300"
              style={{ width: `${job.total ? (job.processed / job.total) * 100 : 0}%` }}
            />
          </div>
          {job.errors?.length > 0 && (
            <p className="pt-1 text-micro text-warn">{job.errors.length} package(s) failed</p>
          )}
        </div>
      ))}

      <p className="eyebrow pb-1 pt-4">recent runs</p>
      {status.history.length === 0 ? (
        <p className="text-tiny text-green-dim">Nothing has run yet.</p>
      ) : (
        <ul className="space-y-1">
          {status.history.map((r, i) => (
            <li key={i} className="flex items-center gap-3 text-tiny">
              <span className="w-10 text-green-dim">{r.source}</span>
              <span className={r.status === 'completed' ? 'text-ip' : 'text-warn'}>{r.status}</span>
              <span className="text-green-ghost">
                {r.upserted} cves · {r.linked} links · {r.pruned} pruned
              </span>
              <span className="ml-auto text-micro text-green-ghost">
                {(r.finished_at ?? '').slice(0, 16).replace('T', ' ')}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Note({ children, tone }) {
  return (
    <p className={`px-3 py-4 text-tiny ${tone === 'alert' ? 'text-alert' : 'text-green-dim'}`}>
      {children}
    </p>
  );
}
