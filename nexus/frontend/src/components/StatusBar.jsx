import { layoutOrder } from '../cytoscape/style.js';

export default function StatusBar({ health, stats, counts, layout, onLayout, message, busy }) {
  const online = health === 'ok';

  return (
    <header className="flex h-9 shrink-0 items-center gap-4 border-b border-rule bg-panel px-3">
      <div className="flex items-baseline gap-2">
        <span className="text-[13px] font-bold tracking-[0.28em] text-green">NEXUS</span>
        <span className="text-micro text-green-ghost">attack surface graph</span>
      </div>

      <div className="h-4 w-px bg-rule" aria-hidden />

      {/* live graph counts */}
      <p className="text-tiny tabular-nums text-green-dim">
        {counts.nodes} nodes · {counts.edges} edges
        {counts.truncated && <span className="pl-2 text-warn">capped at 100</span>}
      </p>

      {stats?.exploitable_cves > 0 && (
        <p className="text-tiny text-alert">
          {stats.exploitable_cves} cve{stats.exploitable_cves === 1 ? '' : 's'} with public exploits
        </p>
      )}

      {/* layout switch */}
      <div className="ml-auto flex items-center gap-1">
        <span className="eyebrow pr-1">layout</span>
        {layoutOrder.map((name, i) => (
          <button
            key={name}
            onClick={() => onLayout(name)}
            className={`btn ${layout === name ? 'btn-on' : ''}`}
            title={`Press ${i + 1}`}
          >
            {name}
          </button>
        ))}
      </div>

      <div className="h-4 w-px bg-rule" aria-hidden />

      {/* connection + last action, right-aligned like a tmux status line */}
      <p className="flex w-64 items-center justify-end gap-2 truncate text-tiny">
        {busy && <span className="animate-blink text-green">▌</span>}
        <span className={message?.startsWith('!') ? 'text-alert' : 'text-green-dim'}>
          {message || (online ? 'ready' : 'no link to api')}
        </span>
        <span
          aria-label={online ? 'API online' : 'API offline'}
          className={`h-1.5 w-1.5 rounded-full ${online ? 'bg-green shadow-glow' : 'bg-alert shadow-alert'}`}
        />
      </p>
    </header>
  );
}
