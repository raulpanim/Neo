import { useState } from 'react';

const TYPES = [
  ['Domain', 'text-domain'],
  ['IP', 'text-ip'],
  ['Port', 'text-port'],
  ['Software', 'text-software'],
  ['CVE', 'text-cve'],
  ['Exploit', 'text-exploit'],
  ['Company', 'text-company'],
  ['Email', 'text-email'],
  ['ASN', 'text-asn'],
];

export default function CommandRail({ onCommand, hiddenTypes, onToggleType, busy }) {
  const [value, setValue] = useState('');

  const submit = (e) => {
    e.preventDefault();
    const q = value.trim();
    if (!q) return;
    onCommand({ kind: 'search', arg: q });
  };

  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-rule bg-panel">
      {/* prompt */}
      <form onSubmit={submit} className="border-b border-rule p-3">
        <label htmlFor="q" className="eyebrow block pb-1.5">
          query
        </label>
        <div className="flex items-center gap-1.5 border border-rule bg-void px-2 py-1.5 focus-within:border-green-dim">
          <span aria-hidden className="text-green-dim">
            ›
          </span>
          <input
            id="q"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="example.com"
            autoComplete="off"
            spellCheck="false"
            className="w-full bg-transparent text-tiny text-green placeholder:text-green-ghost focus:outline-none"
          />
        </div>
        <div className="flex gap-1 pt-2">
          <button type="submit" className="btn flex-1" disabled={busy}>
            search
          </button>
          <button
            type="button"
            className="btn flex-1"
            disabled={busy || !value.trim()}
            onClick={() => onCommand({ kind: 'surface', arg: value.trim() })}
          >
            surface
          </button>
        </div>
      </form>

      {/* standing views */}
      <div className="border-b border-rule p-3">
        <p className="eyebrow pb-1.5">views</p>
        <div className="space-y-1">
          <RailButton onClick={() => onCommand({ kind: 'exploitable' })} disabled={busy}>
            exploitable now
          </RailButton>
          <RailButton onClick={() => onCommand({ kind: 'chains' })} disabled={busy}>
            attack chains
          </RailButton>
          <RailButton onClick={() => onCommand({ kind: 'surface', arg: 'example.com' })} disabled={busy}>
            example.com surface
          </RailButton>
        </div>
      </div>

      {/* filters double as the legend — one control, one meaning */}
      <div className="flex-1 overflow-y-auto p-3">
        <p className="eyebrow pb-1.5">entities</p>
        <ul className="space-y-0.5">
          {TYPES.map(([type, tone]) => {
            const off = hiddenTypes.includes(type);
            return (
              <li key={type}>
                <button
                  onClick={() => onToggleType(type)}
                  aria-pressed={!off}
                  className={`flex w-full items-center gap-2 px-1 py-0.5 text-tiny transition-opacity hover:bg-raised ${
                    off ? 'opacity-35' : ''
                  }`}
                >
                  <span aria-hidden className={`${tone} text-[13px] leading-none`}>
                    ■
                  </span>
                  <span className="text-green-dim">{type}</span>
                  <span className="ml-auto text-micro text-green-ghost">{off ? 'off' : 'on'}</span>
                </button>
              </li>
            );
          })}
        </ul>

        <p className="eyebrow pb-1.5 pt-4">edge risk</p>
        <ul className="space-y-0.5 text-tiny text-green-dim">
          <li className="flex items-center gap-2">
            <span aria-hidden className="text-alert">━</span> public exploit
          </li>
          <li className="flex items-center gap-2">
            <span aria-hidden className="text-warn">╌</span> unconfirmed / cvss ≥ 7
          </li>
          <li className="flex items-center gap-2">
            <span aria-hidden className="text-ip">━</span> low
          </li>
        </ul>
      </div>

      <div className="rule-t p-3 text-micro text-green-ghost">
        <p>
          <span className="kbd">1</span>–<span className="kbd">3</span> layout ·{' '}
          <span className="kbd">f</span> findings · <span className="kbd">a</span> chains ·{' '}
          <span className="kbd">c</span> conflicts ·{' '}
          <span className="kbd">s</span> sync · <span className="kbd">esc</span> clear
        </p>
      </div>
    </aside>
  );
}

function RailButton({ children, ...rest }) {
  return (
    <button
      {...rest}
      className="w-full border border-rule bg-void px-2 py-1 text-left text-tiny lowercase text-green-dim transition-colors hover:border-green-dim hover:text-green disabled:opacity-40"
    >
      {children}
    </button>
  );
}
