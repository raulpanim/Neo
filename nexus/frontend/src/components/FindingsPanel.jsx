import { ConflictsList, SourcesMatrix, Collectors } from './IntelPanel.jsx';
import ChainsPanel from './ChainsPanel.jsx';

const TONE = { high: 'text-alert', medium: 'text-warn', low: 'text-ip' };

const TABS = [
  ['findings', 'findings'],
  ['chains', 'chains'],
  ['conflicts', 'conflicts'],
  ['sources', 'sources'],
  ['collectors', 'collectors'],
];

/**
 * One drawer, four readings of the same graph: what's vulnerable, where the
 * sources disagree, how much each source is worth, and when they last ran.
 */
export default function FindingsPanel({
  findings, summary, title, open, onToggle, onFocus, onFocusNode, onMessage, tab, onTab,
}) {
  return (
    <section
      className={`flex shrink-0 flex-col border-t border-rule bg-panel transition-[height] duration-200 ${
        open ? 'h-64' : 'h-8'
      }`}
    >
      <div className="flex h-8 shrink-0 items-center gap-3 px-3">
        <div className="flex gap-1">
          {TABS.map(([id, label]) => (
            <button
              key={id}
              onClick={() => {
                onTab(id);
                if (!open) onToggle();
              }}
              className={`px-1.5 text-micro uppercase tracking-[0.12em] transition-colors ${
                tab === id && open ? 'text-green' : 'text-green-ghost hover:text-green-dim'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
        {tab === 'findings' && <span className="text-tiny text-green-dim">{title}</span>}
        {tab === 'findings' && summary && (
          <span className="flex gap-2 text-micro">
            <span className="text-alert">{summary.high} high</span>
            <span className="text-warn">{summary.medium} med</span>
            <span className="text-ip">{summary.low} low</span>
            {summary.with_exploits > 0 && (
              <span className="text-exploit">{summary.with_exploits} with exploit</span>
            )}
          </span>
        )}
        <button
          onClick={onToggle}
          aria-expanded={open}
          aria-label={open ? 'Collapse drawer' : 'Expand drawer'}
          className="ml-auto px-1 text-green-ghost hover:text-green"
        >
          <span aria-hidden>{open ? '▾' : '▴'}</span>
        </button>
      </div>

      {open && tab !== 'findings' && (
        <div className="flex-1 overflow-auto">
          {tab === 'chains' && <ChainsPanel onFocusCve={onFocus} onMessage={onMessage} />}
          {tab === 'conflicts' && <ConflictsList onFocus={onFocusNode} />}
          {tab === 'sources' && <SourcesMatrix />}
          {tab === 'collectors' && <Collectors onMessage={onMessage} />}
        </div>
      )}

      {open && tab === 'findings' && (
        <div className="flex-1 overflow-auto">
          {findings.length === 0 ? (
            <p className="px-3 py-4 text-tiny text-green-dim">
              No findings loaded. Run <span className="text-green">surface</span> on a domain, or open{' '}
              <span className="text-green">exploitable now</span>.
            </p>
          ) : (
            <table className="w-full border-collapse text-tiny">
              <thead className="sticky top-0 bg-panel text-micro uppercase text-green-ghost">
                <tr className="border-b border-rule text-left">
                  <Th>risk</Th>
                  <Th>cve</Th>
                  <Th>cvss</Th>
                  <Th>software</Th>
                  <Th>where</Th>
                  <Th>exploit</Th>
                  <Th>match</Th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f, i) => (
                  <tr
                    key={`${f.cve}-${i}`}
                    onClick={() => onFocus?.(f.cve)}
                    className="cursor-pointer border-b border-rule/60 hover:bg-raised"
                  >
                    <Td>
                      <span className={`${TONE[f.risk]} tabular-nums`}>
                        {String(f.risk_score).padStart(3, '0')}
                      </span>
                    </Td>
                    <Td className="text-green">{f.cve}</Td>
                    <Td className="tabular-nums text-green-dim">{f.cvss?.toFixed?.(1) ?? f.cvss}</Td>
                    <Td className="text-green-dim">
                      {f.software} {f.version}
                    </Td>
                    <Td className="text-green-ghost">
                      {f.ip ? `${f.ip}${f.port ? `:${f.port}` : ''}` : (f.domains ?? []).join(', ')}
                    </Td>
                    <Td>
                      {(f.exploits?.length ?? f.exploit_sources?.length ?? 0) > 0 ? (
                        <span className="text-exploit">
                          {(f.exploits ?? []).map((e) => e.source).join(', ') ||
                            (f.exploit_sources ?? []).join(', ')}
                        </span>
                      ) : (
                        <span className="text-green-ghost">—</span>
                      )}
                    </Td>
                    <Td className="text-green-ghost">{f.match_method ?? '—'}</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </section>
  );
}

const Th = ({ children }) => <th className="px-3 py-1.5 font-normal">{children}</th>;
const Td = ({ children, className = '' }) => <td className={`px-3 py-1.5 ${className}`}>{children}</td>;
