import { useEffect, useState } from 'react';
import { api } from './api';

export default function ChainsView() {
  const [chains, setChains] = useState(null);
  const [cveById, setCveById] = useState({});
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.getChains(), api.getCves()])
      .then(([chainsData, cves]) => {
        if (cancelled) return;
        setChains(chainsData);
        setCveById(Object.fromEntries(cves.map((c) => [c.id, c])));
      })
      .catch((err) => {
        if (!cancelled) setError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) return <div className="p-6 text-red-400">Failed to load chains: {error}</div>;
  if (!chains) return <div className="p-6 text-gray-400">Loading chains…</div>;
  if (chains.length === 0) return <div className="p-6 text-gray-400">No exploit chains found.</div>;

  return (
    <div className="h-full space-y-4 overflow-auto p-6">
      <h2 className="text-lg font-semibold text-gray-100">Exploit chains</h2>
      {chains.map((chain, i) => (
        <div key={i} className="flex flex-wrap items-center gap-2 rounded-lg bg-gray-800 p-4">
          {chain.cves.map((cveId, idx) => {
            const cve = cveById[cveId];
            const hop = idx > 0 ? chain.hops[idx - 1] : null;
            const flagged = cve?.kev || cve?.exploited;
            return (
              <div key={cveId} className="flex items-center gap-2">
                {idx > 0 && (
                  <div className="flex flex-col items-center text-xs text-gray-400">
                    <span>→</span>
                    {hop && <span>{Math.round(hop.confidence * 100)}%</span>}
                  </div>
                )}
                <div
                  className={`rounded-md border px-3 py-2 text-sm ${
                    flagged ? 'border-red-500 bg-red-950 text-red-200' : 'border-gray-600 bg-gray-900 text-gray-200'
                  }`}
                >
                  <div className="font-mono">{cveId}</div>
                  {cve && (
                    <div className="text-xs text-gray-400">
                      CVSS {cve.cvss}
                      {flagged ? ' · KEV/exploited' : ''}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      ))}
    </div>
  );
}
