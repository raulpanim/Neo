import { useEffect, useState } from 'react';
import GraphView from './GraphView';
import ChainsView from './ChainsView';

const TABS = [
  { id: 'graph', label: 'Graph', key: 'g' },
  { id: 'chains', label: 'Chains', key: 'a' },
];

export default function App() {
  const [tab, setTab] = useState('graph');

  useEffect(() => {
    function onKeyDown(e) {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
      const match = TABS.find((t) => t.key === e.key.toLowerCase());
      if (match) setTab(match.id);
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  return (
    <div className="flex h-screen flex-col bg-gray-950 text-gray-100">
      <header className="flex items-center gap-4 border-b border-gray-800 px-4 py-3">
        <h1 className="text-lg font-bold">nexus</h1>
        <nav className="flex gap-1">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={`rounded px-3 py-1 text-sm ${
                tab === t.id ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
              }`}
            >
              {t.label} <span className="text-xs opacity-60">({t.key})</span>
            </button>
          ))}
        </nav>
      </header>
      <main className="flex-1 overflow-hidden">{tab === 'graph' ? <GraphView /> : <ChainsView />}</main>
    </div>
  );
}
