/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // surfaces — near-black with a green cast, like an unlit phosphor tube
        void: '#070b0a',
        panel: '#0c1211',
        raised: '#121a18',
        rule: '#1c2a26',

        // phosphor text ramp
        phos: '#5eead4',
        green: { DEFAULT: '#4ade80', dim: '#2c6b4a', ghost: '#1a3a2c' },

        // alert ramp
        alert: '#ff4d4d',
        warn: '#f5c542',

        // entity hues (mirrored in cytoscape/style.js)
        domain: '#3b82f6',
        ip: '#22c55e',
        cve: '#ff4d4d',
        software: '#d946ef',
        exploit: '#fb923c',
        port: '#14b8a6',
        company: '#a78bfa',
        email: '#eab308',
        asn: '#64748b',
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      fontSize: {
        micro: ['10px', { lineHeight: '14px', letterSpacing: '0.12em' }],
        tiny: ['11px', { lineHeight: '16px', letterSpacing: '0.06em' }],
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(74,222,128,0.25), 0 0 24px -6px rgba(74,222,128,0.35)',
        alert: '0 0 0 1px rgba(255,77,77,0.35), 0 0 24px -6px rgba(255,77,77,0.45)',
      },
      keyframes: {
        sweep: { '0%': { transform: 'translateY(-100%)' }, '100%': { transform: 'translateY(100%)' } },
        blink: { '0%,49%': { opacity: 1 }, '50%,100%': { opacity: 0 } },
        boot: { from: { opacity: 0, transform: 'translateY(4px)' }, to: { opacity: 1, transform: 'none' } },
      },
      animation: {
        sweep: 'sweep 7s linear infinite',
        blink: 'blink 1.1s step-end infinite',
        boot: 'boot 260ms ease-out both',
      },
    },
  },
  plugins: [],
};
