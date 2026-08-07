import { Component } from 'react';

/**
 * A bad API response should degrade the one panel that choked on it, not
 * white-screen the whole app - which is exactly what used to happen (a
 * Cytoscape crash from a serialize.js bug once took down the entire UI).
 *
 * Auto-recovers when `resetKeys` changes, so loading different data (a new
 * search, a different domain) clears the error without needing a manual
 * "try again" - the app's flow is already "load new data replaces old", so
 * this just extends that to the error case.
 */
export default class ErrorBoundary extends Component {
  state = { error: null };

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error('[nexus] render error:', error, info);
  }

  componentDidUpdate(prevProps) {
    if (!this.state.error) return;
    const changed = (this.props.resetKeys ?? []).some((k, i) => k !== prevProps.resetKeys?.[i]);
    if (changed) this.setState({ error: null });
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex h-full flex-col items-center justify-center gap-2 p-6 text-center">
          <p className="text-tiny text-alert">{this.props.label ?? 'Something broke rendering this.'}</p>
          <p className="max-w-md text-micro text-green-ghost">{this.state.error.message}</p>
        </div>
      );
    }
    return this.props.children;
  }
}
