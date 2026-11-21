import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertOctagon, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error in component:', error, errorInfo);
  }

  public handleReset = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center min-h-[400px] p-8 text-center bg-[var(--bg-card)] rounded-2xl border border-red-500/20 max-w-2xl mx-auto my-12 shadow-md">
          <div className="p-3 bg-red-500/10 text-red-500 rounded-2xl mb-4 border border-red-500/20">
            <AlertOctagon className="w-8 h-8" />
          </div>
          <h2 className="text-xl font-black text-[var(--text-primary)] mb-2">
            Module Render Notice
          </h2>
          <p className="text-xs text-[var(--text-muted)] mb-4 max-w-md">
            An unexpected error occurred while rendering this module. You can reload or return to the dashboard.
          </p>
          {this.state.error && (
            <pre className="p-3 bg-black/40 text-red-400 font-mono text-[11px] rounded-lg max-w-full overflow-x-auto mb-6 text-left border border-red-500/10">
              {this.state.error.message}
            </pre>
          )}
          <div className="flex gap-3">
            <button
              onClick={this.handleReset}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold transition-all shadow-xs cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Reload Page
            </button>
            <a
              href="/dashboard"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl border border-[var(--border-default)] bg-[var(--bg-card)] text-xs font-semibold text-[var(--text-primary)] hover:bg-[var(--bg-card-hover)] transition-all cursor-pointer"
            >
              Go to Dashboard
            </a>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
