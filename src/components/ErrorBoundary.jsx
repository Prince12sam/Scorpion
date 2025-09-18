import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    // Update state so the next render will show the fallback UI
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    // Log error details
    console.error('ErrorBoundary caught an error:', error, errorInfo);
    
    this.setState({
      error: error,
      errorInfo: errorInfo
    });

    // Cancel any pending API requests to prevent further issues
    if (window.apiClient) {
      window.apiClient.cancelAllRequests();
    }
  }

  handleRetry = () => {
    // Reset error state and retry
    this.setState({ hasError: false, error: null, errorInfo: null });
    
    // Reload the page as a last resort
    if (this.state.error) {
      window.location.reload();
    }
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-slate-950 text-white flex items-center justify-center p-6">
          <div className="max-w-md w-full bg-slate-900 rounded-lg border border-red-500/20 p-6">
            <div className="text-center">
              <AlertTriangle className="h-12 w-12 text-red-500 mx-auto mb-4" />
              <h2 className="text-xl font-bold text-red-400 mb-2">Application Error</h2>
              <p className="text-slate-300 mb-6">
                Something went wrong with the Scorpion Security Platform. 
                The error has been logged for debugging.
              </p>
              
              {this.props.showDetails && this.state.error && (
                <details className="text-left mb-4 p-3 bg-slate-800 rounded border border-slate-700">
                  <summary className="cursor-pointer text-sm font-medium text-slate-200 mb-2">
                    Error Details
                  </summary>
                  <pre className="text-xs text-red-400 whitespace-pre-wrap overflow-auto max-h-32">
                    {this.state.error.toString()}
                    {this.state.errorInfo.componentStack}
                  </pre>
                </details>
              )}
              
              <div className="space-y-3">
                <Button 
                  onClick={this.handleRetry}
                  className="w-full bg-blue-600 hover:bg-blue-700 text-white"
                >
                  <RefreshCw className="h-4 w-4 mr-2" />
                  Retry Application
                </Button>
                
                <Button 
                  onClick={() => window.location.reload()}
                  variant="outline" 
                  className="w-full border-slate-600 text-slate-200 hover:bg-slate-800"
                >
                  Reload Page
                </Button>
              </div>
              
              <p className="text-xs text-slate-500 mt-4">
                If this error persists, check the browser console and server logs for more information.
              </p>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;