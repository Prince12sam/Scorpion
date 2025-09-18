import React from 'react';
import ReactDOM from 'react-dom/client';
import App from '@/App';
import ErrorBoundary from '@/components/ErrorBoundary';
import apiClient from '@/lib/api-client';
import '@/index.css';

// Make API client globally available for error boundary cleanup
window.apiClient = apiClient;

ReactDOM.createRoot(document.getElementById('root')).render(
  <ErrorBoundary showDetails={import.meta.env.DEV}>
    <App />
  </ErrorBoundary>
);