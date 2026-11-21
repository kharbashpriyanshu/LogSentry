import { lazy, Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Activity } from 'lucide-react';
import MainLayout from './layouts/MainLayout';
import { ThemeProvider } from './context/ThemeContext';

// Lazy loaded pages for performance
const Dashboard   = lazy(() => import('./pages/Dashboard'));
const Alerts      = lazy(() => import('./pages/Alerts'));
const Incidents   = lazy(() => import('./pages/Incidents'));
const ThreatIntel = lazy(() => import('./pages/ThreatIntel'));
const AIAnalysis  = lazy(() => import('./pages/AIAnalysis'));
const ThreatHunting = lazy(() => import('./pages/ThreatHunting'));
const MitreMatrix = lazy(() => import('./pages/MitreMatrix'));
const Reports     = lazy(() => import('./pages/Reports'));
const SystemHealth = lazy(() => import('./pages/SystemHealth'));
const ConnectServer = lazy(() => import('./pages/ConnectServer'));
const Settings    = lazy(() => import('./pages/Settings'));
const NotFound    = lazy(() => import('./pages/NotFound'));

import { ErrorBoundary } from './components/ErrorBoundary';

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-64">
      <Activity className="w-6 h-6 text-blue-400 animate-spin mr-3" />
      <span className="text-slate-400 text-sm">Loading module…</span>
    </div>
  );
}

function App() {
  return (
    <ThemeProvider>
      <ErrorBoundary>
        <Router>
          <Routes>
            <Route path="/" element={<MainLayout />}>
              <Route index element={<Navigate to="/dashboard" replace />} />
              <Route path="dashboard" element={<Suspense fallback={<PageLoader />}><Dashboard /></Suspense>} />
              <Route path="alerts" element={<Suspense fallback={<PageLoader />}><Alerts /></Suspense>} />
              <Route path="incidents" element={<Suspense fallback={<PageLoader />}><Incidents /></Suspense>} />
              <Route path="threat-intel" element={<Suspense fallback={<PageLoader />}><ThreatIntel /></Suspense>} />
              <Route path="ai-analysis" element={<Suspense fallback={<PageLoader />}><AIAnalysis /></Suspense>} />
              <Route path="threat-hunting" element={<Suspense fallback={<PageLoader />}><ThreatHunting /></Suspense>} />
              <Route path="mitre-matrix" element={<Suspense fallback={<PageLoader />}><MitreMatrix /></Suspense>} />
              <Route path="reports" element={<Suspense fallback={<PageLoader />}><Reports /></Suspense>} />
              <Route path="connect-server" element={<Suspense fallback={<PageLoader />}><ConnectServer /></Suspense>} />
              <Route path="health" element={<Suspense fallback={<PageLoader />}><SystemHealth /></Suspense>} />
              <Route path="settings" element={<Suspense fallback={<PageLoader />}><Settings /></Suspense>} />
              <Route path="*" element={<Suspense fallback={<PageLoader />}><NotFound /></Suspense>} />
            </Route>
          </Routes>
        </Router>
      </ErrorBoundary>
    </ThemeProvider>
  );
}

export default App;
