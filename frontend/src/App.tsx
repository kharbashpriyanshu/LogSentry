import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import MainLayout from './layouts/MainLayout';
import { ThemeProvider } from './context/ThemeContext';
import { ErrorBoundary } from './components/ErrorBoundary';

// Direct imports for instant, reliable module rendering
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import Incidents from './pages/Incidents';
import ThreatIntel from './pages/ThreatIntel';
import AIAnalysis from './pages/AIAnalysis';
import ThreatHunting from './pages/ThreatHunting';
import MitreMatrix from './pages/MitreMatrix';
import Reports from './pages/Reports';
import SystemHealth from './pages/SystemHealth';
import ConnectServer from './pages/ConnectServer';
import Settings from './pages/Settings';
import NotFound from './pages/NotFound';

function App() {
  return (
    <ThemeProvider>
      <ErrorBoundary>
        <Router>
          <Routes>
            <Route path="/" element={<MainLayout />}>
              <Route index element={<Navigate to="/dashboard" replace />} />
              <Route path="dashboard" element={<Dashboard />} />
              <Route path="alerts" element={<Alerts />} />
              <Route path="incidents" element={<Incidents />} />
              <Route path="threat-intel" element={<ThreatIntel />} />
              <Route path="ai-analysis" element={<AIAnalysis />} />
              <Route path="threat-hunting" element={<ThreatHunting />} />
              <Route path="mitre-matrix" element={<MitreMatrix />} />
              <Route path="reports" element={<Reports />} />
              <Route path="connect-server" element={<ConnectServer />} />
              <Route path="health" element={<SystemHealth />} />
              <Route path="settings" element={<Settings />} />
              <Route path="*" element={<NotFound />} />
            </Route>
          </Routes>
        </Router>
      </ErrorBoundary>
    </ThemeProvider>
  );
}

export default App;
