import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import MainLayout from './layouts/MainLayout';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import ThreatIntel from './pages/ThreatIntel';
import AIAnalysis from './pages/AIAnalysis';
import SystemHealth from './pages/SystemHealth';
import Settings from './pages/Settings';
import NotFound from './pages/NotFound';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<MainLayout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="threat-intel" element={<ThreatIntel />} />
          <Route path="ai-analysis" element={<AIAnalysis />} />
          <Route path="health" element={<SystemHealth />} />
          <Route path="settings" element={<Settings />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </Router>
  );
}

export default App;
