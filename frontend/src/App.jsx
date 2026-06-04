import React, { useState, useEffect } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
} from 'chart.js';
import { Bar, Pie } from 'react-chartjs-2';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend, ArcElement);

// --- SVG Icons ---
const ShieldIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
  </svg>
);
const UploadIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
    <polyline points="17 8 12 3 7 8"></polyline>
    <line x1="12" y1="3" x2="12" y2="15"></line>
  </svg>
);
const DownloadIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
    <polyline points="7 10 12 15 17 10"></polyline>
    <line x1="12" y1="15" x2="12" y2="3"></line>
  </svg>
);
const BotIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="11" width="18" height="10" rx="2"></rect>
    <circle cx="12" cy="5" r="2"></circle>
    <path d="M12 7v4"></path>
    <line x1="8" y1="16" x2="8" y2="16"></line>
    <line x1="16" y1="16" x2="16" y2="16"></line>
  </svg>
);
const XIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="18" y1="6" x2="6" y2="18"></line>
    <line x1="6" y1="6" x2="18" y2="18"></line>
  </svg>
);

function App() {
  const [stats, setStats] = useState({ total_logs: 0, unique_ips: 0, top_endpoints: [], total_alerts: 0, recent_alerts: [] });
  const [chartData, setChartData] = useState({ severity: null, attacks: null });
  const [file, setFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState('');

  // AI Modal State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [aiAnalysis, setAiAnalysis] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [currentAlert, setCurrentAlert] = useState(null);

  const fetchData = async () => {
    try {
      const statsRes = await fetch('http://localhost:5000/api/stats');
      const statsData = await statsRes.json();
      setStats(statsData);

      const chartRes = await fetch('http://localhost:5000/api/chart-data');
      const chartResData = await chartRes.json();
      setChartData(chartResData);
    } catch (error) {
      console.error('Error fetching data:', error);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);
    setIsUploading(true);
    setUploadStatus('Processing logs and analyzing threats...');

    try {
      const response = await fetch('http://localhost:5000/api/upload', {
        method: 'POST',
        body: formData
      });
      const data = await response.json();
      setUploadStatus(data.message || 'Upload complete');
      fetchData(); // Refresh all data
    } catch (error) {
      setUploadStatus('Upload failed. Please check server logs.');
    } finally {
      setIsUploading(false);
      setTimeout(() => setUploadStatus(''), 5000);
    }
  };

  const handleExport = (format) => {
    window.location.href = `http://localhost:5000/api/export/${format}`;
  };

  const handleAnalyzeAI = async (alert) => {
    setCurrentAlert(alert);
    setIsModalOpen(true);
    setIsAnalyzing(true);
    setAiAnalysis('');

    try {
      const res = await fetch(`http://localhost:5000/api/analyze/${alert.id}`);
      const data = await res.json();
      
      if (data.analysis) {
        setAiAnalysis(data.analysis);
      } else if (data.error) {
        setAiAnalysis(`❌ Error: ${data.error}`);
      }
    } catch (error) {
      setAiAnalysis('❌ Failed to connect to AI Analyst.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const formatAiText = (text) => {
    if (!text) return null;
    // Basic markdown formatting for the simple UI without needing a markdown library
    return text.split('\n').map((line, i) => {
      if (line.startsWith('**') && line.endsWith('**')) {
        return <h3 key={i} style={{marginTop: '1rem'}}>{line.replace(/\*\*/g, '')}</h3>;
      }
      if (line.startsWith('* ')) {
        return <li key={i}>{line.replace('* ', '')}</li>;
      }
      if (line.includes('**')) {
        // Handle bolding within a line
        const parts = line.split('**');
        return (
          <p key={i}>
            {parts.map((part, j) => j % 2 === 1 ? <strong key={j}>{part}</strong> : part)}
          </p>
        );
      }
      return <p key={i}>{line}</p>;
    });
  };

  // Chart Configs
  const pieOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { position: 'right', labels: { color: '#f1f5f9' } },
    }
  };
  
  const barOptions = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      y: { ticks: { color: '#94a3b8' }, grid: { color: '#2a375a' } },
      x: { ticks: { color: '#94a3b8' }, grid: { display: false } }
    },
    plugins: {
      legend: { display: false }
    }
  };

  const getSeverityBadgeClass = (severity) => {
    switch(severity?.toLowerCase()) {
      case 'critical': return 'badge-critical';
      case 'high': return 'badge-high';
      case 'medium': return 'badge-medium';
      default: return 'badge-low';
    }
  };

  return (
    <div className="container">
      <header>
        <h1 style={{display: 'flex', alignItems: 'center', gap: '0.75rem'}}>
          <ShieldIcon /> LogSentry SOC
        </h1>
        <div className="header-actions">
          <button className="btn-secondary" onClick={() => handleExport('csv')}>
            <DownloadIcon /> Export CSV
          </button>
          <button className="btn-secondary" onClick={() => handleExport('pdf')}>
            <DownloadIcon /> Export PDF
          </button>
        </div>
      </header>
      
      {/* Upload Section */}
      <div className="card">
        <h2>Ingest Logs</h2>
        <form onSubmit={handleUpload} className="upload-form">
          <input type="file" onChange={(e) => setFile(e.target.files[0])} accept=".log,.txt" required />
          <button type="submit" disabled={isUploading || !file}>
            {isUploading ? 'Processing...' : <><UploadIcon /> Analyze Logs</>}
          </button>
        </form>
        {uploadStatus && <p style={{marginTop: '1rem', color: '#06b6d4'}}>{uploadStatus}</p>}
      </div>

      {/* Stats Grid */}
      <div className="stats-grid">
        <div className="card stat-card">
          <h3>Total Logs Parsed</h3>
          <div className="stat-number">{stats.total_logs}</div>
        </div>
        <div className="card stat-card">
          <h3>Unique IP Addresses</h3>
          <div className="stat-number">{stats.unique_ips}</div>
        </div>
        <div className="card stat-card">
          <h3>Total Threats Detected</h3>
          <div className="stat-number" style={{color: '#ef4444', textShadow: '0 0 20px rgba(239, 68, 68, 0.4)'}}>
            {stats.total_alerts}
          </div>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="charts-grid">
        <div className="card">
          <h3>Threat Severity Distribution</h3>
          <div className="chart-container">
            {chartData.severity && chartData.severity.labels.length > 0 ? (
              <Pie 
                data={{
                  labels: chartData.severity.labels,
                  datasets: [{
                    data: chartData.severity.values,
                    backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6'],
                    borderWidth: 0
                  }]
                }} 
                options={pieOptions} 
              />
            ) : <p style={{color: '#94a3b8'}}>No threat data available.</p>}
          </div>
        </div>
        
        <div className="card">
          <h3>Attack Types</h3>
          <div className="chart-container">
            {chartData.attacks && chartData.attacks.labels.length > 0 ? (
              <Bar 
                data={{
                  labels: chartData.attacks.labels,
                  datasets: [{
                    label: 'Count',
                    data: chartData.attacks.values,
                    backgroundColor: '#06b6d4',
                    borderRadius: 4
                  }]
                }} 
                options={barOptions} 
              />
            ) : <p style={{color: '#94a3b8'}}>No attack data available.</p>}
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="card">
        <h2>Recent Security Alerts</h2>
        <div className="table-container">
          {stats.recent_alerts && stats.recent_alerts.length > 0 ? (
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>IP Address</th>
                  <th>Attack Type</th>
                  <th>Severity</th>
                  <th>Threat Intel</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {stats.recent_alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td style={{whiteSpace: 'nowrap'}}>{new Date(alert.timestamp).toLocaleString()}</td>
                    <td style={{fontFamily: 'monospace'}}>{alert.ip_address}</td>
                    <td>{alert.attack_type}</td>
                    <td>
                      <span className={`badge ${getSeverityBadgeClass(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td>
                      {alert.threat_intel_score !== null ? (
                        <span className={`badge ${alert.threat_intel_score > 50 ? 'badge-score-high' : 'badge-score'}`}>
                          Score: {alert.threat_intel_score}
                        </span>
                      ) : <span style={{color: '#94a3b8'}}>N/A</span>}
                    </td>
                    <td>
                      <button className="btn-ai" onClick={() => handleAnalyzeAI(alert)}>
                        <BotIcon /> AI Analyst
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p style={{color: '#94a3b8', textAlign: 'center', padding: '2rem 0'}}>
              System is secure. No recent alerts detected.
            </p>
          )}
        </div>
      </div>

      {/* AI Analyst Modal */}
      {isModalOpen && (
        <div className="modal-overlay" onClick={() => setIsModalOpen(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2><BotIcon /> AI SOC Analyst</h2>
              <button className="modal-close" onClick={() => setIsModalOpen(false)}>
                <XIcon />
              </button>
            </div>
            <div className="modal-body">
              {currentAlert && (
                <div style={{marginBottom: '1.5rem', padding: '1rem', background: 'rgba(0,0,0,0.2)', borderRadius: '8px'}}>
                  <strong style={{color: '#06b6d4'}}>Target Incident:</strong> {currentAlert.attack_type} from {currentAlert.ip_address}
                </div>
              )}
              
              {isAnalyzing ? (
                <div className="ai-loader">
                  <div className="spinner"></div>
                  <p>Generating Threat Analysis & Remediation Steps...</p>
                </div>
              ) : (
                <div className="ai-response">
                  {formatAiText(aiAnalysis)}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
