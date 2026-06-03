import React, { useState, useEffect } from 'react';

function App() {
  const [stats, setStats] = useState({ total_logs: 0, unique_ips: 0, top_endpoints: [] });
  const [file, setFile] = useState(null);
  const [uploadStatus, setUploadStatus] = useState('');

  const fetchStats = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/stats');
      const data = await response.json();
      setStats(data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);
    setUploadStatus('Uploading...');

    try {
      const response = await fetch('http://localhost:5000/api/upload', {
        method: 'POST',
        body: formData
      });
      const data = await response.json();
      setUploadStatus(data.message || 'Upload complete');
      fetchStats(); // Refresh stats after upload
    } catch (error) {
      setUploadStatus('Upload failed');
    }
  };

  return (
    <div className="container">
      <header>
        <h1>LogSentry SIEM Dashboard</h1>
      </header>
      
      <div className="card">
        <h2>Upload Log File</h2>
        <form onSubmit={handleUpload}>
          <input type="file" onChange={(e) => setFile(e.target.files[0])} />
          <button type="submit">Upload & Analyze</button>
        </form>
        {uploadStatus && <p>{uploadStatus}</p>}
      </div>

      <div className="stats-grid">
        <div className="card stat-card">
          <h3>Total Logs</h3>
          <div className="stat-number">{stats.total_logs}</div>
        </div>
        <div className="card stat-card">
          <h3>Unique IPs</h3>
          <div className="stat-number">{stats.unique_ips}</div>
        </div>
      </div>

      <div className="card">
        <h2>Top Endpoints</h2>
        <ul>
          {stats.top_endpoints.map((ep, idx) => (
            <li key={idx}><strong>{ep.endpoint}</strong> - {ep.count} requests</li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export default App;
