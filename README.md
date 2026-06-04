# LogSentry 🛡️

LogSentry is an AI-powered Security Information and Event Management (SIEM) dashboard designed to ingest server logs, detect malicious activity (like SQL Injections, XSS, Path Traversals, and Brute Force attacks), and automatically enrich alerts with Threat Intelligence and AI-driven remediation steps.

## Features ✨
- **Log Ingestion & Parsing**: Upload raw Apache/Nginx logs, and the system automatically parses and stores them.
- **Real-Time Threat Detection**: Pattern-based detection for web vulnerabilities and threshold-based detection for Brute Force attempts.
- **Threat Intelligence**: Integrates with the AbuseIPDB API to score and contextually evaluate malicious IP addresses.
- **AI SOC Analyst**: Integrates with Google Gemini to act as a virtual SOC Analyst. With the click of a button, it analyzes an alert and provides an explanation of the attack along with actionable remediation steps.
- **Reporting & Exports**: Generate detailed CSV and PDF incident reports with one click.
- **Interactive Dashboard**: A premium, dark-mode, glassmorphic UI complete with dynamic charts.

## Tech Stack 🛠️
- **Backend**: Python, Flask, SQLAlchemy (SQLite)
- **Frontend**: HTML5, Vanilla JS, CSS3, Chart.js (Served natively via Flask static assets)
- **APIs**: AbuseIPDB (Threat Intel), Google Gemini (Generative AI Analysis)
- **PDF Generation**: ReportLab

## Quick Start 🚀

### 1. Prerequisites
- Python 3.8+ installed on your system.

### 2. Setup the Environment
Navigate to the `backend` directory and install the requirements:
```bash
cd backend
python -m venv venv
venv\Scripts\activate  # On Windows (use `source venv/bin/activate` on Mac/Linux)
pip install -r requirements.txt
```

### 3. Configure API Keys
Create a `.env` file in the `backend` directory (you can copy `.env.example`):
```bash
# backend/.env
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
GEMINI_API_KEY=your_gemini_key_here
```

### 4. Run the Application
Start the Flask application from the `backend` directory:
```bash
python app.py
```

### 5. View the Dashboard
Open your web browser and navigate to:
[http://127.0.0.1:5000/](http://127.0.0.1:5000/)

Upload the provided `sample_malicious.log` file from the root directory to see the dashboard populate with data, charts, and alerts!

## Project Structure 📁
- `/backend`: Contains the Flask server, DB models, AI logic, Threat Intel integrations, and the Static UI.
  - `/static`: Contains the `index.html` frontend dashboard.
  - `/database`: Contains SQLAlchemy models.
- `/frontend`: Contains an experimental React/Vite frontend structure.
- `sample_malicious.log`: A test log file containing various cyber attacks for testing.
