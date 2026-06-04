from flask import Flask, request, jsonify, Response, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import re
from datetime import datetime
from database.models import db, LogEntry, Alert
from detection import analyze_log_entry, detect_brute_force
from threat_intel import check_abuseipdb
from reporting import generate_csv_report, generate_pdf_report
from ai_analyst import analyze_alert_with_ai
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'), override=True)

app = Flask(__name__, static_folder='static', static_url_path='/')
CORS(app) # Allow React frontend to communicate with Flask

@app.route('/')
def index():
    return app.send_static_file('index.html')

# Configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///logsentry.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()

# Robust regex for Common and Combined Log Formats
# Format: 192.168.1.10 - - [12/Jun/2026:10:00:00] "GET /login HTTP/1.1" 200 1234 "referer" "user-agent"
APACHE_REGEX = r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<endpoint>[^\s]+)[^"]*"\s+(?P<status>\d+)'

def parse_log_line(line):
    match = re.match(APACHE_REGEX, line)
    if match:
        data = match.groupdict()
        try:
            # Note: A real parser will handle datetime properly, this is a simplified version for Phase 1
            dt = datetime.strptime(data['timestamp'].split(' ')[0], '%d/%b/%Y:%H:%M:%S')
        except:
            dt = datetime.utcnow()
            
        return {
            'ip_address': data['ip'],
            'method': data['method'],
            'endpoint': data['endpoint'],
            'status_code': int(data['status']),
            'timestamp': dt,
            'raw_log': line.strip()
        }
    return None

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # For demo purposes: Clear existing database on new upload
        db.session.query(LogEntry).delete()
        db.session.query(Alert).delete()
        db.session.commit()
        
        # Parse and store logs
        entries = []
        with open(filepath, 'r') as f:
            for line in f:
                parsed_data = parse_log_line(line)
                if parsed_data:
                    entry = LogEntry(**parsed_data)
                    db.session.add(entry)
                    entries.append(entry)
                    
                    # Phase 3 & 6: Inline Threat Detection & Intel
                    alert_data = analyze_log_entry(entry)
                    if alert_data:
                        score, report = check_abuseipdb(entry.ip_address)
                        alert = Alert(
                            ip_address=entry.ip_address,
                            attack_type=alert_data['attack_type'],
                            severity=alert_data['severity'],
                            description=alert_data['description'],
                            timestamp=entry.timestamp,
                            threat_intel_score=score,
                            threat_intel_report=report
                        )
                        db.session.add(alert)
                        
        db.session.commit()
        
        # Phase 3: Post-processing Threat Detection (Brute Force)
        detect_brute_force(db, LogEntry, Alert)
        
        return jsonify({"message": f"Successfully processed {len(entries)} log entries."}), 200

@app.route('/api/stats', methods=['GET'])
def get_stats():
    # Dashboard should show: Total Logs, Unique IPs, Most Requested Endpoints
    total_logs = db.session.query(LogEntry).count()
    unique_ips = db.session.query(LogEntry.ip_address).distinct().count()
    
    # Simple counting for endpoints
    from sqlalchemy import func
    top_endpoints = db.session.query(
        LogEntry.endpoint, func.count(LogEntry.id).label('count')
    ).group_by(LogEntry.endpoint).order_by(func.count(LogEntry.id).desc()).limit(5).all()
    
    endpoints_data = [{"endpoint": e[0], "count": e[1]} for e in top_endpoints]
    
    # Alert Stats
    total_alerts = db.session.query(Alert).count()
    recent_alerts = db.session.query(Alert).order_by(Alert.timestamp.desc()).limit(10).all()
    alerts_data = [a.to_dict() for a in recent_alerts]
    
    return jsonify({
        "total_logs": total_logs,
        "unique_ips": unique_ips,
        "top_endpoints": endpoints_data,
        "total_alerts": total_alerts,
        "recent_alerts": alerts_data
    })

@app.route('/api/chart-data', methods=['GET'])
def get_chart_data():
    from sqlalchemy import func
    
    # Severity distribution
    severity_counts = db.session.query(
        Alert.severity, func.count(Alert.id)
    ).group_by(Alert.severity).all()
    
    severity_data = {
        "labels": [s[0] for s in severity_counts],
        "values": [s[1] for s in severity_counts]
    }
    
    # Attack Type distribution
    attack_counts = db.session.query(
        Alert.attack_type, func.count(Alert.id)
    ).group_by(Alert.attack_type).all()
    
    attack_data = {
        "labels": [a[0] for a in attack_counts],
        "values": [a[1] for a in attack_counts]
    }
    
    return jsonify({
        "severity": severity_data,
        "attacks": attack_data
    })

@app.route('/api/export/csv', methods=['GET'])
def export_csv():
    alerts = db.session.query(Alert).order_by(Alert.timestamp.desc()).all()
    csv_data = generate_csv_report(alerts)
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=logsentry_report.csv"}
    )

@app.route('/api/export/pdf', methods=['GET'])
def export_pdf():
    alerts = db.session.query(Alert).order_by(Alert.timestamp.desc()).all()
    pdf_buffer = generate_pdf_report(alerts)
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name='logsentry_report.pdf',
        mimetype='application/pdf'
    )

@app.route('/api/analyze/<int:alert_id>', methods=['GET'])
def analyze_alert(alert_id):
    alert = db.session.query(Alert).get(alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
        
    ai_response = analyze_alert_with_ai(alert)
    return jsonify({"analysis": ai_response})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
