from io import StringIO, BytesIO
import csv
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

def generate_csv_report(alerts):
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'Timestamp', 'IP Address', 'Attack Type', 'Severity', 'Threat Score', 'Description'])
    for alert in alerts:
        cw.writerow([
            alert.id, 
            alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'), 
            alert.ip_address, 
            alert.attack_type, 
            alert.severity, 
            alert.threat_intel_score if alert.threat_intel_score is not None else 'N/A', 
            alert.description
        ])
    return si.getvalue()

def generate_pdf_report(alerts):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
    elements = []
    
    styles = getSampleStyleSheet()
    elements.append(Paragraph("LogSentry Security Incident Report", styles['Title']))
    elements.append(Spacer(1, 12))
    
    data = [['Time', 'Attacker IP', 'Attack Type', 'Severity', 'Threat Score']]
    for alert in alerts:
        score = str(alert.threat_intel_score) if alert.threat_intel_score is not None else 'N/A'
        data.append([
            alert.timestamp.strftime('%Y-%m-%d %H:%M'),
            alert.ip_address,
            alert.attack_type,
            alert.severity,
            score
        ])
        
    t = Table(data, colWidths=[120, 100, 150, 80, 80])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e293b")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor("#f8fafc")),
        ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('TEXTCOLOR', (0,1), (-1,-1), colors.black),
    ]))
    
    elements.append(t)
    doc.build(elements)
    buffer.seek(0)
    return buffer
