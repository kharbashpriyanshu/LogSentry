# LogSentry SIEM — Enterprise Server & Infrastructure Connection Guide

This guide details how **LogSentry SIEM** connects to and continuously ingests security telemetry from any corporate infrastructure: **Linux servers, Windows Active Directory Domain Controllers, firewalls, network switches, Kubernetes clusters, and multi-cloud platforms (AWS/Azure/GCP)**.

---

## 1. Enterprise Architecture Overview

Modern enterprise environments combine **agentless network streaming**, **lightweight host forwarders**, and **cloud-native serverless pipelines**.

```mermaid
flowchart TD
    subgraph Corporate Network & Data Center
        FW[Firewalls & Routers<br/>Palo Alto / Fortinet / Cisco] -->|UDP / TCP 1514 Syslog| LB
        LNX[Linux Server Clusters<br/>RHEL / Ubuntu / Nginx] -->|rsyslog / Vector HTTPS| LB
        WIN[Windows Servers & AD DC<br/>EVTX 4624, 4625, 4688, 4104] -->|Winlogbeat / Shipper HTTPS| LB
        K8S[Kubernetes Pods<br/>FluentBit DaemonSet] -->|JSON HTTPS API| LB
    end

    subgraph Multi-Cloud Infrastructure
        AWS[AWS CloudTrail & VPC Flow] -->|Lambda / S3 SQS| LB
        AZ[Azure Activity & NSG Logs] -->|Event Hub / Webhook| LB
        GCP[GCP Cloud Audit Logs] -->|Pub/Sub Push| LB
    end

    LB[LogSentry Ingestion Gateway / Reverse Proxy] --> Q[Streaming Buffer Queue<br/>50,000 Capacity]
    
    subgraph LogSentry Core Engine
        Q --> ENG[Sigma Rules & Regex Detection Engine]
        ENG --> DB[(Encrypted Forensics DB)]
        ENG --> AI[AI SOC Incident Analyst]
        ENG --> SOAR[SOAR Active Response Engine]
    end

    SOAR -->|Automated IP Block| WAF[Cloudflare / AWS WAF / iptables]
    SOAR -->|Urgent Dispatch| PAGER[Slack / PagerDuty / Jira]
    ENG --> UI[Real-time SOC Dashboard & WebSockets]
```

---

## 2. Port & Firewall Requirements

To permit telemetry to reach your LogSentry cluster, open the following ports on the LogSentry host or network perimeter:

| Port | Protocol | Purpose | Source Assets |
| :--- | :--- | :--- | :--- |
| **8000 / 443** | TCP (HTTPS) | LogSentry Ingestion API & REST endpoints | Linux/Windows shippers, K8s, Cloud functions |
| **1514 / 514** | UDP & TCP | RFC 5424 & RFC 3164 Syslog | Network appliances, firewalls, routers, switches |
| **6514** | TCP (mTLS) | Encrypted TLS Syslog forwarder | PCI-DSS / HIPAA high-compliance environments |
| **5173 / 80** | TCP (HTTP/WS) | SOC Analyst Browser UI & WebSocket alerts | SOC Analysts & Threat Hunters |

---

## 3. How to Connect Any Infrastructure Asset

### Method 1: Linux Production Servers (Ubuntu, RHEL, CentOS, Debian, SUSE)

Linux servers can be connected using the native `rsyslog` service or LogSentry's universal shipper.

#### Option A: Native Rsyslog (Zero Software Installation)
1. Edit `/etc/rsyslog.d/99-logsentry.conf` on each Linux host:
   ```text
   # Forward auth.log (SSH brute force, sudo escalation) to LogSentry
   auth,authpriv.* action(type="omfwd" target="siem.company.internal" port="1514" protocol="tcp" template="RSYSLOG_SyslogProtocol23Format")
   
   # Forward web server access logs
   local6.* action(type="omfwd" target="siem.company.internal" port="1514" protocol="tcp" template="RSYSLOG_SyslogProtocol23Format")
   ```
2. Restart the logging daemon:
   ```bash
   sudo systemctl restart rsyslog
   ```

#### Option B: LogSentry Universal Shipper as a Systemd Daemon
Run LogSentry's native lightweight forwarder:
```bash
# Start as a daemon watching Nginx access and authentication logs
python3 scripts/logsentry_shipper.py \
  --file /var/log/nginx/access.log \
  --parser nginx \
  --server https://siem.company.internal:8000 \
  --tenant-id prod-us-east
```

---

### Method 2: Windows Server & Active Directory Domain Controllers

Windows servers record crucial identity and execution logs (Kerberos, Process Launch, PowerShell).

#### Option A: Elastic Winlogbeat (Recommended for Enterprise)
1. Place `deploy/collectors/winlogbeat_logsentry.yml` into `C:\Program Files\Winlogbeat\winlogbeat.yml`.
2. Configure the destination URL to point to your LogSentry cluster:
   ```yaml
   output.http:
     enabled: true
     url: "https://siem.company.internal:8000/api/v1/detection/analyze"
     headers:
       Authorization: "Bearer COMPANY_SIEM_API_KEY"
   ```
3. Install and start as a Windows Service:
   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File .\install-service-winlogbeat.ps1
   Start-Service winlogbeat
   ```

#### Option B: LogSentry Windows Host Agent
Run the native agent on any laptop or server:
```powershell
.\venv\Scripts\python.exe scripts/laptop_agent.py --live-powershell
```

---

### Method 3: Network Firewalls & Appliances (Agentless Syslog)

Corporate security appliances emit logs continuously over RFC 5424 Syslog.

* **Palo Alto Networks (PAN-OS):**
  1. Go to **Device** -> **Server Profiles** -> **Syslog**.
  2. Click **Add**: Set Server to LogSentry IP, Port `1514`, Format `BSD` or `IETF (RFC 5424)`.
  3. Go to **Objects** -> **Log Forwarding** -> Add rule to forward Traffic, Threat, and WildFire logs to the profile.

* **Fortinet (FortiGate):**
  Run in the FortiGate CLI:
  ```text
  config log syslogd setting
      set status enable
      set server "10.0.1.50"
      set port 1514
      set mode udp
      set facility local7
  end
  ```

* **pfSense / OPNsense:**
  1. Navigate to **Status** -> **System Logs** -> **Settings**.
  2. Check **Enable Remote Logging**.
  3. Enter LogSentry IP with port `1514`. Check *Firewall Events*, *User Authentication*, and *DHCP Service*.

---

### Method 4: Multi-Cloud Infrastructure (AWS, Azure, GCP)

#### AWS CloudTrail & VPC Flow Logs
1. Configure AWS CloudTrail to write events to an Amazon S3 bucket.
2. Attach an **Amazon EventBridge** or **AWS Lambda** rule triggered on `ObjectCreated`:
   ```python
   # Lightweight forwarder snippet
   import urllib.request, gzip, json
   def lambda_handler(event, context):
       # Stream event batch to LogSentry
       req = urllib.request.Request(
           "https://siem.company.internal:8000/api/v1/detection/analyze",
           data=json.dumps({"event": event_payload}).encode("utf-8"),
           headers={"Content-Type": "application/json", "Authorization": "Bearer AWS_INGEST_KEY"}
       )
       urllib.request.urlopen(req)
   ```
3. LogSentry parses unauthorized IAM policy alterations, root account logons, and cross-region egress anomalies via [app/parsers/cloudtrail.py](file:///d:/Project%20Resume/LogSentry/app/parsers/cloudtrail.py).

---

### Method 5: Kubernetes & Container Clusters (EKS, GKE, On-Prem)

Deploy **FluentBit** or **Vector** as a Kubernetes `DaemonSet` across all nodes.
1. Mount `/var/log/containers/*.log` into the FluentBit pod.
2. In the FluentBit `OUTPUT` section:
   ```text
   [OUTPUT]
       Name          http
       Match         kube.*
       Host          siem.company.internal
       Port          8000
       URI           /api/v1/detection/analyze
       Header        Authorization Bearer K8S_PROD_TOKEN
       Format        json
   ```

---

## 4. Multi-Tenancy & MSSP Client Isolation

When hosting LogSentry for multiple subsidiaries, clients, or branches:
* Every request accepts a `tenant_id` (e.g. `client-alpha`, `client-bravo`, `finance-dept`).
* The LogSentry database partitions alerts and forensics cases by `tenant_id`:
  ```json
  {
    "event": {
      "raw_log": "...",
      "tenant_id": "client-acme-corp"
    }
  }
  ```
* SOC Analysts only see logs and indicators relevant to their authorized tenant workspace.
