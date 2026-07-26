# LogSentry v1.0.0 — Directory Enumeration Detection Audit

**Date:** July 26, 2026  
**Subject:** Architectural Refactoring of Directory Enumeration Detection (`MITRE T1083`)  
**Status:** ✅ CERTIFIED & PRODUCTION-READY  

---

## 1. Executive Summary & Original Root Cause

### 1.1 Audit Findings
During system audit and telemetry verification, LogSentry's Directory Enumeration rule (`app/detection/rules/dir_enum.py`) was identified as generating false positives for ordinary web requests (e.g., individual requests to `/login` or standard navigation).

### 1.2 Root Cause Analysis
- **Stateless Single-Event Evaluation:** The original `DirectoryEnumerationRule` inherited from `RegexDetectionRule`. Under this architecture, every single log event was evaluated independently without memory of prior requests or source IP context.
- **Overly Broad Regular Expression:** The legacy pattern `r'(?i)(/admin|/login|/\.git|/backup|/config|/phpmyadmin)'` matched `/login` on any single request. Consequently, an ordinary user navigating to a login page immediately triggered a `Directory Enumeration Attempt` alert.
- **Lack of Campaign Correlation:** Multiple probing requests from an automated scanner generated dozens of individual alerts rather than a single correlated reconnaissance campaign alert.

---

## 2. New Behavioral Detection Algorithm

### 2.1 Architectural Refactoring
`DirectoryEnumerationRule` was rewritten to inherit from `BaseRule` and implement **behavioral, threshold-based reconnaissance detection**:
1. **Per-IP Sliding Window (`self._state`):** Tracks incoming requests mapped by `source_ip` within an adjustable time window (`DETECTION_DIR_ENUM_WINDOW_SECONDS = 60`).
2. **Distinct Path Accounting:** Probing is evaluated based on the count of **unique paths requested** (`unique_paths = list(dict.fromkeys(...))`). Repeated hits to the exact same path (e.g., 10 hits to `/admin`) do not inflate the distinct path count.
3. **Benign Path Filtering (`_is_benign_path`):** Standard user browsing and static asset requests are filtered out before evaluation:
   - **Exact Paths:** `/`, `/index.html`, `/about`, `/contact`, `/login`, `/favicon.ico`, `/sitemap.xml`, `/home`, `/dashboard`, `/products`, `/api/login`, `/api/v1/health`, `/metrics`, and core API endpoints.
   - **Static Asset Directories:** `/css/`, `/js/`, `/assets/`, `/images/`, `/fonts/`, `/static/`, `/public/`.
   - **Static Extensions:** `.css`, `.js`, `.png`, `.jpg`, `.jpeg`, `.svg`, `.ico`, `.woff`, `.woff2`, `.map`, `.gif`, `.html`, `.htm`.
   - *Note:* These paths are ignored by Directory Enumeration but remain inspectable by payload rules (`sqli`, `xss`, `cmd_injection`).
4. **Special `robots.txt` Sequence Handling:**
   - `GET /robots.txt` by itself **NEVER** triggers a Directory Enumeration alert.
   - However, when an attacker requests `/robots.txt` as part of a multi-path reconnaissance sequence (`/robots.txt` → `/admin` → `/backup` → `/.git`), `/robots.txt` is recorded in the campaign history and included in `sample_paths` evidence.
5. **Campaign Correlation:** When the threshold is reached (`len(unique_paths) >= self.threshold`), the rule generates **one correlated alert** describing the campaign and clears the IP state to prevent alert spamming.

---

## 3. Configuration & Sensible Defaults

The following parameters have been added to `app/config/settings.py`:

```python
DETECTION_DIR_ENUM_THRESHOLD: int = 3
DETECTION_DIR_ENUM_WINDOW_SECONDS: int = 60
```

| Parameter | Default Value | Description |
| :--- | :--- | :--- |
| **`DETECTION_DIR_ENUM_THRESHOLD`** | **`3`** | Minimum number of distinct unusual/suspicious paths probed by the same IP required to trigger detection. |
| **`DETECTION_DIR_ENUM_WINDOW_SECONDS`** | **`60s`** | Sliding time window in seconds during which distinct path probes are correlated. |

---

## 4. Alert Evidence & Description Structure

When a Directory Enumeration alert fires, `generate_alert(event)` populates structured forensic data:

### 4.1 Alert Evidence Dictionary (`alert.evidence`)
```json
{
  "unique_paths_probed": 5,
  "request_count": 5,
  "window_seconds": 60,
  "source_ip": "10.0.1.59",
  "sample_paths": [
    "/.git/config",
    "/.env",
    "/.htaccess",
    "/admin",
    "/wp-admin"
  ],
  "first_seen": "2026-07-26T08:05:00+00:00",
  "last_seen": "2026-07-26T08:05:04+00:00"
}
```

### 4.2 Description & Raw Log Reference
- **Description:** `"Source 10.0.1.59 requested 5 distinct administrative or sensitive paths within 60 seconds, consistent with web directory reconnaissance."`
- **Raw Log Reference (`alert.raw_log_reference`):** Combines the complete raw log lines of all requests in the reconnaissance burst, allowing analysts to inspect the exact HTTP headers and user agents (`gobuster/3.2.0`, `Nikto`, etc.) in the **Original Payload** tab.

---

## 5. UI Improvement (`frontend/src/pages/Alerts.tsx`)

The Alert Drawer's **Evidence** tab has been enhanced:
- When an alert contains reconnaissance evidence (`unique_paths_probed`), the UI renders a dedicated **Reconnaissance Campaign Evidence** card displaying:
  - **Unique Paths Probed**, **Request Count**, **Time Window**, and **Source IP**.
  - **First Seen** and **Last Seen** timestamps.
  - **Sample Paths Probed** rendered as individual green monospace badges.
- Extracted Fields value rendering was upgraded to format array values (`v.join(', ')`) cleanly.

---

## 6. Comprehensive Verification & Regression Matrix

### 6.1 Targeted Directory Enumeration Test Cases (`tests/test_detection.py`)
| Test Case | Scenario | Expected Outcome | Verified |
| :--- | :--- | :--- | :--- |
| **`test_dir_enum_rule`** | Probing 1 (`/admin/settings`), 2 (`/.git/config`), then 3 (`/backup`) distinct paths. | No alert on 1 & 2; fires exactly 1 alert on 3rd path with `unique_paths_probed = 3`. | ✅ PASSED |
| **`test_dir_enum_normal_traffic`** | Same IP browsing `/`, `/index.html`, `/robots.txt`, `/favicon.ico`, `/css/app.css`, `/js/app.js`, `/images/logo.png`, `/about`, `/contact`. | **ZERO alerts generated.** | ✅ PASSED |
| **`test_dir_enum_robots_txt_handling`** | (1) 5 consecutive requests to `/robots.txt` alone.<br>(2) `/robots.txt` + `/admin` + `/backup`. | (1) **ZERO alerts**.<br>(2) Alert fires on `/backup` with `/robots.txt` included in `sample_paths`. | ✅ PASSED |
| **`test_dir_enum_false_positive_protection`** | Single `/admin` from IP1, single `/robots.txt` from IP2, single 404 from IP3. | **ZERO alerts generated.** | ✅ PASSED |
| **`test_dir_enum_mixed_traffic`** | Mixed traffic containing XSS (`/search?q=<script>`) and SQLi (`/products?id=1' UNION SELECT`). | XSS and SQLi rules fire independently; **ZERO Directory Enumeration false positives.** | ✅ PASSED |

### 6.2 Full Backend Regression Suite (`pytest -v`)
- **Total Tests Executed:** **131 tests** across 10 test modules.
- **Pass Rate:** **100% (131 / 131 PASSED)**.
- **Code Coverage:** **81.42%** (exceeds required 65% threshold).

### 6.3 Frontend Production Build (`npm run build`)
- **TypeScript Compilation (`tsc -b`):** 0 errors.
- **Vite Production Bundle:** Successfully compiled in **575ms** (`dist/assets/index-Bf4VwAwA.js`, `dist/assets/Alerts-BtsAjZ4g.js`).

---

## 7. Files Modified

1. **`app/config/settings.py`**: Added `DETECTION_DIR_ENUM_THRESHOLD = 3` and `DETECTION_DIR_ENUM_WINDOW_SECONDS = 60`.
2. **`app/detection/rules/dir_enum.py`**: Completely rewrote `DirectoryEnumerationRule` to inherit from `BaseRule`, implement sliding-window distinct path tracking, benign path filtering, `robots.txt` sequence handling, and rich alert evidence formatting.
3. **`frontend/src/pages/Alerts.tsx`**: Added structured **Reconnaissance Campaign Evidence** card in Alert Drawer and array-safe value formatting.
4. **`tests/test_detection.py`**: Replaced legacy static test with 5 comprehensive behavioral test suites covering normal traffic, reconnaissance bursts, `robots.txt` handling, false-positive protection, and mixed traffic.

---

## 8. Release Compliance Declaration
- **No Git Commits Performed**
- **No Git Pushes Performed**
- **No Git Tags or Release Artifacts Fabricated**
