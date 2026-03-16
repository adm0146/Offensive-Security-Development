# 🔎 Fingerprinting

## Overview

Fingerprinting extracts **technical details** about the technologies running on a target — web server software, versions, frameworks, CMS platforms, and WAFs. This tells you exactly what to look for when hunting for exploits.

---

## Fingerprinting Techniques

| Technique | What You Do | What You Get |
|---|---|---|
| **Banner Grabbing** | `curl -I target.com` | Server software, version, OS |
| **HTTP Header Analysis** | Inspect `Server`, `X-Powered-By`, `X-Redirect-By` headers | Frameworks, CMS, language info |
| **Probing for Responses** | Send crafted requests, trigger errors | Technology-specific error pages |
| **Page Content Analysis** | Check source, scripts, comments, paths | CMS indicators, version strings |

---

## Banner Grabbing with curl

### Core Command

```bash
curl -I <target>
```

The `-I` flag fetches **headers only** — no page content.

### Example — Following Redirects

```bash
curl -I inlanefreight.com
```

```
HTTP/1.1 301 Moved Permanently
Server: Apache/2.4.41 (Ubuntu)
Location: https://inlanefreight.com/
```

```bash
curl -I https://inlanefreight.com
```

```
HTTP/1.1 301 Moved Permanently
Server: Apache/2.4.41 (Ubuntu)
X-Redirect-By: WordPress
Location: https://www.inlanefreight.com/
```

```bash
curl -I https://www.inlanefreight.com
```

```
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
Link: <https://www.inlanefreight.com/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8
```

### What to Look For in Headers

| Header | What It Reveals | Example |
|---|---|---|
| **Server** | Web server software + version | `Apache/2.4.41 (Ubuntu)` |
| **X-Powered-By** | Backend language/framework | `PHP/7.4`, `Express` |
| **X-Redirect-By** | What is handling redirects | `WordPress` |
| **Link** | API endpoints, CMS indicators | `wp-json` = WordPress |
| **Set-Cookie** | Session tech, framework clues | `PHPSESSID` = PHP, `JSESSIONID` = Java |
| **X-Frame-Options** / **CSP** | Security header config | Missing = potential misconfig |

---

## WAF Detection with wafw00f

Before deeper fingerprinting, check if a WAF is in place — it can block your probes.

### Install

```bash
pip3 install git+https://github.com/EnableSecurity/wafw00f
```

### Run

```bash
wafw00f inlanefreight.com
```

### Example Output

```
[*] Checking https://inlanefreight.com
[+] The site https://inlanefreight.com is behind Wordfence (Defiant) WAF.
[~] Number of requests: 2
```

**If a WAF is detected:** Adapt your techniques — some probes may be blocked or rate-limited. Note the WAF type for potential bypass research.

---

## Nikto — Automated Fingerprinting + Vuln Scanning

### Install (pre-installed on Kali/Pwnbox)

```bash
sudo apt update && sudo apt install -y perl
git clone https://github.com/sullo/nikto
cd nikto/program && chmod +x ./nikto.pl
```

### Fingerprint-Only Scan

```bash
nikto -h inlanefreight.com -Tuning b
```

| Flag | Purpose |
|---|---|
| `-h` | Target host |
| `-Tuning b` | Run **only** Software Identification modules (skip vuln checks) |

### What Nikto Finds

| Finding | What It Means |
|---|---|
| `Server: Apache/2.4.41` | Web server version — check if outdated |
| `WordPress installation found` | CMS identified — check for WP-specific exploits |
| `/wp-login.php` | Login portal found — brute-force target |
| `/license.txt` | May reveal software versions |
| Missing `Strict-Transport-Security` | No HSTS — potential downgrade attack |
| Missing `X-Content-Type-Options` | MIME sniffing possible |
| `Apache/2.4.41 appears outdated` | Current is 2.4.59+ — known CVEs may apply |

---

## Other Fingerprinting Tools

| Tool | Type | Best For |
|---|---|---|
| **Wappalyzer** | Browser extension | Quick tech stack ID — CMS, frameworks, analytics |
| **BuiltWith** | Web service | Detailed technology reports |
| **WhatWeb** | CLI | Signature-based fingerprinting from terminal |
| **Nmap** | CLI | Service/OS fingerprinting with NSE scripts |
| **Netcraft** | Web service | Hosting provider, tech stack, security posture |

---

## Fingerprinting Workflow

```
1. curl -I target.com          → Server, version, headers
2. Follow redirects             → X-Redirect-By, X-Powered-By
3. wafw00f target.com           → WAF detection
4. nikto -h target.com -Tuning b → Automated fingerprinting
5. Wappalyzer (browser)         → Full tech stack overview
```

---

## Key Takeaways

- **`curl -I` is step one** — always grab headers before running heavier tools
- **Follow redirects** — each hop can leak new info (`X-Redirect-By: WordPress`)
- **Check for WAFs first** with `wafw00f` — a WAF can block your scans
- **Nikto `-Tuning b`** runs fingerprinting only without full vuln scanning
- **Outdated software versions** in headers = check for known CVEs immediately
- **WordPress indicators**: `wp-json`, `wp-login.php`, `X-Redirect-By: WordPress`, `wp-content` paths

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
