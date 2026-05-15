# 🔎 Fingerprinting

## Overview

Fingerprinting extracts technical details about the technologies running on a target. This includes the web server software and version, backend frameworks, Content Management System (CMS) platforms, and Web Application Firewalls (WAFs). Knowing what software the target runs tells you exactly what to look for when hunting exploits.

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
> Sends a HEAD request to the target and prints only the response headers. `-I` stands for "headers only" — no page body is downloaded. Replace `<target>` with your IP or domain.

The `-I` flag fetches headers only — no page content.

### Example — Following Redirects

```bash
curl -I inlanefreight.com
```
> First hop — returns a 301 redirect and reveals the web server version (`Apache/2.4.41 (Ubuntu)`). Follow each redirect to the next hop to collect more headers.

```
HTTP/1.1 301 Moved Permanently
Server: Apache/2.4.41 (Ubuntu)
Location: https://inlanefreight.com/
```

```bash
curl -I https://inlanefreight.com
```
> Second hop — `X-Redirect-By: WordPress` leaks the CMS handling the redirect. This header would not appear on a non-WordPress site.

```
HTTP/1.1 301 Moved Permanently
Server: Apache/2.4.41 (Ubuntu)
X-Redirect-By: WordPress
Location: https://www.inlanefreight.com/
```

```bash
curl -I https://www.inlanefreight.com
```
> Final hop — `wp-json` in the `Link` header confirms WordPress. The `Content-Type` confirms HTML is being served.

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

Before running deeper fingerprinting, check whether a WAF is in place. A WAF can block or distort your probe results.

### Install

```bash
pip3 install git+https://github.com/EnableSecurity/wafw00f
```
> Installs `wafw00f` directly from its GitHub repository using pip3. Run this only if the tool is not already installed.

### Run

```bash
wafw00f inlanefreight.com
```
> Detects the Web Application Firewall (WAF) in front of the target by sending known probe requests and analyzing the responses. Replace the domain with your target. If a WAF is detected, adapt your scanning techniques — some probes may be blocked or rate-limited.

### Example Output

```
[*] Checking https://inlanefreight.com
[+] The site https://inlanefreight.com is behind Wordfence (Defiant) WAF.
[~] Number of requests: 2
```

If a WAF is detected, adapt your techniques. Some probes may be blocked or rate-limited. Note the WAF type so you can research bypass methods.

---

## Nikto — Automated Fingerprinting + Vuln Scanning

### Install (pre-installed on Kali/Pwnbox)

```bash
sudo apt update && sudo apt install -y perl
git clone https://github.com/sullo/nikto
cd nikto/program && chmod +x ./nikto.pl
```
> Installs the Perl dependency, clones the nikto repository, and makes the main script executable. Kali Linux has nikto pre-installed — only run this if the command is missing.

### Fingerprint-Only Scan

```bash
nikto -h inlanefreight.com -Tuning b
```
> Runs nikto against the target with `-Tuning b` to limit the scan to Software Identification modules only. This fingerprints the server without running a full vulnerability scan. Swap the hostname for your target.

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

- `curl -I` is step one. Always grab headers before running heavier tools.
- Follow redirects — each hop can leak new information (for example, `X-Redirect-By: WordPress`).
- Check for WAFs first with `wafw00f` — a WAF can block or alter your scans.
- `nikto -Tuning b` runs fingerprinting modules only, without a full vulnerability scan.
- Outdated software versions in headers mean you should check for known CVEs immediately.
- WordPress indicators: `wp-json`, `wp-login.php`, `X-Redirect-By: WordPress`, and `wp-content` paths.

---

## CMS Identification Cheat Sheet

| CMS | Header / Source Indicators |
|---|---|
| **WordPress** | `wp-content`, `wp-json`, `wp-login.php`, `X-Redirect-By: WordPress` |
| **Joomla** | `/administrator/`, `com_content`, random hex session cookie, aggressive cache-busting headers |
| **Drupal** | `/node/`, `Drupal.settings`, `sites/default` |
| **Magento** | `/skin/frontend/`, `Mage.Cookies` |

---

## Walkthrough — Fingerprinting HTB Exercise

### Setup

Question gave VHosts: `app.inlanefreight.local` and `dev.inlanefreight.local`

```bash
echo "<TARGET_IP>  app.inlanefreight.local dev.inlanefreight.local" | sudo tee -a /etc/hosts
```
> Adds both discovered VHosts to `/etc/hosts` at once so tools can resolve them. Replace `<TARGET_IP>` with the actual lab IP.

### Identifying the CMS on app.inlanefreight.local

```bash
curl -I http://app.inlanefreight.local
```
> Fetches headers from the app VHost. Look for `X-Redirect-By`, `X-Powered-By`, and the cookie format to identify the CMS.

Check headers for `X-Redirect-By`, `X-Powered-By`, and cookie format. Also check page source:

```bash
curl -s http://app.inlanefreight.local | grep -i "wordpress\|joomla\|drupal\|wp-content\|wp-json"
```
> Downloads the page body and searches for CMS-specific strings. A match on `wp-content` or `wp-json` means WordPress. `com_content` or `components/com_` means Joomla. Adjust the grep pattern for whatever CMS you suspect.

Answer: Joomla — identified by the random hex session cookie and aggressive anti-caching headers.

### Identifying the OS on dev.inlanefreight.local

```bash
curl -I http://dev.inlanefreight.local
```
> Fetches headers from the dev VHost. The OS is revealed in the `Server` header in parentheses after the version string — `Apache/2.4.41 (Ubuntu)` means Ubuntu.

```
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: 02a93f6429c54209e06c64b77be2180d=nd451vqcaoqgb0l6e69d0ddbh0; path=/; HttpOnly
Expires: Wed, 17 Aug 2005 00:00:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
```

Answer: Ubuntu — from `Apache/2.4.41 (Ubuntu)` in the `Server` header. The operating system is in the parentheses after the version string.

### Header Analysis

| Header | What It Told Us |
|---|---|
| `Server: Apache/2.4.41 (Ubuntu)` | Web server + version + OS |
| `Set-Cookie: 02a93f...` with `HttpOnly` | Server-side sessions, cookie not accessible via JS |
| `Expires: 2005` + `Cache-Control: no-store` | Anti-caching — dynamic content (CMS indicator) |

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
