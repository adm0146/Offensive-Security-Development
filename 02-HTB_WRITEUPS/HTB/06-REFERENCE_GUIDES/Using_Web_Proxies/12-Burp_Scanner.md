# Section 12 — Burp Scanner

> Pro-only feature. Automated crawler + passive + active vulnerability scanner.
> No lab question in this section — questions are in Section 13.

---

## Three Scanning Modes

| Mode | What It Does | Speed |
|------|-------------|-------|
| **Crawl only** | Builds a site map by following links and submitting forms | Fast |
| **Passive Scan** | Analyzes already-captured responses for issues — sends no new requests | Fast |
| **Crawl and Audit** | Crawl + passive + active fuzzing for SQLi, XSS, command injection, etc. | Slow (hours) |

---

## Setting the Target Scope (Do This First)

Before scanning, define what's in scope so Burp doesn't waste time on out-of-scope URLs.

```
Target → Site map → right-click target URL → "Add to scope"
Target → Scope → review / add / remove items
```

**Exclude dangerous paths** (logout, delete actions, etc.):
```
Target → Scope → Exclude from scope → add paths like /logout, /delete
```

**Restrict all Burp features to scope only:**
When you add the first item, Burp asks if you want to ignore out-of-scope items. Click Yes — this prevents Burp from processing unrelated traffic and cluttering your history.

---

## Crawler — Build the Site Map

```
Dashboard → New Scan → select in-scope URL
Choose: "Crawl" (map only) or "Crawl and Audit" (map + vulnerability scan)

Scan Configuration tab → Select from library:
  "Crawl strategy - fastest"   = quick surface-level map
  "Crawl strategy - thorough"  = slower, more complete

Application login tab → add credentials if the app requires auth
→ authenticated crawl finds more pages than unauthenticated
```

**Important:** The crawler follows links only — it does NOT brute-force directories like ffuf/gobuster. To find unreferenced pages, run Intruder/Content Discovery separately, then add findings to scope.

View the site map result:
```
Target → Site map → see all discovered directories, files, endpoints
```

---

## Passive Scanner

**What it does:** Analyzes response content already captured — looks for issues like:
- Missing security headers (X-Frame-Options, Content-Security-Policy)
- Cookies without HttpOnly/Secure flags
- Potential DOM-based XSS
- Information disclosure in comments/errors

**What it does NOT do:** Send any new requests — pure analysis of what Burp has already seen.

**How to run:**
```
Proxy History → right-click request → "Do passive scan"
OR
Target Site map → right-click target → "Passively scan this target"

Results: Dashboard → Issue activity pane
OR: Dashboard → task → View details → Issue activity tab
```

**Confidence levels:**
- **Certain** = definitively confirmed
- **Firm** = strong evidence
- **Tentative** = possible but unverified

Focus on: **High severity + Certain/Firm confidence**

---

## Active Scanner

**What it does (in order):**
1. Crawl + fuzz for all pages (like dirb/ffuf)
2. Run passive scan on all found pages
3. Verify passive scan findings with active requests
4. Analyze JavaScript for vulnerabilities
5. Fuzz insertion points for SQLi, XSS, command injection, SSRF, XXE, etc.

**How to run:**
```
Dashboard → New Scan → Crawl and Audit
Scan Configuration → Audit checks → Select from library:
  "Audit checks - critical issues only"  ← use for quick high-severity scan
  "Audit checks - all issues"            ← thorough but very slow
```

**View active scan traffic:**
```
Logger tab → see every request the scanner sends
Dashboard → task → View details → Logger tab
```

**Filter results by severity/confidence:**
```
Dashboard → Issue activity → filter: High severity + Certain confidence
```

---

## Generating Reports

```
Target → Site map → right-click target → Issues → Report issues for this host
→ Select format (HTML recommended)
→ Select which severities to include
→ Export → open in browser
```

**What the report includes:**
- Issue name, severity, confidence
- Affected URL and parameter
- Proof-of-concept request/response
- Remediation advice

**Important:** Never submit a raw Burp report as a pentest deliverable. Use it as supplementary data / appendix. The main deliverable should be a manually written report explaining the impact and exploitability in context.

---

## Quick Reference

```
Start scan on one request: Proxy History → right-click → Scan
Passive scan only:         right-click → Do passive scan
Active scan (fast):        New Scan → Crawl and Audit → "critical issues only"
View results:              Dashboard → Issue activity
Export report:             Target → Site map → right-click → Issues → Report issues
```

---

## Exam Notes

- Burp Scanner = **Pro only** — Community Edition has no scanner
- Always set scope before scanning — prevents scanning out-of-scope hosts
- Crawler ≠ directory brute-forcer — it follows links, doesn't enumerate hidden paths
- Passive scan = no new requests (safe to run anytime) | Active scan = sends many requests (noisy)
- "Crawl and Audit" with "critical issues only" is the fastest useful active scan config
- High + Firm/Certain = findings you can confidently report; Tentative = needs manual verification
- The Logger tab shows every request the scanner makes — useful for debugging
- Reports are a starting point for client deliverables, not a finished deliverable
