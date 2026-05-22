# 00 — Documentation & Reporting · EXAM CHEATSHEET

> Fast reference for the whole module (§01–08). Through-line:
> **Document as you test → organized notes → professional report → QA → deliver.** The report is what the client pays for.

---

## 0 · Assessment Setup (run at START of every engagement)

```bash
# Create project directory structure
mkdir -p CLIENT-IPT/{Admin,Deliverables,Evidence/{Findings,Scans/{Vuln,Service,Web,'AD Enumeration'},Notes,OSINT,Wireless,'Logging output','Misc Files'},Retest}

# Start Tmux with logging
tmux new -s pentest
# [Ctrl]+[B] then [Shift]+[P] to start logging
```

### Start notification email (send day 1)

Include: tester name, assessment type/scope, source IP, testing dates, primary + secondary contact info (email + phone).

### Stop notification (send end of each day)

Include: high-level summary of activities, any critical findings discovered, reiterate report delivery timeline.

---

## 1 · Notetaking Structure

| Category | What Goes Here |
|----------|---------------|
| Attack Path | Full compromise chain with screenshots + command output |
| Credentials | All compromised creds/secrets (centralized) |
| Findings | Subfolder per finding — narrative + evidence |
| Activity Log | Timestamped log of all testing activities |
| Payload Log | Payloads used, file hashes, upload paths, cleanup status |
| Scoping Info | In-scope IPs/CIDRs, URLs, provided creds |
| Service Enum | Services investigated, failed attempts, promising leads |
| Web App Research | Interesting apps, default creds tried |
| AD Enum | Step-by-step AD enumeration performed |
| Vuln Scan Research | Scanner results investigated (avoid re-doing work) |
| OSINT | Collected OSINT if applicable |
| Admin Info | POC contacts, RoE, to-do list |

---

## 2 · Tmux Logging Quick Reference

| Action | Keys |
|--------|------|
| Start/stop logging | `[Ctrl]+[B]` → `[Shift]+[P]` |
| Retroactive capture | `[Ctrl]+[B]` → `[Alt]+[Shift]+[P]` |
| Screen capture (single pane) | `[Ctrl]+[B]` → `[Alt]+[P]` |
| Clear pane history | `[Ctrl]+[B]` → `[Alt]+[C]` |
| Split vertical | `[Ctrl]+[B]` → `[Shift]+[%]` |
| Split horizontal | `[Ctrl]+[B]` → `[Shift]+["]` |
| Switch panes | `[Ctrl]+[B]` → `[O]` |

Add `set -g history-limit 50000` to `~/.tmux.conf` to prevent buffer loss.

---

## 3 · Report Structure

```
1. Executive Summary        ← Non-technical, 1.5-2 pages, for budget holders
2. Remediation Summary      ← Short/medium/long-term recommendations
3. Attack Chain             ← Step-by-step compromise narrative with evidence
4. Technical Findings       ← Individual finding writeups
5. Appendices               ← Scope, methodology, severity ratings, cred lists
```

---

## 4 · Executive Summary Rules

### Do

- Be specific with numbers ("25 occurrences" not "several")
- Keep it to 1.5-2 pages
- Describe access in business terms ("HR documents" not "Domain Admin")
- Recommend process improvements, not just patches
- Recognize what the client does well

### Don't

- Name specific vendors (say "EDR solution" not "CrowdStrike")
- Use acronyms (no SNMP, MitM, LLMNR)
- Reference technical sections of the report
- Use obscure vocabulary

---

## 5 · Finding Template

Each finding must include:

| Element | Required |
|---------|----------|
| Description | What the vuln is, what platform, root cause |
| Impact | Business impact if unresolved |
| Affected Systems | Specific hosts/apps |
| Remediation | Actionable steps (specific registry paths, GPO settings) |
| References | Vendor-agnostic, free, reputable sources |
| Reproduction Steps | Step-by-step with evidence between narrative |

Optional: CVE, CVSS, OWASP/MITRE IDs, ease of exploitation

### Evidence rules

- Break each step into its own figure with narrative between
- Use text output over screenshots (copy/pasteable)
- Redact creds with `<REDACTED>` (never blur — use solid black bars)
- Include URL bar or ipconfig to prove target identity
- Offer alternative tools for validation

### Remediation rules

- Be specific (exact registry paths, config changes)
- Provide free alternatives alongside commercial options
- Warn about risks of changes (test before large-scale deployment)
- Never recommend specific vendor products

---

## 6 · Report Types

| Type | Key Difference |
|------|---------------|
| Internal Pentest | Attack chain, AD findings, credential appendix |
| External Pentest | OSINT appendix, external services focus |
| Vulnerability Assessment | No exploitation — scan + validation only |
| Web Application | OWASP Top 10 focus |
| Post-Remediation | Retest ONLY original findings on original hosts |
| Attestation Letter | 1-2 pages for third parties — no technical details |
| Draft → Final | Always issue draft first, then final after client review |

---

## 7 · QA Checklist

```
□ Grammar and spelling checked (Grammarly/LanguageTool with approval)
□ Fonts and sizes consistent throughout
□ All findings have complete evidence
□ Credentials redacted everywhere
□ Tool output redacted (remove "Pwn3d!" etc.)
□ Screenshots cropped, annotated, professional
□ Hostname/username professional (not azzkicker@clientsmasher)
□ Terminal background solid black (not transparent)
□ Acronyms spelled out on first use
□ Executive summary readable by non-technical audience
□ No previous client data left in report
□ All hyperlinks/ToC working
□ Page numbers present
□ Reviewed by someone other than author
```

---

## 8 · Artifact Tracking

### Payload log (mandatory)

| Field | Track This |
|-------|-----------|
| Timestamp | When payload was used |
| Target host | IP + hostname |
| File path | Where uploaded on target |
| File hash | MD5/SHA256 for client to search |
| Cleanup | Removed / needs client cleanup |

### Account/system modifications

Track: IP, timestamp, description, location, app/service, account name + password. Get **written approval** before making changes.

---

## 9 · Client Communication Timeline

```
Pre-engagement  → Scope confirmation, RoE, exclusion list
Day 1           → Start notification (tester, scope, source IP, dates, contacts)
Each day        → Stop notification (activities summary, critical findings)
Critical find   → Immediate vulnerability notification (stop testing, notify)
DA achieved     → Notify client, ask about additional focus areas
End of testing  → Final stop notification, report delivery timeline
~1 week later   → Draft report delivered
~2 weeks later  → Report review meeting
After meeting   → Final report (Draft → Final designation change)
Post-remediation → Retest original findings only (within time limit)
```

---

## 10 · Reporting Tools

| Free | Paid |
|------|------|
| Ghostwriter | AttackForge |
| Dradis | PlexTrac |
| VECTR | Rootshell Prism |
| WriteHat | |

---

## 11 · MS Word Hotkeys

| Hotkey | Action |
|--------|--------|
| `F4` | Repeat last action |
| `Ctrl+A` → `F9` | Update all fields (ToC, figures) |
| `Ctrl+S` | Save (do constantly) |
| `Ctrl+Alt+S` | Split window into two panes |
| `Shift+F5` | Jump to last edit location |
