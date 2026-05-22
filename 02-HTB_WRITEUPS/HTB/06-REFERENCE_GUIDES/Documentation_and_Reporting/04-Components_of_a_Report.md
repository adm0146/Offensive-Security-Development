# Section 04 — Components of a Report

> **Lab: no** — Reading-only section covering report structure, executive summaries, attack chains, and appendices.

**Core principle:** The report is what the client pays for. Every element must serve a purpose: the Executive Summary sells the urgency to non-technical decision-makers, the Attack Chain connects findings into a coherent narrative, and the Findings section gives technical teams reproduction steps. No fluff, no filler.

---

## Report structure overview

```
1. Executive Summary           ← Non-technical, 1.5-2 pages max
2. Summary of Recommendations ← Short/medium/long-term remediation roadmap
3. Attack Chain                ← Visual + step-by-step compromise narrative
4. Findings                    ← Individual vulnerability writeups with evidence
5. Appendices                  ← Supporting data (scope, methodology, creds, etc.)
```

---

## Writing an attack chain

The attack chain demonstrates how individual findings combine to achieve compromise. It helps the reader understand why certain findings are rated at a given severity — a medium-risk issue that chains into domain admin becomes high-risk in context.

### Structure

1. **Summary paragraph** — High-level overview of the path from anonymous user to domain compromise
2. **Numbered steps** — Each step with tool output / screenshots showing exactly what happened
3. **Reusable evidence** — Each step can be copy/pasted into individual finding writeups

### Sample attack chain (from module)

```
Responder (LLMNR spoofing) → NTLMv2 hash capture
→ Hashcat crack → bsmith domain user foothold
→ BloodHound enumeration → identify mssqlsvc SPN with admin on SQL01
→ Kerberoasting (GetUserSPNs.py) → crack mssqlsvc password
→ CrackMapExec LSA dump on SQL01 → srvadmin cleartext creds
→ RDP to MS01 as srvadmin → pramirez logged in (has DCSync rights)
→ Rubeus TGT extraction → Pass-the-Ticket as pramirez
→ Mimikatz DCSync → Domain Admin NTLM hash
→ Domain compromise confirmed via CrackMapExec
```

---

## Executive Summary

### Purpose
- Written for the budget holder (CEO, CFO, board members)
- Justifies security spending / requests additional funding
- Must be understandable by someone with zero technical knowledge

### Do's

| Rule | Rationale |
|------|-----------|
| Be specific with numbers | "25 occurrences" not "several" — executives won't dig through the report |
| Keep it to 1.5-2 pages | It's a summary, not a novel |
| Describe what you accessed in business terms | "HR documents and banking systems" not "Domain Admin" |
| Describe what processes need to improve | "patch management process" not "install KB5004237" |
| Set effort expectations (if experienced) | Low/moderate/significant effort categories |
| Recognize what the client does well | Builds trust, validates their existing investment |

### Don'ts

| Rule | Rationale |
|------|-----------|
| Don't name specific vendors | Report is technical, not sales — say "EDR solution" not "CrowdStrike" |
| Don't use acronyms | No SNMP, MitM, LLMNR — describe in plain English |
| Don't spend time on low-impact issues | Steer attention to what matters |
| Don't use obscure vocabulary | If they have to Google a word, you lost them |
| Don't reference technical sections | They're reading this BECAUSE they won't read those sections |

### Vocabulary translations

| Technical Term | Executive-Friendly Version |
|----------------|---------------------------|
| VPN, SSH | Protocol for secure remote administration |
| SSL/TLS | Technology for secure web browsing |
| Hash | Output from an algorithm used to validate file integrity |
| Password spraying | Trying one common password against many user accounts |
| Password cracking | Converting encrypted password back to readable form |
| Buffer overflow / deserialization | Attack resulting in remote command execution |
| OSINT | Hunting publicly available data about a company |
| SQL injection / XSS | Vulnerability where user input manipulates application logic |

---

## Summary of Recommendations

Structure recommendations by timeframe:

| Timeframe | Example |
|-----------|---------|
| **Short-term** (immediate) | Push missing patches, change compromised passwords, disable LLMNR |
| **Medium-term** (weeks) | Implement tiered admin model, harden service account configurations |
| **Long-term** (months) | Develop configuration management program, periodic security assessments |

- Every short/medium recommendation must tie to a specific finding
- A single finding can have both short-term (fix it) and long-term (fix the process that allowed it) recommendations
- If 15 findings are all "high," this section helps the client prioritize which high is "most high"

---

## Appendices

### Static (always include)

| Appendix | Content |
|----------|---------|
| Scope | In-scope URLs, network ranges, facilities |
| Methodology | Repeatable process ensuring thorough, consistent testing |
| Severity Ratings | Criteria for each severity level (must be defensible) |
| Biographies | Consultant qualifications (required for PCI compliance) |

### Dynamic (include when applicable)

| Appendix | When to Include |
|----------|-----------------|
| Exploitation Attempts & Payloads | Always — helps IR team differentiate you from real attackers |
| Compromised Credentials | When accounts were compromised (skip if entire domain dumped) |
| Configuration Changes | Any changes made to client environment during testing |
| Additional Affected Scope | When host lists are too long for the finding itself |
| Information Gathering / OSINT | External pentests — subdomains, emails, breach data, SSL analysis |
| Domain Password Analysis | When NTDS dump + cracking was performed (use DPAT tool) |

---

## Report type differences

| Assessment Type | Key Focus | Likely Omissions |
|-----------------|-----------|------------------|
| Internal Pentest (with domain compromise) | Attack chain, AD findings, credential appendix | OSINT appendix |
| External Pentest (no internal compromise) | OSINT, external services, information gathering | Attack chain, config changes, password analysis |
| Web Application (WASA) | OWASP Top 10, application findings | Network findings, AD content |
| Physical / Social Engineering | Narrative format, timeline of events | Traditional finding format |
| Red Team | Evasion narrative, detection gaps | Comprehensive finding list |

---

## Prioritizing during assessment

- Focus effort on high-impact findings (RCE, sensitive data exposure)
- Consolidate low-impact "noise" into categories (e.g., "35 SSL/TLS issues" → one finding)
- Don't fall down rabbit holes on broken PoCs — ask senior teammates
- Track what you tried but didn't work (shows thoroughness in low-finding reports)

---

## Answers

| Question | Answer |
|----------|--------|
| Q1: Which report component should be non-technical? | `Executive Summary` |
| Q2: Good practice to name specific vendors in that component? | `False` |

---

## Key takeaways

- **The Executive Summary is for the budget holder.** If your parents can't understand it, rewrite it.
- **Attack chains connect the dots.** Individual medium findings become high-risk when chained — demonstrate this visually.
- **Be specific with metrics.** "25 occurrences" not "several." Executives don't dig through technical details.
- **Never recommend specific vendors.** Say "EDR solution" not "CrowdStrike." Keep the report vendor-neutral.
- **Recommendations need timeframes.** Short/medium/long-term tied to specific findings gives the client an actionable roadmap.
- **Appendices exist for supporting data.** Exploitation logs, compromised creds, and payload tracking protect both you and the client.
