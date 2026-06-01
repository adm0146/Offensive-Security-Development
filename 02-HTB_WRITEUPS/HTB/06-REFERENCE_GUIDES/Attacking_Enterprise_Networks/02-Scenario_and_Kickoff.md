# Section 2 — Scenario & Kickoff

> Sets the stage for the engagement — scope, rules of engagement, and the professional process before any technical work begins.

---

## Engagement Type

Full-scope External Penetration Test, transitioning to Internal if DMZ is breached. Non-evasive (no stealth required). Goal: identify as many vulnerabilities as possible from an anonymous Internet perspective.

## Scope

| Phase | Targets |
|-------|---------|
| External | `10.129.x.x` (HTB-spawned external target) |
| External | `*.inlanefreight.local` (all subdomains) |
| Internal | `172.16.8.0/23` |
| Internal | `172.16.9.0/23` |
| Internal | `INLANEFREIGHT.LOCAL` (Active Directory domain) |

- No credentials provided (web, VPN, or AD)
- Subdomain and live host discovery is part of the test
- Automated scanning permitted, but no service disruptions

## Out of Scope

- Phishing / social engineering
- Physical attacks
- Destructive actions / DoS
- Environment modifications without written consent

## Key Documents (Professional Process)

| Document | Purpose |
|----------|---------|
| Scope of Work (SoW) | Testing specifics, methodology, timeline, meetings, deliverables — signed by both parties |
| Rules of Engagement (RoE) / Authorization to Test | Scope details (URLs, IPs, CIDRs, creds), key personnel with contact info (min 2 per side), testing window |

## Testing Window

- Duration: 1 week testing + 2 days draft report
- Hours: 24/7 authorized
- Restriction: heavy vulnerability scans after 18:00 London time only
- Report should be drafted as you go — fill in template during scan wait times

## Kickoff Checklist

1. All documents signed (SoW + RoE) with complete scope filled in
2. Key contacts identified on both sides (names, cell, email)
3. Testing VM set up and ready
4. Notetaking structure and directory skeleton created
5. Report template started — pre-fill everything you can before first scan finishes
6. Kickoff email sent to all stakeholders with:
   - Start date/time
   - Source testing IP
   - Primary and secondary tester contact info
   - Brief procedure overview

## Why This Section Matters for the Exam

This is the professional wrapper around the technical work. On the CPTS exam you won't send kickoff emails, but the report you submit needs to demonstrate you understand the engagement lifecycle — not just the hacking. The Documentation & Reporting module covered the deliverable side; this section shows the process that bookends it.

## What Comes Next

External information gathering — passive recon, then active scanning against the external target. No creds, no insider knowledge, just the scope and your methodology.
