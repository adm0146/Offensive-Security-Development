# Section 03 — Types of Reports

> **Lab: no** — Reading-only section covering assessment types, report types, and deliverables.

**Core principle:** Different assessment types produce different deliverables. Know what you're being asked to deliver before you start testing. The report is what the client pays for — understand the lifecycle from draft → final → post-remediation → attestation.

---

## Assessment types

| Type | Description | Exploitation? |
|------|-------------|---------------|
| **Vulnerability Assessment** | Automated scan + validation of results (no exploitation) | No |
| **Penetration Test** | Manual testing that goes beyond scanning — exploitation, pivoting, privesc | Yes |
| **Purple Team** | Red + Blue collaborate — tester simulates threats, responder validates detection | Yes (controlled) |
| **Cloud Focused** | Pentest with cloud architecture expertise (secrets, containers, serverless) | Yes |
| **IoT Testing** | Network + cloud + application + hardware layers | Varies |
| **Web Application** | App-focused (may include underlying infrastructure) | Yes |
| **Hardware** | Physical device testing (IoT, kiosks, ATMs, laptops) | Varies |

---

## Penetration test perspectives

| Perspective | Information Given |
|-------------|-------------------|
| **Black box** | Company name only (external) or network connection only (internal) |
| **Grey box** | In-scope IP addresses / CIDR ranges |
| **White box** | Credentials, source code, configurations, architecture docs |

### Evasion levels

| Level | Approach |
|-------|----------|
| Non-evasive | Maximum coverage, no stealth — uncover as many vulns as possible |
| Hybrid evasive | Start stealthy, gradually get noisier — test at what level detection kicks in |
| Fully evasive | Remain undetected throughout — simulate advanced adversary |
| Adversary simulation | Long-term (months), few staff aware, no fixed start time |

---

## Report lifecycle

```
Draft Report → Client Review → Final Report → Post-Remediation Report
                                            → Attestation Letter (for third parties)
```

### Draft report
- Submit first, give client time to review independently
- Offer a review meeting for questions/clarification
- Client may want to add management responses, adjust language, or restructure

### Final report
- Issued after client confirms satisfaction with draft
- Some auditing firms won't accept draft reports for compliance

### Post-remediation report
- Retest ONLY original findings on originally affected hosts
- Do NOT redo the entire assessment
- Set a time limit (weeks, not months) to avoid environment drift
- Note the time elapsed and "snapshot" nature explicitly

**Pitfalls of delayed remediation testing:**
- Environment changes make apples-to-apples comparison impossible
- New hosts appear with the same vuln → endless loop
- New vulnerability scans find new issues → scope creep
- Recommend BAS tools for continuous validation if client needs ongoing assurance

### Attestation report
- For client's vendors/customers who need proof of testing
- 1-2 pages: approach taken, number of findings, general environment comments
- NO specific technical details, credentials, or sensitive information

---

## Other deliverables

| Deliverable | Purpose | Tips |
|-------------|---------|------|
| **Slide deck** | Present findings to technical or executive audience | Tailor language to audience; use anecdotes and current events (same industry = bonus); avoid graphs-only |
| **Spreadsheet of findings** | Tabular format for sorting/importing to ticketing systems | Use pivot tables for severity/category analytics; no narratives |
| **Vulnerability notifications** | Urgent out-of-band alert for critical flaws | Minimal fluff — finding details + evidence only; establish threshold at kickoff |

### When to send vulnerability notifications

- Directly exploitable + internet-facing + unauthenticated RCE or data exposure
- Weak/default credentials leading to same
- Set baseline at project kickoff — some clients want all highs/criticals reported immediately

---

## Internal vs External

| Aspect | External | Internal |
|--------|----------|----------|
| Perspective | Anonymous internet attacker | User on corporate network |
| Data sources | OSINT, public-facing systems | Internal hosts behind firewall |
| Typical goal | Breach perimeter, gain internal access | Foothold → domain compromise |
| Report extras | OSINT appendix (emails, subdomains, breach data) | AD attack chain, internal scanning results |

### OSINT data categories (External reports)

- Public DNS and domain ownership records
- Email addresses (check breach dumps, Google dorks)
- Subdomains
- Third-party vendors
- Similar/typosquatting domains
- Public cloud resources (S3 buckets, Azure blobs)

---

## Handling client pressure on remediation reports

If a client pushes to modify severity levels or findings:
1. Don't cross ethical boundaries (but don't accuse them of dishonesty)
2. Commiserate with their situation
3. Offer alternatives — many auditors accept documented remediation plans with reasonable deadlines
4. If too much time has passed, recommend treating it as a new assessment
5. If client refuses new assessment, clearly note the time gap and scope limitations in the report

---

## Answers

| Question | Answer |
|----------|--------|
| Q1: Mostly automated, no exploitation — what assessment type? | `Vulnerability Assessment` |
| Q2: Only company name + network connection, no other detail — what perspective? | `Black box` |

---

## Key takeaways

- **Vulnerability Assessment = no exploitation.** Automated scan + validation only. Penetration Test = manual exploitation.
- **Black box = minimum information.** Just company name (external) or network connection (internal).
- **Always submit a draft first.** Give clients the opportunity to review and provide feedback before finalizing.
- **Post-remediation ≠ new assessment.** Only retest original findings on original hosts. Set time limits.
- **Attestation letters strip technical details.** They exist to prove testing happened without exposing findings to third parties.
- **Vulnerability notifications are immediate.** Critical internet-facing RCE/data exposure can't wait for the final report.
