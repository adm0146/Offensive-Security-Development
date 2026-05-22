# Section 05 — How to Write Up a Finding

> **Lab: optional** — WriteHat reporting tool available for practice. No mandatory exploitation.

**Core principle:** Each finding must be self-contained: explain the issue, demonstrate the impact, show reproduction steps, and provide actionable remediation. Write for a reader who has never heard of the tool you used or the attack you performed.

---

## Required elements per finding

| Element | Purpose |
|---------|---------|
| **Description** | What the vulnerability is, what platform it affects, root cause explanation |
| **Impact** | What happens if left unresolved — in business terms |
| **Affected Systems** | Specific hosts, networks, environments, or applications |
| **Remediation** | Actionable steps to fix the issue (not just "fix it") |
| **Reference Links** | External sources for further reading (vendor-agnostic, no paywalls) |
| **Reproduction Steps** | Step-by-step evidence with command output/screenshots |

### Optional fields

- CVE identifier
- OWASP / MITRE ATT&CK IDs
- CVSS score
- Ease of exploitation / probability of attack
- Alternative tools for validation

---

## Writing effective reproduction steps

### Rules

| Do | Don't |
|----|-------|
| Break each step into its own figure | Combine multiple steps in one screenshot |
| Show full tool configuration before execution | Just show the final result |
| Write narrative between figures explaining your thought process | Stack consecutive figures with only captions |
| Offer alternative tools for validation (name + link) | Reproduce the entire exploit twice with different tools |
| Use text-based output (copy/pasteable) | Screenshot terminal when text is available |
| Include URL bar or `ipconfig` output to prove target identity | Use screenshots that could be from any host |
| Redact credentials with `<REDACTED>` | Leave cleartext passwords visible |

### Evidence must be defensible

- Proving basic auth is insecure? Show the login prompt AND the cleartext credentials in a Wireshark capture
- Proving a web vuln? Include the URL bar showing the target domain
- Turn off bookmarks bar and unprofessional browser extensions

---

## Writing effective remediation recommendations

### Bad vs Good examples

**Example 1 — Registry hardening:**

| Quality | Recommendation |
|---------|---------------|
| Bad | "Reconfigure your registry settings to harden against X." |
| Good | "To fully remediate this finding, update the following registry hives with the specified values. Note: changes to critical components like the registry should be tested in a small group before large-scale deployment.<br>- `HKLM\System\CurrentControlSet\...` → Change value X to Y" |

**Example 2 — Commercial tool:**

| Quality | Recommendation |
|---------|---------------|
| Bad | "Implement [expensive commercial tool] to address this." |
| Good | "Multiple approaches exist. [Vendor] has published a workaround (linked below). Commercial tools exist that disable the vulnerable functionality but may be cost-prohibitive. The linked workaround provides an interim solution." |

### Principles

- Be specific — list exact registry paths, GPO settings, configuration files
- Provide alternatives — not every client has budget for commercial solutions
- Include warnings about risk of changes (registry, GPO, production services)
- Don't recommend specific vendor products — recommend technology categories
- Research the fix yourself — you learn more, client appreciates the effort, builds trust

---

## Selecting quality references

| Criteria | Rationale |
|----------|-----------|
| Vendor-agnostic | Vendor articles push their product instead of solving the problem |
| Thorough walkthrough | Reader needs enough detail to understand and fix |
| Not behind a paywall | Client shouldn't have to pay to learn about their vulnerability |
| Gets to the point | Don't link RFC 9000 or NIST 800-53 in full — link specific sections |
| Clean website | No crypto miners, pop-up ads, or suspicious redirects |
| Stable URL | Well-known sources (MITRE, OWASP, Microsoft Docs) won't disappear |

---

## Finding quality checklist

| Element | Good Finding | Bad Finding |
|---------|-------------|-------------|
| Description | Explains root cause, affected technology, how it works | Vague one-liner |
| Impact | Specific business impact ("access to HR data, banking systems") | Generic "could lead to compromise" |
| CVSS | Filled in with justifiable score | Left blank |
| Remediation | Specific steps, multiple options, warnings about side effects | "Fix it" or "buy expensive tool" |
| Evidence | Step-by-step with narrative, redacted creds, identified hosts | Single screenshot with no context |
| References | Reputable, free, actionable links | Broken links, paywalled, irrelevant |

---

## Example finding structure

```
┌─────────────────────────────────────────────────────┐
│ Finding: Weak Kerberos Authentication (Kerberoasting)│
├─────────────────────────────────────────────────────┤
│ Severity: High          │ CVSS: 9.5               │
│ CWE: CWE-916           │ MITRE: T1558.003        │
├─────────────────────────────────────────────────────┤
│ Description:                                        │
│ [2-3 paragraphs explaining what Kerberoasting is,   │
│  why SPN accounts are vulnerable, what an attacker  │
│  gains from cracking the TGS ticket]               │
├─────────────────────────────────────────────────────┤
│ Impact:                                             │
│ [What access does this grant? What data is at risk?]│
├─────────────────────────────────────────────────────┤
│ Affected Systems: INLANEFREIGHT.LOCAL domain        │
│ (6 SPN accounts identified)                        │
├─────────────────────────────────────────────────────┤
│ Remediation:                                        │
│ - Enable AES 256 encryption for Kerberos           │
│ - Use Group Managed Service Accounts (gMSA)        │
│ - Enforce 25+ character passwords on SPN accounts  │
│ - Remove unnecessary SPNs                          │
├─────────────────────────────────────────────────────┤
│ References:                                         │
│ - [Microsoft: Service Account Security]             │
│ - [MITRE ATT&CK T1558.003]                        │
├─────────────────────────────────────────────────────┤
│ Reproduction Steps:                                 │
│ [Step 1: Enumerate SPNs — GetUserSPNs.py output]   │
│ [Step 2: Request TGS ticket — command + output]    │
│ [Step 3: Crack offline — Hashcat with redacted pw] │
│ Alternative tools: Rubeus (Windows), PowerView     │
└─────────────────────────────────────────────────────┘
```

---

## WriteHat reporting tool

- URL: `https://<TARGET_IP>/`
- Creds: `htb-student` / `HTB_@cademy_stdnt!`
- Pre-populated findings database with common categories
- Practice adding findings, building reports, generating output
- Data is NOT saved when target expires — keep local copies

---

## Answers

| Question | Answer |
|----------|--------|
| Q1: "An attacker can own your whole network cause your DC is out of date. Fix that!" — Good or Bad? | `Bad` |

---

## Key takeaways

- **Every finding must be self-contained.** A reader should understand the issue, its impact, and how to fix it without reading anything else.
- **Write for someone who's never seen your tools.** Break steps into individual figures with narrative explanations between them.
- **Remediation must be actionable and specific.** Registry paths, GPO settings, exact configuration changes — not "harden your systems."
- **Never recommend specific vendors.** Recommend technology categories and provide free workarounds alongside commercial options.
- **Evidence must be defensible.** Prove the target, prove the vulnerability, prove the impact — leave no room for debate.
- **Redact credentials everywhere.** Reports get passed around to many audiences; protect sensitive data with `<REDACTED>` or solid black bars.
