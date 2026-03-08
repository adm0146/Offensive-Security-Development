# 🔍 Utilising WHOIS

## Overview

WHOIS lookups are not just about gathering raw data — they provide **actionable intelligence** across multiple security disciplines. The following scenarios illustrate how WHOIS data is applied in real-world security operations.

---

## Scenario 1: Phishing Investigation

**Situation:** An email security gateway flags a suspicious email sent to multiple employees, claiming to be from the company's bank and urging recipients to click a link to update account information.

**Action:** Security analyst performs a WHOIS lookup on the domain linked in the email.

### WHOIS Red Flags Identified

| Indicator | Finding | Why It's Suspicious |
|-----------|---------|---------------------|
| **Registration Date** | Domain registered just a few days ago | Legitimate banks use long-established domains |
| **Registrant** | Hidden behind a privacy service | Banks typically have transparent registration |
| **Name Servers** | Associated with a known bulletproof hosting provider | Often used for malicious activities |

### Response Actions

1. Alert IT department to **block the domain**
2. Warn employees about the phishing scam
3. Investigate the hosting provider and associated IP addresses to uncover **additional phishing domains** or threat actor infrastructure

---

## Scenario 2: Malware Analysis

**Situation:** A security researcher is analysing a new malware strain that communicates with a remote **command-and-control (C2) server** to receive commands and exfiltrate stolen data.

**Action:** Perform a WHOIS lookup on the C2 domain to gain insights into the threat actor's infrastructure.

### Intelligence Gathered

- Identify whether the C2 is hosted on a **compromised or bulletproof server**
- Use WHOIS data to identify the **hosting provider**
- Notify the hosting provider of **malicious activity**
- Cross-reference registrant details with known threat actor infrastructure

---

## Scenario 3: Threat Intelligence Report

**Situation:** A cybersecurity firm tracks a sophisticated threat actor group known for targeting **financial institutions**. Analysts need to compile a comprehensive threat intelligence report.

**Action:** Gather WHOIS data on **multiple domains** associated with the group's past campaigns.

### Intelligence Value

- **Pattern identification** — Recurring registrants, email addresses, or registrars across campaigns
- **Infrastructure mapping** — Shared name servers or hosting providers linking multiple domains
- **Timeline analysis** — Registration and expiration dates revealing campaign preparation windows
- **Attribution clues** — Registrant details (even partial) that tie campaigns together

### Patterns Uncovered by Analysts

| Pattern | Finding | Significance |
|---------|---------|--------------|
| **Registration Dates** | Domains registered in clusters, shortly before major attacks | Reveals campaign preparation timelines |
| **Registrants** | Various aliases and fake identities used | Indicates deliberate OPSEC by threat actor |
| **Name Servers** | Domains often share the same name servers | Suggests common infrastructure across campaigns |
| **Takedown History** | Many domains taken down after attacks | Indicates previous law enforcement or security interventions |

These insights enable analysts to create a detailed profile of the threat actor's **Tactics, Techniques, and Procedures (TTPs)** and generate **Indicators of Compromise (IOCs)** for other organisations to detect and block future attacks.

---

## Using WHOIS (Practical)

### Installation

```bash
sudo apt update
sudo apt install whois -y
```

### Basic Lookup

```bash
whois <domain>
```

### Example: facebook.com

```bash
whois facebook.com
```

```
Domain Name: FACEBOOK.COM
Registry Domain ID: 2320948_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.registrarsafe.com
Registrar URL: http://www.registrarsafe.com
Updated Date: 2024-04-24T19:06:12Z
Creation Date: 1997-03-29T05:00:00Z
Registry Expiry Date: 2033-03-30T04:00:00Z
Registrar: RegistrarSafe, LLC
Registrar IANA ID: 3237
Registrar Abuse Contact Email: abusecomplaints@registrarsafe.com
Registrar Abuse Contact Phone: +1-650-308-7004
Domain Status: clientDeleteProhibited
Domain Status: clientTransferProhibited
Domain Status: clientUpdateProhibited
Domain Status: serverDeleteProhibited
Domain Status: serverTransferProhibited
Domain Status: serverUpdateProhibited
Name Server: A.NS.FACEBOOK.COM
Name Server: B.NS.FACEBOOK.COM
Name Server: C.NS.FACEBOOK.COM
Name Server: D.NS.FACEBOOK.COM
DNSSEC: unsigned
[...]
Registrant Name: Domain Admin
Registrant Organization: Meta Platforms, Inc.
```

### Analysing the Output

| Category | Details | Analysis |
|----------|---------|----------|
| **Domain Registration** | Registrar: RegistrarSafe, LLC · Created: 1997-03-29 · Expires: 2033-03-30 | Active for a long period — suggests legitimacy and established presence. Distant expiry reinforces longevity. |
| **Domain Owner** | Registrant/Admin/Tech Org: Meta Platforms, Inc. · Contact: Domain Admin | Confirms Facebook is owned by Meta Platforms, Inc. — consistent with expectations. |
| **Domain Status** | `clientDeleteProhibited`, `clientTransferProhibited`, `clientUpdateProhibited`, `serverDeleteProhibited`, `serverTransferProhibited`, `serverUpdateProhibited` | Strong security controls — domain protected against unauthorized changes, transfers, or deletions on both client and server sides. |
| **Name Servers** | `A.NS.FACEBOOK.COM` through `D.NS.FACEBOOK.COM` | All within `facebook.com` domain — Meta manages its own DNS infrastructure. Common for large organisations to maintain control over DNS resolution. |

---

## Key Takeaways

1. WHOIS is a **first-response tool** in phishing investigations — check registration date, registrant, and name servers
2. **Recently registered domains** with hidden registrant info and bulletproof hosting are strong phishing indicators
3. In malware analysis, WHOIS helps map **C2 infrastructure** and identify hosting providers for takedown requests
4. For threat intelligence, WHOIS enables **pattern recognition** across multiple campaigns by the same actor
5. Always look for **connections between domains** — shared registrants, name servers, or hosting can link separate attacks
6. WHOIS alone won't identify individual employees or specific vulnerabilities — **combine with other recon techniques** for comprehensive coverage
7. **Domain status flags** (e.g., `clientTransferProhibited`) reveal the security posture of a domain

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
