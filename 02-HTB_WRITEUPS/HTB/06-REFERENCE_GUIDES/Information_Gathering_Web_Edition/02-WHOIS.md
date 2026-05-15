# 🔍 WHOIS

## Overview

WHOIS queries domain registration databases. It returns the owner's name, contact emails, name servers, and registration dates. It is passive recon — no packets go to the target. Run it first on every engagement.

---

## Installation & Usage

```bash
sudo apt update && sudo apt install whois -y
```
> Updates the package list and installs the `whois` client. Kali Linux usually has it pre-installed — run this only if the command is missing.

### Core Command

```bash
whois <domain>
```
> Queries the WHOIS database for the target domain. Replace `<domain>` with your target (e.g., `inlanefreight.com`). Output includes registrar, creation date, name servers, and contact info.

### Example

```bash
whois inlanefreight.com
```
> Runs WHOIS against the example target domain. The output below is what a real response looks like — key fields to scan are `Creation Date`, `Name Server`, and any contact emails.

```
Domain Name: inlanefreight.com
Registry Domain ID: 2420436757_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.registrar.amazon
Registrar URL: https://registrar.amazon.com
Updated Date: 2023-07-03T01:11:15Z
Creation Date: 2019-08-05T22:43:09Z
[...]
```

---

## What to Look For in the Output

| Field | What It Tells You | Recon Value |
|---|---|---|
| **Registrar** | Where the domain was registered (GoDaddy, Amazon, etc.) | Identifies hosting ecosystem |
| **Creation Date** | When the domain was first registered | Recently created = possible phishing domain |
| **Expiration Date** | When registration expires | Expired domains can be hijacked |
| **Registrant/Admin Contact** | Person or org that owns the domain | Names, emails, phone numbers for social engineering |
| **Name Servers** | DNS servers handling the domain | Reveals hosting provider, shared infrastructure |
| **Domain Status** | Protection flags (`clientTransferProhibited`, etc.) | Shows security posture of the domain |

---

## Red Flags to Watch For

| Indicator | What It Suggests |
|---|---|
| Domain registered **days ago** | Phishing / malicious infrastructure |
| Registrant behind **privacy service** | Could be legitimate OR hiding malicious intent |
| Name servers on **bulletproof hosting** | Commonly used for C2 / phishing |
| Multiple status flags (`Prohibited`) | Well-secured domain — harder target |

---

## Acting on WHOIS Findings

| Finding | Next Step |
|---|---|
| Email pattern found (e.g., `admin@company.com`) | Use for social engineering research, spray login portals |
| Name servers identified | Run `dig` against them for DNS records |
| Registrar identified | Check for other domains registered through the same registrar |
| Old creation date | Look at historical WHOIS via **WhoisFreaks** for ownership changes |

---

## Key Takeaways

- WHOIS is passive recon. Run it early. There is no detection risk.
- Look for email patterns, name servers, and creation dates first.
- Domains registered recently with privacy services are suspicious.
- Name servers from WHOIS output go directly into `dig` for DNS enumeration.
- Use WhoisFreaks to see historical WHOIS data and track ownership changes over time.

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
