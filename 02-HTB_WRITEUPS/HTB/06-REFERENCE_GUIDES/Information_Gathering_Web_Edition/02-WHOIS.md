# 🔍 WHOIS

## Overview

WHOIS queries registration databases for domain ownership, contacts, name servers, and dates. It's **passive recon** — very low detection risk. Run it first on every engagement.

---

## Installation & Usage

```bash
sudo apt update && sudo apt install whois -y
```

### Core Command

```bash
whois <domain>
```

### Example

```bash
whois inlanefreight.com
```

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

- WHOIS is **passive recon** — run it early, no detection risk
- Look for **email patterns**, **name servers**, and **creation dates** first
- **Recently registered domains** with privacy services = suspicious
- Name servers in WHOIS output → feed directly into `dig` queries for DNS enumeration
- Use **WhoisFreaks** for historical WHOIS data to track ownership changes over time

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
