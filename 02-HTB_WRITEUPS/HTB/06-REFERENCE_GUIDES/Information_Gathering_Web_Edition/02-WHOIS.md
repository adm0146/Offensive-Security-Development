# 🔍 WHOIS

## Overview

WHOIS is a widely used **query and response protocol** designed to access databases that store information about registered internet resources. Primarily associated with domain names, WHOIS can also provide details about **IP address blocks** and **autonomous systems**. Think of it as a giant phonebook for the internet, letting you look up who owns or is responsible for various online assets.

---

## WHOIS Record Fields

| Field | Description | Example |
|-------|-------------|---------|
| **Domain Name** | The domain itself | `example.com` |
| **Registrar** | Company where the domain was registered | GoDaddy, Namecheap, Amazon Registrar |
| **Registrant Contact** | Person or organization that registered the domain | Company name, individual |
| **Administrative Contact** | Person responsible for managing the domain | Admin email, phone |
| **Technical Contact** | Person handling technical issues | Tech team email |
| **Creation Date** | When the domain was registered | `2019-08-05T22:43:09Z` |
| **Expiration Date** | When registration expires | Renewal deadline |
| **Name Servers** | Servers that translate domain name into an IP address | `ns1.example.com` |

---

## Command Syntax

```bash
# Basic WHOIS lookup
whois <domain>

# Example
whois inlanefreight.com
```

### Example Output

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

## History of WHOIS

The history of WHOIS is linked to **Elizabeth Feinler**, a computer scientist who played a pivotal role in shaping the early internet.

In the **1970s**, Feinler and her team at the Stanford Research Institute's Network Information Center (NIC) recognised the need for a system to track and manage the growing number of network resources on the **ARPANET** (the precursor to the modern internet). Their solution was the creation of the **WHOIS directory** — a rudimentary yet groundbreaking database that stored information about network users, hostnames, and domain names.

---

## Why WHOIS Matters for Web Recon

WHOIS data serves as a **treasure trove of information** for penetration testers during the reconnaissance phase. It offers valuable insights into the target organisation's digital footprint and potential vulnerabilities:

| Use Case | Description |
|----------|-------------|
| **Identifying Key Personnel** | WHOIS records often reveal names, email addresses, and phone numbers of individuals responsible for managing the domain. This can be leveraged for **social engineering** or **phishing campaigns**. |
| **Discovering Network Infrastructure** | Technical details like name servers and IP addresses provide clues about the target's network infrastructure. Helps identify potential **entry points** or **misconfigurations**. |
| **Historical Data Analysis** | Accessing historical WHOIS records through services like **WhoisFreaks** can reveal changes in ownership, contact information, or technical details over time. Useful for tracking the evolution of the target's digital presence. |

---

## Key Takeaways

1. WHOIS is a **passive reconnaissance** technique — very low detection risk
2. Always check WHOIS early in an engagement to identify **ownership, contacts, and infrastructure**
3. Look for **email patterns** (e.g., `admin@company.com`) that reveal the organisation's email format
4. **Historical WHOIS** data (via WhoisFreaks) can reveal past owners, old infrastructure, and changes over time
5. Name servers in WHOIS output can hint at **hosting providers** and **DNS infrastructure** to investigate further

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
