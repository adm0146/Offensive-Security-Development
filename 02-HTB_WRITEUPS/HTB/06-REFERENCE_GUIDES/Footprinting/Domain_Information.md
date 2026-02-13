# Domain Information

## Overview

Domain information is a core component of any pentest -- not just subdomains, but the company's entire internet presence. The goal is to understand the company's functionality and identify which technologies and structures are necessary for their services to operate.

This information is gathered **passively** -- no direct scans. We remain hidden, navigating as normal customers or visitors to avoid connections that could expose us.

**Note:** OSINT techniques covered here are only a fraction of the full discipline. For deeper approaches, see the HTB Module: OSINT: Corporate Recon.

---

## Passive Reconnaissance Approach

### Step 1: Scrutinize the Main Website

Read through the company's content with a technical lens:
- What services do they offer? (app development, IoT, data science, IT security, etc.)
- What technologies and structures are needed to deliver those services?
- If you encounter an unfamiliar service, research what it consists of and what opportunities it presents

### Step 2: Think Like a Developer

This applies the first two enumeration principles together:
- **Principle 1:** There is more than meets the eye
- **Principle 2:** Distinguish between what we see and what we do not see

We see the services but **not** their functionality. However, services are bound to certain technical aspects necessary to deliver them. Taking the developer's point of view reveals technical insights into how things actually work under the hood.

### Step 3: Use Third-Party Services

Passive information gathering through external sources to build a deeper understanding of the company's infrastructure without making direct contact.

---

## Online Presence

### SSL Certificate Analysis

SSL certificates from the company's main website often include more than just one subdomain -- the certificate may be used for several domains, and these are most likely still active.

### Certificate Transparency Logs (crt.sh)

Certificate Transparency (RFC 6962) requires all digital certificates issued by a certificate authority to be logged in audit-proof logs. This enables detection of false or maliciously issued certificates. SSL providers like Let's Encrypt share this data with crt.sh.

**Query crt.sh for subdomains (JSON output):**

```bash
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .
```

Example response shows certificates for `matomo.inlanefreight.com`, `smartfactory.inlanefreight.com`, and others -- each with issuer, validity dates, and serial numbers.

**Filter for unique subdomains only:**

```bash
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u
```

This extracts a clean list of all unique subdomains from the certificate logs.

### Identify Directly Accessible Hosts

Filter out third-party hosted services (we cannot test those without permission):

```bash
for i in $(cat subdomainlist); do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4; done
```

### Shodan Reconnaissance

Shodan finds devices and systems permanently connected to the internet -- IoT devices, servers, surveillance cameras, industrial controllers, etc. It searches for open TCP/IP ports and filters by terms and criteria.

**Generate IP list from subdomains:**

```bash
for i in $(cat subdomainlist); do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt; done
```

**Run IPs through Shodan:**

```bash
for i in $(cat ip-addresses.txt); do shodan host $i; done
```

Shodan returns city, country, organization, open ports, service versions, and SSL information for each IP. This reveals the attack surface without sending a single packet to the target.

**Key finding from example:** `10.129.127.22` (matomo.inlanefreight.com) had 8 open ports including SMTP (25), DNS (53), HTTP (80/81/443), POP3 (110), and RPC (111) -- flagged for later active investigation.

### DNS Records

Display all available DNS records to find additional hosts and infrastructure details:

```bash
dig any inlanefreight.com
```

DNS records reveal:

| Record Type | What It Tells Us |
|-------------|-----------------|
| A | IP addresses of the domain |
| MX | Mail servers (Google in the example -- indicates Google Workspace) |
| NS | Name servers (hosting provider) |
| TXT | Verification records exposing third-party services |
| SOA | Primary DNS authority |

**TXT records are goldmines.** The example revealed:
- `MS=...` -- Microsoft 365 integration
- `atlassian-domain-verification` -- Atlassian/Jira/Confluence in use
- `google-site-verification` -- Google services
- `logmein-verification-code` -- LogMeIn remote access tool
- `v=spf1` -- SPF record listing all authorized mail senders (Mailgun, Google, Outlook, Atlassian)

---

## Key Takeaways

- Start passive -- scrutinize the website, think like a developer
- SSL certificates and crt.sh expose subdomains without any active scanning
- Filter out third-party hosts -- you cannot test them without permission
- Shodan reveals open ports and services without touching the target
- DNS TXT records leak third-party service integrations (Atlassian, Google, Microsoft, LogMeIn)
- Flag interesting hosts (high port count, unusual services) for later active investigation
