# 📡 Introduction to Web Reconnaissance

## Overview

Web recon is the Information Gathering phase of the pentest process. You are mapping the target's attack surface before touching anything.

Two approaches — use both:

| Approach | Interaction | Detection Risk | When to Use |
|---|---|---|---|
| **Passive** | None — public sources only | Very low | Always do this first |
| **Active** | Direct contact with target | Higher — can trigger IDS | After you have authorization |

---

## Passive Recon — What to Run First

No direct contact with the target. Start every engagement here.

| Technique | Command / Tool | What You Get |
|---|---|---|
| **WHOIS** | `whois domain.com` | Owner, registrar, name servers, creation date |
| **DNS Records** | `dig domain.com ANY` | Subdomains, mail servers, IPs, TXT records |
| **Search Engines** | Google: `site:target.com` | Indexed pages, subdomains, exposed files |
| **Web Archives** | Wayback Machine | Old site versions, removed pages, leaked info |
| **Code Repos** | GitHub search: `target.com` | Exposed creds, API keys, internal paths |
| **CT Logs** | crt.sh: `%.target.com` | SSL certificates → subdomain discovery |

---

## Active Recon — After Authorization

Direct interaction with the target. Requires written permission.

| Technique | Command / Tool | What You Get |
|---|---|---|
| **Port Scanning** | `nmap -sV -sC target.com` | Open ports, service versions, default scripts |
| **Vulnerability Scanning** | Nessus, Nikto | Known CVEs, misconfigs |
| **Web Spidering** | Burp Suite, ZAP | Site map, hidden directories, parameters |
| **VHost Fuzzing** | `gobuster vhost`, `ffuf` | Hidden virtual hosts not in DNS |
| **Banner Grabbing** | `curl -I target.com` | Server software, headers, version info |

---

## Module Workflow

This module follows this progression. Each technique feeds into the next:

```
WHOIS → DNS → Subdomains → Zone Transfers → Virtual Hosts → Web Fingerprinting
```

---

## Key Takeaways

- Passive first, active second. Always gather publicly available intelligence before making direct contact.
- Active recon requires authorization. Port scanning without permission can be illegal.
- Findings are iterative. WHOIS reveals name servers, DNS reveals subdomains, and subdomains reveal more attack surface.
- Document everything. Each finding feeds into the next phase.
