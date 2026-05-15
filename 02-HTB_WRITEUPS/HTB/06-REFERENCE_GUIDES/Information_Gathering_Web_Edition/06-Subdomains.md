# 🌐 Subdomains

## Overview

Subdomains extend the main domain (for example, `blog.example.com`, `dev.example.com`, `admin.example.com`). They expand the attack surface. Development environments, admin panels, and legacy apps often run on subdomains with weaker security than the main site.

---

## What You Find on Subdomains

| Discovery | Why It Matters |
|---|---|
| **Dev/Staging environments** | Relaxed security, test data, debug info exposed |
| **Admin panels** | Login portals not meant to be public |
| **Legacy apps** | Outdated software with known CVEs |
| **Sensitive files** | Config files, internal docs, backups |

---

## Two Approaches to Finding Subdomains

### 1. Active Enumeration — Direct Interaction

You are querying the target DNS or brute-forcing names against it. This is detectable.

| Technique | Tool | Command |
|---|---|---|
| **DNS Zone Transfer** | `dig` | `dig axfr @<nameserver> domain.com` |
| **Brute-Force** | `dnsenum` | `dnsenum --enum domain.com -f <wordlist>` |
| **Brute-Force** | `gobuster` | `gobuster dns -d domain.com -w <wordlist>` |
| **Brute-Force** | `ffuf` | `ffuf -w <wordlist> -u http://domain.com -H "Host: FUZZ.domain.com"` |

### 2. Passive Enumeration — No Direct Contact

External sources only. No contact with the target — stealthy.

| Source | How to Use It | What You Get |
|---|---|---|
| **Certificate Transparency Logs** | Browse `https://crt.sh/?q=%.domain.com` | Subdomains listed in SSL certificate SANs |
| **Search Engines** | Google: `site:domain.com -www` | Indexed subdomains |
| **Online DNS Databases** | VirusTotal, DNSDumpster, SecurityTrails | Aggregated subdomain data |

---

## Active vs Passive — When to Use Which

| Factor | Active | Passive |
|---|---|---|
| **Stealth** | Detectable | No interaction with target |
| **Coverage** | Can find non-public subdomains | Only what external sources have indexed |
| **Authorization** | Required | Not needed |
| **Best For** | Authorized engagements | Initial recon, OSINT |

> **Use both.** Passive first to build your list, then active to find what passive missed.

---

## Key Takeaways

- Subdomains expand the attack surface. Dev, staging, admin, and legacy apps are prime targets.
- Use passive methods first (crt.sh, Google dorks, DNSDumpster), then active brute-force with dnsenum or gobuster.
- Certificate Transparency (CT) logs are a goldmine. SSL certificates list subdomains in the Subject Alternative Name (SAN) field.
- Zone transfers are always worth trying. Low effort, massive payoff if the server is misconfigured.
- Every discovered subdomain is a new target to enumerate further.

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
