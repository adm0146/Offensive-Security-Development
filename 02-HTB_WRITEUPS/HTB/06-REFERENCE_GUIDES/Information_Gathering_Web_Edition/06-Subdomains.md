# 🌐 Subdomains

## Overview

Beyond the main domain (e.g., `example.com`) lies a potential network of **subdomains** — extensions of the primary domain created to organise and separate different sections or functionalities. For example: `blog.example.com`, `shop.example.com`, or `mail.example.com`. Discovering these subdomains is a critical part of web reconnaissance.

---

## Why Subdomains Matter for Recon

Subdomains often host valuable information and resources that aren't directly linked from the main website:

| What You Might Find | Why It Matters |
|---------------------|----------------|
| **Development & Staging Environments** | Companies test new features on subdomains before deploying to production. Relaxed security measures can expose vulnerabilities or sensitive information |
| **Hidden Login Portals** | Administrative panels or login pages not meant to be publicly accessible — attractive targets for unauthorised access |
| **Legacy Applications** | Older, forgotten web applications with outdated software and known vulnerabilities |
| **Sensitive Information** | Confidential documents, internal data, or configuration files inadvertently exposed on subdomains |

---

## Subdomain Enumeration

Subdomain enumeration is the process of systematically identifying and listing subdomains. From a DNS perspective:

- **A records** (or AAAA for IPv6) map the subdomain name to its IP address
- **CNAME records** create aliases for subdomains, pointing them to other domains or subdomains

There are **two main approaches**:

---

### 1. Active Subdomain Enumeration

Directly interacting with the target domain's DNS servers to uncover subdomains.

| Technique | Description | Notes |
|-----------|-------------|-------|
| **DNS Zone Transfer** | Request a full copy of the zone file from a misconfigured DNS server | Rarely successful due to tightened security, but always worth trying |
| **Brute-Force Enumeration** | Systematically test a list of potential subdomain names against the target domain | Most common active technique |

**Brute-Force Tools:**

| Tool | Description |
|------|-------------|
| `dnsenum` | Automated DNS enumeration with dictionary attacks and zone transfer attempts |
| `ffuf` | Fast web fuzzer that can brute-force subdomains using wordlists |
| `gobuster` | Directory/subdomain brute-forcing tool with DNS mode |

> 💡 **Tip:** Use wordlists of common subdomain names (e.g., from SecLists) or generate custom lists based on patterns specific to the target.

---

### 2. Passive Subdomain Enumeration

Relies on external sources to discover subdomains **without directly querying the target's DNS servers**.

| Source | Description |
|--------|-------------|
| **Certificate Transparency (CT) Logs** | Public repositories of SSL/TLS certificates. Certificates often include associated subdomains in their **Subject Alternative Name (SAN)** field |
| **Search Engines** | Use specialised operators like `site:example.com` in Google or DuckDuckGo to filter results to only subdomains |
| **Online DNS Databases** | Various tools and databases aggregate DNS data from multiple sources, allowing you to search for subdomains without direct interaction |

---

## Active vs. Passive Comparison

| Aspect | Active Enumeration | Passive Enumeration |
|--------|-------------------|-------------------- |
| **Method** | Directly queries target DNS servers | Uses external data sources |
| **Control** | More control, potentially more comprehensive | Limited to what external sources have indexed |
| **Stealth** | More detectable by the target | Stealthier — no direct interaction with target |
| **Coverage** | Can discover subdomains not publicly indexed | May miss subdomains not in CT logs or search engines |
| **Best For** | Thorough discovery during authorised engagements | Initial recon and OSINT gathering |

> 🔑 **Best Practice:** Combine both active and passive approaches for the most thorough and effective subdomain enumeration strategy.

---

## Key Takeaways

1. **Subdomains expand the attack surface** — dev environments, admin panels, and legacy apps are common findings
2. **Active enumeration** (brute-force with `dnsenum`, `ffuf`, `gobuster`) gives you the most control but is detectable
3. **Passive enumeration** (CT logs, search engines, online databases) is stealthier but may miss subdomains
4. **Certificate Transparency logs** are a goldmine — SSL/TLS certificates often list subdomains in the SAN field
5. **Zone transfers** are rarely successful but always worth attempting — a misconfigured server can leak everything
6. **Combine both approaches** for comprehensive subdomain discovery

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
