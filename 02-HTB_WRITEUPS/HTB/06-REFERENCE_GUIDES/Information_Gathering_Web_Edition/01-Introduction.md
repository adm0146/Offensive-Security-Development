# 📡 Introduction to Web Reconnaissance

## Overview

Web Reconnaissance is the **foundation** of a thorough security assessment. It involves systematically collecting information about a target website or web application. It forms a critical part of the **"Information Gathering"** phase of the Penetration Testing Process.

## Penetration Testing Process Flow

```
Pre-Engagement → Information Gathering → Vulnerability Assessment → Exploitation
                                              ↕                        ↕
                                        Lateral Movement ←→ Post-Exploitation
                                              ↓
                                      Proof-of-Concept → Post-Engagement
```

## Primary Goals of Web Reconnaissance

| Goal | Description |
|------|-------------|
| **Identifying Assets** | Uncover all publicly accessible components: web pages, subdomains, IP addresses, and technologies used |
| **Discovering Hidden Information** | Locate sensitive info inadvertently exposed: backup files, config files, internal documentation |
| **Analysing the Attack Surface** | Examine potential vulnerabilities and weaknesses in technologies, configurations, and entry points |
| **Gathering Intelligence** | Collect info for further exploitation or social engineering: key personnel, email addresses, behaviour patterns |

> **Key Insight:** Attackers use recon to tailor attacks and target specific weaknesses. Defenders use recon to proactively identify and patch vulnerabilities before malicious actors can exploit them.

---

## Types of Reconnaissance

### 🔴 Active Reconnaissance

**Direct interaction** with the target system. Higher risk of detection but yields more detailed information.

| Technique | Description | Example | Tools | Detection Risk |
|-----------|-------------|---------|-------|----------------|
| **Port Scanning** | Identifying open ports and running services | Using Nmap to scan for ports 80 (HTTP) and 443 (HTTPS) | Nmap, Masscan, Unicornscan | 🔴 **High** — Can trigger IDS/firewalls |
| **Vulnerability Scanning** | Probing for known vulnerabilities (outdated software, misconfigs) | Running Nessus to check for SQLi or XSS | Nessus, OpenVAS, Nikto | 🔴 **High** — Sends exploit payloads |
| **Network Mapping** | Mapping network topology and connected devices | Using traceroute to reveal network hops | Traceroute, Nmap | 🟡 **Medium-High** — Unusual traffic raises suspicion |
| **Banner Grabbing** | Retrieving service banners for version info | Connecting to port 80 to identify web server software | Netcat, curl | 🟢 **Low** — Minimal interaction, can be logged |
| **OS Fingerprinting** | Identifying the target's operating system | Using Nmap `-O` to detect Windows/Linux | Nmap, Xprobe2 | 🟢 **Low** — Usually passive, some advanced techniques detectable |
| **Service Enumeration** | Determining specific service versions on open ports | Using Nmap `-sV` to identify Apache 2.4.50 vs Nginx 1.18.0 | Nmap | 🟢 **Low** — Can be logged, unlikely to trigger alerts |
| **Web Spidering** | Crawling website to map pages, directories, and files | Running Burp Suite Spider to discover hidden resources | Burp Suite Spider, OWASP ZAP Spider, Scrapy | 🟡 **Medium** — Generates noticeable traffic patterns |

### 🔵 Passive Reconnaissance

**No direct interaction** with the target. Relies on publicly available information and resources. Stealthier but may yield less comprehensive data.

| Technique | Description | Example | Tools | Detection Risk |
|-----------|-------------|---------|-------|----------------|
| **Search Engine Queries** | Using search engines to uncover target information | Searching `"[Target] employees"` on Google | Google, DuckDuckGo, Bing, Shodan | 🟢 **Very Low** — Normal internet activity |
| **WHOIS Lookups** | Querying WHOIS databases for domain registration details | WHOIS lookup to find registrant name, contact info, name servers | `whois` CLI, online WHOIS services | 🟢 **Very Low** — Legitimate queries |
| **DNS Analysis** | Analysing DNS records for subdomains, mail servers, infrastructure | Using `dig` to enumerate subdomains | dig, nslookup, host, dnsenum, fierce, dnsrecon | 🟢 **Very Low** — Normal DNS queries |
| **Web Archive Analysis** | Examining historical website snapshots | Using Wayback Machine to view past versions of a site | Wayback Machine | 🟢 **Very Low** — Normal activity |
| **Social Media Analysis** | Gathering info from LinkedIn, Twitter, Facebook | Searching LinkedIn for employee roles and responsibilities | LinkedIn, Twitter, Facebook, OSINT tools | 🟢 **Very Low** — Public profile access |
| **Code Repositories** | Analysing public repos for exposed credentials/vulnerabilities | Searching GitHub for target-related code with sensitive info | GitHub, GitLab | 🟢 **Very Low** — Repos are public by design |

---

## Active vs Passive — Quick Comparison

| Factor | Active | Passive |
|--------|--------|---------|
| **Target Interaction** | Direct | None |
| **Detection Risk** | Higher | Very Low |
| **Information Depth** | More comprehensive | Limited to public data |
| **Legal Considerations** | Requires authorization | Generally safe |
| **Examples** | Port scanning, vulnerability scanning | WHOIS, Google dorking, DNS lookups |

---

## Key Takeaways

1. **Always start with passive recon** — gather as much as you can without touching the target
2. **Active recon requires authorization** — port scanning and vulnerability scanning can trigger alarms and may be illegal without permission
3. **Both approaches complement each other** — passive recon informs and focuses your active recon efforts
4. **Information gathering is iterative** — findings from one technique feed into others throughout the penetration test
5. **This module starts with WHOIS** as the foundation, then builds to more advanced techniques

---

## Module Roadmap

```
WHOIS → DNS Enumeration → Passive Recon (OSINT) → Active Recon → Virtual Hosts → Web Fingerprinting
```
