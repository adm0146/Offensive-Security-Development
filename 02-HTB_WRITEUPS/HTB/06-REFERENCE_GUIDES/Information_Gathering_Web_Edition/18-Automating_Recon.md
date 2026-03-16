# 18 — Automating Recon

> Stop doing manually what a framework can do in seconds — FinalRecon, theHarvester, Recon-ng, and SpiderFoot.

---

## Why Automate?

- **Speed** — tools run hundreds of queries while you'd do one
- **Scale** — scan multiple targets/domains simultaneously
- **Consistency** — no missed steps, reproducible results
- **Coverage** — DNS, subdomains, headers, SSL, crawling, Wayback all in one run

---

## Recon Frameworks Overview

| Tool | Language | Best For |
|---|---|---|
| **FinalRecon** | Python | All-in-one web recon — headers, WHOIS, SSL, crawl, DNS, subs, dirs, Wayback |
| **theHarvester** | Python | Emails, subdomains, hosts, employee names from public sources |
| **Recon-ng** | Python | Modular framework — DNS, subs, ports, crawling, exploit integration |
| **SpiderFoot** | Python | OSINT automation — IPs, domains, emails, social media, integrates many data sources |
| **OSINT Framework** | Web-based | Collection of tools/resources organized by category |

---

## FinalRecon — Setup & Usage

### Install

```bash
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt --break-system-packages
chmod +x ./finalrecon.py
./finalrecon.py --help
```

### Flags Reference

| Flag | What It Does |
|---|---|
| `--url URL` | Set the target |
| `--headers` | Grab response headers |
| `--sslinfo` | SSL certificate details |
| `--whois` | WHOIS lookup |
| `--crawl` | Spider the site (HTML, CSS, JS, links, images, robots.txt, sitemap) |
| `--dns` | DNS enumeration (40+ record types including DMARC) |
| `--sub` | Subdomain enumeration (crt.sh, AnubisDB, ThreatMiner, Shodan, etc.) |
| `--dir` | Directory brute-force (custom wordlists + extensions) |
| `--wayback` | Wayback Machine URLs (last 5 years) |
| `--ps` | Fast port scan |
| `--full` | Run EVERYTHING |

### Extra Options

| Flag | What It Does | Default |
|---|---|---|
| `-dt` | Threads for directory enum | 30 |
| `-pt` | Threads for port scan | 50 |
| `-T` | Request timeout (seconds) | 30.0 |
| `-w` | Custom wordlist path | dirb_common.txt |
| `-r` | Allow redirects | False |
| `-s` | Toggle SSL verification | True |
| `-e` | File extensions to search | -- |
| `-o` | Export format | txt |
| `-k` | API key (e.g., `shodan@key`) | -- |

---

## Common FinalRecon Commands

```bash
# Headers + WHOIS
./finalrecon.py --headers --whois --url http://TARGET

# Full recon (everything)
./finalrecon.py --full --url http://TARGET

# Subdomain enumeration only
./finalrecon.py --sub --url http://TARGET

# Crawl + DNS
./finalrecon.py --crawl --dns --url http://TARGET

# Directory brute-force with custom wordlist and extensions
./finalrecon.py --dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -e php,txt,bak --url http://TARGET

# Wayback URLs
./finalrecon.py --wayback --url http://TARGET
```

---

## What FinalRecon Extracts

| Module | Intel Gathered |
|---|---|
| **Headers** | Server version, technologies, security headers, API endpoints (wp-json) |
| **WHOIS** | Registrar, creation/expiry dates, name servers, abuse contacts |
| **SSL** | Certificate validity, issuer, SANs (alternative domain names) |
| **Crawl** | Internal/external links, JS files, images, robots.txt, sitemap.xml |
| **DNS** | A, AAAA, MX, NS, TXT, DMARC, SOA + 40 more record types |
| **Subdomains** | From crt.sh, ThreatMiner, CertSpotter, Shodan, VirusTotal |
| **Wayback** | Historical URLs — old pages, removed content, old endpoints |

---

## Example Output Analysis

```
[!] Headers :
Server : Apache/2.4.41 (Ubuntu)
Link : <.../wp-json/>; rel="https://api.w.org/"
```

| Finding | Recon Value |
|---|---|
| `Apache/2.4.41 (Ubuntu)` | Exact server version + OS — check for CVEs |
| `wp-json` in Link header | Confirms WordPress — enumerate users, plugins |
| WHOIS: `Amazon Registrar` + AWS name servers | Hosted on AWS — check for S3 buckets, EC2 metadata |
| WHOIS: `Creation Date: 2019` | Relatively new domain |

---

## Key Takeaways

- **`--full` runs everything** — use it when you want comprehensive recon in one command
- **FinalRecon exports results** to `~/.local/share/finalrecon/dumps/` — review later
- **Combine with manual recon** — automation finds the leads, you analyze them
- **Add API keys** (`-k shodan@KEY`) for deeper subdomain and port data
- **PEP 668 fix** — use `--break-system-packages` when installing on Kali
- **theHarvester** is better for email harvesting; **FinalRecon** is better for full web recon

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
