# 🔨 Subdomain Brute-Forcing

## Overview

Subdomain brute-force enumeration is a powerful **active** subdomain discovery technique that leverages pre-defined lists of potential subdomain names. This approach systematically tests these names against the target domain to identify valid subdomains. By using carefully crafted wordlists, you can significantly increase the efficiency and effectiveness of your discovery efforts.

---

## How It Works

The brute-force process breaks down into four steps:

| Step | Action | Description |
|------|--------|-------------|
| 1 | **Wordlist Selection** | Choose a list of potential subdomain names to test |
| 2 | **Iteration & Querying** | A tool iterates through the wordlist, appending each word to the target domain (e.g., `dev.example.com`, `staging.example.com`) |
| 3 | **DNS Lookup** | A DNS query (A or AAAA record) is performed for each potential subdomain to check if it resolves to an IP address |
| 4 | **Filtering & Validation** | Valid subdomains are collected and further validated (e.g., attempting to access via web browser) |

### Wordlist Types

| Type | Description | When to Use |
|------|-------------|-------------|
| **General-Purpose** | Broad range of common names (`dev`, `staging`, `blog`, `mail`, `admin`, `test`) | When you don't know the target's naming conventions |
| **Targeted** | Focused on specific industries, technologies, or naming patterns | More efficient, reduces false positives |
| **Custom** | Created from keywords, patterns, or intelligence gathered from other sources | Best results when you have prior recon data |

---

## Brute-Force Tools

| Tool | Description |
|------|-------------|
| **`dnsenum`** | Comprehensive DNS enumeration tool supporting dictionary and brute-force attacks for discovering subdomains |
| **`fierce`** | User-friendly tool for recursive subdomain discovery with wildcard detection |
| **`dnsrecon`** | Versatile tool combining multiple DNS recon techniques with customisable output formats |
| **`amass`** | Actively maintained tool focused on subdomain discovery, integrates with other tools and extensive data sources |
| **`assetfinder`** | Simple yet effective tool using various techniques, ideal for quick and lightweight scans |
| **`puredns`** | Powerful and flexible DNS brute-forcing tool, capable of resolving and filtering results effectively |

---

## DNSEnum Deep Dive

`dnsenum` is a versatile command-line tool written in Perl that serves as a comprehensive toolkit for DNS reconnaissance.

### Key Functions

| Function | Description |
|----------|-------------|
| **DNS Record Enumeration** | Retrieves A, AAAA, NS, MX, and TXT records for a comprehensive overview of the target's DNS configuration |
| **Zone Transfer Attempts** | Automatically attempts zone transfers from discovered name servers — a successful attempt can reveal a treasure trove of DNS info |
| **Subdomain Brute-Forcing** | Systematically tests potential subdomain names from a wordlist against the target domain |
| **Google Scraping** | Scrapes Google search results to find additional subdomains not listed in DNS records directly |
| **Reverse Lookup** | Performs reverse DNS lookups to identify domains associated with a given IP, revealing other sites on the same server |
| **WHOIS Lookups** | Gathers information about domain ownership and registration details |

### Usage Example

```bash
adm0146@htb[/htb]$ dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r
```

| Flag | Purpose |
|------|---------|
| `--enum` | Shortcut for tuning options |
| `-f <wordlist>` | Path to the wordlist for brute-forcing |
| `-r` | Enable recursive subdomain brute-forcing (if a subdomain is found, enumerate subdomains of *that* subdomain) |

### Example Output

```
dnsenum VERSION:1.2.6

-----   inlanefreight.com   -----

Host's addresses:
__________________

inlanefreight.com.                       300      IN    A        134.209.24.248

[...]

Brute forcing with /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt:
_______________________________________________________________________________________

www.inlanefreight.com.                   300      IN    A        134.209.24.248
support.inlanefreight.com.               300      IN    A        134.209.24.248
[...]

done.
```

> 💡 **Tip:** The `subdomains-top1million-20000.txt` wordlist from **SecLists** contains the top 20,000 most common subdomains — a solid starting point for most engagements.

---

## Key Takeaways

1. **Subdomain brute-forcing is a 4-step process** — wordlist selection, iteration, DNS lookup, and validation
2. **Wordlist choice matters** — general-purpose for broad scans, targeted or custom for efficient, focused enumeration
3. **`dnsenum` is a Swiss Army knife** — it combines brute-forcing with zone transfers, Google scraping, reverse lookups, and WHOIS
4. **Recursive brute-forcing** (`-r` flag) digs deeper by enumerating subdomains of discovered subdomains
5. **SecLists** is your go-to source for quality wordlists (`/usr/share/seclists/Discovery/DNS/`)
6. **Multiple tools exist** — `amass`, `fierce`, `puredns`, and others each have strengths depending on the engagement

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
