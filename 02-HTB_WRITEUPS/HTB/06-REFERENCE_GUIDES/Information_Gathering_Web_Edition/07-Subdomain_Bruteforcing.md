# 🔨 Subdomain Brute-Forcing

## Overview

Subdomain brute-forcing systematically tests potential subdomain names from a wordlist against the target domain. Each word is prepended to the domain (e.g., `dev.target.com`) and a DNS query checks if it resolves to an IP.

---

## How It Works

```
Wordlist → Append each word to target domain → DNS lookup → Resolves? → Valid subdomain
```

| Step | What Happens |
|---|---|
| 1. **Wordlist loaded** | Tool reads a list of potential subdomain names |
| 2. **DNS query per word** | `dev.target.com` → A record lookup → does it resolve? |
| 3. **Valid subdomains collected** | Words that resolve to an IP are valid subdomains |
| 4. **Validate findings** | Browse to each discovered subdomain, run further enumeration |

---

## dnsenum — Primary Brute-Force Tool

### Core Command

```bash
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r
```

### Flags

| Flag | Purpose |
|---|---|
| `--enum` | Shortcut for tuning enumeration options |
| `-f <wordlist>` | Path to the subdomain wordlist |
| `-r` | Enable **recursive** brute-forcing — if `dev` is found, also brute-force `*.dev.target.com` |

### Example Output

```
dnsenum VERSION:1.2.6

-----   inlanefreight.com   -----

Host addresses:
__________________

inlanefreight.com.                       300      IN    A        134.209.24.248

Brute forcing with /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt:
_______________________________________________________________________________________

www.inlanefreight.com.                   300      IN    A        134.209.24.248
support.inlanefreight.com.               300      IN    A        134.209.24.248

done.
```

### What to Look For

| In the Output | What It Means |
|---|---|
| Subdomain resolves to **same IP** as main domain | Likely VHost on the same server |
| Subdomain resolves to **different IP** | Separate server — new target to scan |
| Subdomain resolves to **internal IP** (10.x, 172.16.x, 192.168.x) | Internal infrastructure leaked via DNS |

---

## Wordlist Selection

| Wordlist | Location | When to Use |
|---|---|---|
| **Top 5K** | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` | Quick initial check |
| **Top 20K** | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt` | Standard starting point |
| **Top 110K** | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt` | Deeper scan |
| **Custom** | Build from prior recon | Best results when you have intel on naming patterns |

> SecLists is pre-installed on Kali at `/usr/share/seclists/`

---

## Other Brute-Force Tools

| Tool | Command Example |
|---|---|
| **gobuster** | `gobuster dns -d target.com -w <wordlist> -t 50` |
| **amass** | `amass enum -d target.com -brute -w <wordlist>` |
| **fierce** | `fierce --domain target.com` |
| **puredns** | `puredns bruteforce <wordlist> target.com` |

---

## Key Takeaways

- **dnsenum** is the go-to brute-force tool — combines brute-forcing with zone transfers, Google scraping, and reverse lookups
- **`-r` flag** enables recursive brute-forcing — finds subdomains of subdomains
- **Wordlist choice matters** — start with top 20K, go deeper if needed
- Watch for subdomains resolving to **internal IPs** — that is leaked infrastructure
- **SecLists** (`/usr/share/seclists/Discovery/DNS/`) has all the wordlists you need

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
