# 🔐 Certificate Transparency Logs

## Overview

Certificate Transparency (CT) logs are **public ledgers** that record every SSL/TLS certificate issued by a Certificate Authority. When a CA issues a cert, it gets logged — and those logs are searchable. For recon, this means you can find **every subdomain that has ever had a certificate issued for it** without brute-forcing or guessing.

**Why CT logs beat brute-forcing:**
- Not limited by wordlist size or quality
- Reveals **historical** subdomains (old/expired certs = potentially vulnerable hosts)
- Finds subdomains you would never guess (e.g., `web17611.inlanefreight.htb`)
- Completely **passive** — no interaction with the target

---

## Tools for Searching CT Logs

| Tool | How to Access | Best For |
|---|---|---|
| **crt.sh** | `https://crt.sh/?q=%.domain.com` | Quick searches, free, no registration |
| **Censys** | `https://search.censys.io` | Advanced filtering, API access, deeper analysis |

---

## crt.sh — Web Interface

Browse to:

```
https://crt.sh/?q=%.target.com
```

The `%` is a wildcard — returns all certs for the domain and its subdomains.

---

## crt.sh — Command Line with curl + jq

### Core Command

```bash
curl -s "https://crt.sh/?q=<domain>&output=json" | jq -r '.[] | .name_value' | sort -u
```

### Filter for Specific Subdomains

```bash
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
```

### Example Output

```
*.dev.facebook.com
*.newdev.facebook.com
*.secure.dev.facebook.com
dev.facebook.com
devvm1958.ftw3.facebook.com
facebook-amex-dev.facebook.com
facebook-amex-sign-enc-dev.facebook.com
newdev.facebook.com
secure.dev.facebook.com
```

### Breaking Down the Command

| Part | What It Does |
|---|---|
| `curl -s` | Fetch the URL silently (no progress bar) |
| `?q=facebook.com&output=json` | Query crt.sh for the domain, return JSON |
| `jq -r '.[] \| .name_value'` | Extract the `name_value` field (domain/subdomain) from each cert |
| `select(.name_value \| contains("dev"))` | Filter — only entries containing "dev" |
| `sort -u` | Sort alphabetically and remove duplicates |

---

## What to Look For in CT Log Results

| Finding | Recon Value |
|---|---|
| **Active subdomains** (`dev.`, `staging.`, `admin.`) | New targets to enumerate |
| **Wildcard certs** (`*.dev.target.com`) | Entire subdomain trees exist under that prefix |
| **Old/expired cert subdomains** | May host outdated software with known CVEs |
| **Internal-sounding names** (`devvm1958.`, `internal.`) | Leaked internal infrastructure naming |
| **Third-party service subdomains** | Reveals services and integrations the target uses |

---

## Key Takeaways

- CT logs are **passive recon** — no interaction with the target, no detection risk
- `crt.sh` is free, no registration, works from browser or command line
- The `curl + jq` pipeline lets you **filter and automate** CT log searches
- CT logs find subdomains that **brute-forcing would miss** — they are a historical record, not a guess
- Always check CT logs **before** brute-forcing — you may already have what you need
- Old certificate subdomains = potentially **vulnerable hosts** with outdated configs

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
