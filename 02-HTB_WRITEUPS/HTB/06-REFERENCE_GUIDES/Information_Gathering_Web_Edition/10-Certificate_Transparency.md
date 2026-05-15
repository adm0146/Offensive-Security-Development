# 🔐 Certificate Transparency Logs

## Overview

Certificate Transparency (CT) logs are public records that track every SSL/TLS certificate issued by a Certificate Authority (CA). When a CA issues a certificate, it is logged — and those logs are searchable. For recon, this means you can find every subdomain that has ever had a certificate without brute-forcing or guessing.

CT logs beat brute-forcing for several reasons:
- They are not limited by wordlist size or quality.
- They reveal historical subdomains — old or expired certificates may point to vulnerable hosts.
- They find subdomains you would never guess, such as `web17611.inlanefreight.htb`.
- They are completely passive — no contact with the target.

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

The `%` is a wildcard. It returns all certificates for the domain and every subdomain.

---

## crt.sh — Command Line with curl + jq

### Core Command

```bash
curl -s "https://crt.sh/?q=<domain>&output=json" | jq -r '.[] | .name_value' | sort -u
```
> Queries crt.sh for all certificates issued to the domain and its subdomains. `output=json` returns machine-readable data. `jq -r '.[] | .name_value'` extracts the domain name from each certificate entry. `sort -u` removes duplicates. Replace `<domain>` with your target. No packets are sent to the target — this is entirely passive.

### Filter for Specific Subdomains

```bash
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
```
> Same command with an extra `select()` filter to show only certificate entries that contain "dev" in the name. Useful for narrowing results when the full output is very large. Replace "dev" with whatever naming pattern you are hunting for.

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

- CT logs are passive recon. No interaction with the target, no detection risk.
- crt.sh is free, requires no registration, and works from both the browser and command line.
- The `curl + jq` pipeline lets you filter and automate CT log searches.
- CT logs find subdomains that brute-forcing would miss — they are a historical record, not a guess.
- Always check CT logs before brute-forcing. You may already have what you need.
- Old certificate subdomains may point to vulnerable hosts running outdated software.

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
