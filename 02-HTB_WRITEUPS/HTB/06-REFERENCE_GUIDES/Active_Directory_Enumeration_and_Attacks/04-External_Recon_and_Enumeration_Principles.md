# Section 04 — External Recon & Enumeration Principles

> No lab questions. Pre-foothold passive recon — done before touching internal network.

---

## QUICK REFERENCE — External Recon Commands

```bash
# DNS — pull all record types at once
dig any target.com @8.8.8.8
nslookup ns1.target.com

# Google dorks
filetype:pdf inurl:target.com          # documents with metadata
intext:"@target.com" inurl:target.com  # email addresses → naming format
inurl:target.com intext:"login"        # exposed portals

# LinkedIn username scraping
python3 linkedin2username.py -u YOUR_EMAIL -p YOUR_PASS -c "Company Name"

# GitHub secret hunting
trufflehog github --org=TargetOrg
trufflehog git https://github.com/target/repo

# Breach data
sudo python3 dehashed.py -q target.local -p
```

---

## What to Look For

| Data Point | Goal |
|------------|------|
| IP space / ASN | Netblocks, cloud providers, hosting |
| Domain info | Subdomains, mail servers, DNS servers, exposed services |
| Email / username format | Build spray list (e.g. first.last, flast) |
| Document metadata | AD username format from Author field (`exiftool file.pdf`) |
| GitHub / code repos | Hardcoded credentials, internal hostnames |
| Breach data | Leaked passwords → test against VPN, OWA, Citrix |

---

## Where to Look

| Resource | Tool / URL |
|----------|-----------|
| ASN / IP registrars | bgp.he.net, ARIN, RIPE |
| Domain / DNS | viewdns.info, nslookup, dig |
| Social media | LinkedIn, Twitter |
| Cloud / dev storage | GitHub (Trufflehog), AWS S3 (Greyhat Warfare) |
| Breach data | HaveIBeenPwned, Dehashed |
| Company site | About Us, press releases, job postings, embedded docs |

---

## Recon Workflow (inlanefreight.com example)

```
1. bgp.he.net          → IP space, ASN, mail/nameservers
2. viewdns.info        → validate IP, reverse IP lookup
3. dig any target.com  → all DNS records at once
4. Google dork filetype:pdf → download docs, run exiftool → username format
5. Google dork intext:"@domain" → confirm email format
6. LinkedIn scrape     → build username list
7. Dehashed            → breach password candidates
8. Test breach creds against any AD-authenticated portal (OWA, VPN, Citrix)
```

---

## Exam Notes

- All external recon is passive — no scanning, no direct interaction with target systems
- Username format from emails/docs = gold for internal spraying later
- Breach passwords + AD-authenticated portals = potential low-priv foothold
- Third-party hosted infra (AWS, Azure, Cloudflare) requires written authorization from the **provider**, not just the client
- `dig any` pulls all record types — make it your default over single-type queries
- Job postings reveal software versions, security tooling, cloud providers
