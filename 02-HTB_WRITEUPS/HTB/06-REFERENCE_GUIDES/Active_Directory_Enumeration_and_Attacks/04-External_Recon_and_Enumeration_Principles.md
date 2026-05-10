# Section 4 — External Recon and Enumeration Principles

## Why External Recon?

Before touching anything internal, passive external recon lets you:
- Validate the scoping document (are you targeting the right IPs/domains?)
- Ensure you stay within authorized scope when working remotely
- Surface leaked credentials, internal naming conventions, or infrastructure details that change your attack plan

If you hit a wall during internal testing, external recon data (breach passwords, VPN portals, schema formats) can provide the nudge to get back in.

---

## What to Look For

| Data Point | Goal |
|------------|------|
| **IP Space** | ASN, netblocks, cloud hosting providers, DNS records |
| **Domain Info** | Subdomains, mail servers, DNS servers, externally exposed services, defenses (SIEM/AV/IPS hints) |
| **Schema Format** | Email format, AD username convention, password policy → build spray/stuff lists |
| **Data Disclosures** | Public files (.pdf, .docx, .xlsx) with metadata, intranet links, internal hostnames, credentials in GitHub |
| **Breach Data** | Leaked usernames/passwords to test against VPN, OWA, Citrix, RDS, etc. |

---

## Where to Look

| Resource | Examples / Tools |
|----------|-----------------|
| **ASN / IP registrars** | [bgp.he.net](https://bgp.he.net), IANA, ARIN (Americas), RIPE (Europe) |
| **Domain / DNS** | Domaintools, viewdns.info, PTRArchive, ICANN, `nslookup`, `dig` |
| **Social media** | LinkedIn, Twitter, Facebook, Instagram |
| **Company website** | About Us, Contact Us, press releases, embedded docs |
| **Cloud / dev storage** | GitHub (Trufflehog), AWS S3, Azure Blob (Greyhat Warfare), Google dorks |
| **Breach data** | HaveIBeenPwned, Dehashed |

---

## Key Recon Techniques

### ASN / IP Space — BGP Toolkit
```
https://bgp.he.net
```
- Search domain or IP → get assigned netblocks and ASN
- Large corps → own ASN (self-hosted)
- Small orgs → likely on Cloudflare / AWS / Azure (hosted infra)

**Important:** Confirm hosting before scanning. Third-party hosted infra requires written approval from the provider, not just the client. AWS has its own pentest policy; Oracle requires a Cloud Security Testing Notification.

---

### DNS Validation — viewdns.info + nslookup
```bash
# Validate nameservers
nslookup ns1.target.com
nslookup ns2.target.com

# Pull ALL record types at once — always use this
dig any target.com
dig any target.com @8.8.8.8
```

**Always check TXT records** — they commonly contain SPF/DKIM config, domain verification tokens, and occasionally sensitive internal info that shouldn't be public. `dig any` pulls all record types in one shot — make it your default.

Cross-reference IP addresses from BGP with viewdns reverse IP lookup. Mismatches may indicate CDN/proxy (Cloudflare) in front of real infra.

---

### Google Dorks

```
# Find public PDFs/docs
filetype:pdf inurl:target.com
filetype:xlsx inurl:target.com
filetype:docx inurl:target.com

# Hunt email addresses (reveals naming schema)
intext:"@target.com" inurl:target.com

# Find login/intranet portals
inurl:target.com intext:"login"
inurl:target.com intitle:"intranet"
```

Documents often contain:
- Author metadata with AD username format
- Links to internal shares or intranet sites
- Org chart data, software/hardware stack details

---

### Job Postings (LinkedIn, Indeed, Glassdoor)

Job listings accidentally reveal:
- Software versions in use (e.g., SharePoint 2013 + 2016 → likely upgraded in place → old vulns)
- Cloud providers and internal tooling
- Security tooling (SIEM, EDR, AV product names)
- Username/email format from HR postings

---

### LinkedIn Username Harvesting

```bash
# linkedin2username — scrapes LinkedIn, generates username format permutations
# Output: flast, first.last, f.last, firstlast, etc.
python3 linkedin2username.py -u YOUR_LI_EMAIL -p YOUR_LI_PASS -c "Target Company"
```

Feed output into password spray wordlist once you've confirmed naming convention from emails or documents.

---

### GitHub / Code Repo Hunting — Trufflehog

```bash
# Scan a GitHub org for secrets
trufflehog github --org=TargetOrg

# Scan a specific repo
trufflehog git https://github.com/target/repo
```

Also: [Greyhat Warfare](https://buckets.grayhatwarfare.com) for exposed AWS S3 / Azure Blob storage.

---

### Breach Data — Dehashed

```bash
# Query Dehashed API for domain
sudo python3 dehashed.py -q target.local -p
```

Output includes cleartext passwords and hashes. Use against:
- VPN portals
- OWA / O365
- Citrix / RDS
- Any AD-authenticated external service

---

## Overarching Enumeration Principles

1. **Passive first, wide then narrow** — start with no direct target interaction, broaden scope, then tighten
2. **Iterative** — you will loop back to enumeration multiple times during a test; new access = new recon
3. **Document everything immediately** — save files, screenshots, tool output as you find it; don't trust memory
4. **Validate all data** — cross-reference sources; BGP + viewdns + nslookup confirms a finding is real
5. **Never assume scope** — if a host is on a third-party provider or looks out of scope, confirm in writing before touching it

---

## Practical Workflow (inlanefreight.com example)

```
1. BGP toolkit → IP, mail server, nameservers
2. viewdns.info → validate IP, reverse IP (find co-hosted domains)
3. nslookup ns1/ns2 → get additional IPs
4. Google dork filetype:pdf → download, inspect metadata
5. Google dork intext:"@domain" → email format confirmed (first.last)
6. LinkedIn scrape → username list
7. Dehashed → breach password candidates
8. Build spray list → test against any exposed auth portals
```

---

## Exam Notes

- External recon is **pre-foothold** — all passive, no scanning
- Username format from emails/docs = gold for spraying internally later
- Breach passwords + AD-authenticated portals (OWA, VPN, Citrix) = low-privilege foothold
- Even without a foothold, a standard domain user account unlocks the majority of internal AD enumeration
- Stay in scope: third-party hosted infra requires explicit written authorization from the *provider*, not just the client
