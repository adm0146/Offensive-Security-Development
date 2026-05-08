# Information Gathering — Web Edition — Exam Cheatsheet

**Distilled from HTB Academy "Information Gathering — Web Edition" + Skills Assessment (inlanefreight.htb).** Open this during the exam.

---

## The Universal Web Recon Methodology

```
1. /etc/hosts FIRST — .htb domains don't resolve publicly
2. WHOIS / DNS — registrar, NS, MX, A, TXT, CNAME
3. Subdomain brute — first level AND nested (FUZZ.sub.dom.htb)
4. VHost fuzz — same IP, different Host: header
5. Fingerprint — server, framework, CMS
6. robots.txt + .well-known + sitemap.xml
7. Crawl — gospider / ReconSpider for emails, comments, links
8. Wayback / crt.sh / Google dorks for OSINT angle
```

> **Forever rule:** When the main page is bare HTML with no links, the content is on a **nested subdomain or vhost** — fuzz harder.

---

## Stage 0 — /etc/hosts Discipline

```bash
echo "10.129.X.X inlanefreight.htb www.inlanefreight.htb dev.inlanefreight.htb" | sudo tee -a /etc/hosts
```
Every new subdomain you discover → add it before curl/crawler can hit it.

---

## Stage 1 — DNS / WHOIS / Records

```bash
whois inlanefreight.com
whois inlanefreight.com | grep -iE "registrar|iana|name server|emails"

# Records
dig inlanefreight.htb @TARGET ANY
dig inlanefreight.htb @TARGET +short
dig MX inlanefreight.htb @TARGET
dig TXT inlanefreight.htb @TARGET
dig NS inlanefreight.htb @TARGET
dig AXFR @TARGET inlanefreight.htb                   # ALWAYS try
dig AXFR @ns1.inlanefreight.htb dev.inlanefreight.htb  # also child zones

host -t mx inlanefreight.htb
nslookup -type=any inlanefreight.htb TARGET
```

### Subdomain brute (DNS)
```bash
gobuster dns -d inlanefreight.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 30
dnsenum --enum inlanefreight.htb -f subdomains.txt
fierce --domain inlanefreight.htb
amass enum -passive -d inlanefreight.com
```

### Certificate Transparency (passive subdomain harvest)
```bash
curl -s "https://crt.sh/?q=%25.inlanefreight.com&output=json" | jq -r '.[].name_value' | sort -u
```

---

## Stage 2 — VHost / Nested Subdomain Brute (THE assessment trick)

```bash
# 1. Get default response size for a non-existent vhost
curl -s -o /dev/null -w "%{size_download}\n" -H "Host: nope.inlanefreight.htb" http://TARGET/
# → 120

# 2. Fuzz Host header, filter that size
ffuf -u http://TARGET/ \
     -H "Host: FUZZ.inlanefreight.htb" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -fs 120 -t 100

# 3. Found web1337? Now fuzz NESTED:
ffuf -u http://web1337.inlanefreight.htb:PORT/ \
     -H "Host: FUZZ.web1337.inlanefreight.htb" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -fs 120 -t 100

# gobuster equivalent
gobuster vhost -u http://TARGET -w subdomains.txt --append-domain --domain inlanefreight.htb --exclude-length 120
```

> **Key insight:** Always fuzz at every depth: `FUZZ.dom.htb`, then `FUZZ.sub.dom.htb`. Skills Assessment hid email behind `dev.web1337.inlanefreight.htb`.

---

## Stage 3 — Fingerprint

```bash
curl -I http://target                                # Server, X-Powered-By
curl -sI -H "Host: x" http://TARGET | grep -iE "server|powered|set-cookie"
whatweb http://target
whatweb -a 3 http://target
wappalyzer (browser ext)                             # tech stack visual
nikto -h http://target
nuclei -u http://target -t technologies/

# WAF
wafw00f http://target
```

---

## Stage 4 — robots.txt / .well-known / sitemap

```bash
curl -s http://target/robots.txt
curl -s http://target/sitemap.xml
curl -s http://target/.well-known/security.txt
curl -s http://target/.well-known/openid-configuration
curl -s http://target/.git/HEAD                       # source code leak!
curl -s http://target/.env
curl -s http://target/.DS_Store
```

> **Skills Assessment Q3:** `/robots.txt` `Disallow: /admin_h1dd3n` → API key in plaintext.

### Common .well-known paths to check
```
/.well-known/security.txt
/.well-known/openid-configuration
/.well-known/assetlinks.json
/.well-known/apple-app-site-association
/.well-known/change-password
/.well-known/host-meta
```

---

## Stage 5 — Crawling (emails, links, comments)

```bash
# gospider — fast initial pass + robots discovery
gospider -s http://target -d 3 -t 10 -o /tmp/gospider/

# hakrawler
echo http://target | hakrawler -d 3

# katana (project discovery)
katana -u http://target -d 3 -jc -kf all -o crawl.txt

# ReconSpider — best for emails + HTML comments
python3 ReconSpider.py http://target
cat results.json | jq -r '.emails[]'
cat results.json | jq -r '.comments[]'                # ← future API keys live here
cat results.json | jq -r '.urls[]' | sort -u

# Wget mirror (offline grep)
wget --recursive --no-clobber --no-parent --level=3 -P /tmp/mirror http://target
grep -rE "password|api[_-]?key|secret|token" /tmp/mirror | head
```

### What to grep crawl output for
```
password|passwd|pwd
api[-_]?key|apikey|access[-_]?token|secret
@inlanefreight.htb       # emails
TODO|FIXME|XXX           # dev notes
http://(192|10|172)\.    # internal URLs
```

---

## Stage 6 — Directory / File Brute Force

```bash
gobuster dir -u http://target -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt,bak -t 50
ffuf  -u http://target/FUZZ -w raft-medium-directories.txt -e .php,.html,.txt,.bak -mc 200,204,301,302,401,403 -fc 404 -t 100
feroxbuster -u http://target -w raft-medium-words.txt -x php,html -d 3

# JS endpoint discovery
katana -u http://target -jc -d 3 | grep -iE '\.js$' | sort -u | xargs -I{} curl -s {} | grep -oE '["'\''](/[a-zA-Z0-9_/.-]+)["'\'']'
```

---

## Stage 7 — Web Archives & Search

```bash
# Wayback URLs
curl -s "https://web.archive.org/cdx/search/cdx?url=*.inlanefreight.com/*&output=text&fl=original&collapse=urlkey" | head
waybackurls inlanefreight.com | tee wayback.txt
gau inlanefreight.com

# Find params from wayback
cat wayback.txt | grep '?' | unfurl keys | sort -u
```

### Google dorks (cheat list)
```
site:inlanefreight.com -www
site:inlanefreight.com filetype:pdf
site:inlanefreight.com inurl:admin
site:inlanefreight.com intext:"password"
site:inlanefreight.com ext:env | ext:sql | ext:bak | ext:old
intitle:"index of /" site:inlanefreight.com
"@inlanefreight.com" -site:inlanefreight.com           # employee emails
```

### GitHub OSINT
```bash
github-search -u inlanefreight                         # repos
gitleaks detect --source . -v                          # secrets in repo
trufflehog github --repo https://github.com/x/y
```

---

## Stage 8 — Skills Assessment Recap (inlanefreight.htb)

| Q | Skill | Tool | Answer |
|---|-------|------|--------|
| 1 | WHOIS IANA ID | `whois inlanefreight.com` | `468` |
| 2 | Server fingerprint | `curl -I` | `nginx` |
| 3 | robots.txt → admin dir → API | `curl /robots.txt` → `/admin_h1dd3n/` | `e963d863ee0e82ba7080fbf558ca0d3f` |
| 4 | Nested subdomain → crawl → email | ffuf vhost + ReconSpider | `1337testing@inlanefreight.htb` |
| 5 | Future API key (HTML comment) | `jq -r '.comments[]'` | `ba988b835be4aa97d068941dc852ff33` |

---

## STUCK? Triage

| Symptom | Fix |
|---------|-----|
| Crawl returns nothing | page has no links → fuzz nested vhosts |
| ffuf shows ALL words "found" | catch-all response — filter with `-fs SIZE` (`curl ... -w "%{size_download}"` for baseline) |
| `whois` empty / GDPR-redacted | use `crt.sh`, `dnsdumpster`, `securitytrails` instead |
| AXFR refused on apex | try child zones (`dig NS` first), or per-NS server |
| robots.txt empty | check `.well-known/`, `sitemap.xml`, `.git/HEAD`, `.env` |
| Subdomain brute returns 0 | wordlist too small — try `subdomains-top1million-110000.txt` or `bitquark-subdomains-top100000.txt` |
| `Forbidden` on every dir | virtual host mismatch — set `Host:` header correctly |
| .htb domain "could not resolve" | forgot `/etc/hosts` |

---

## Wordlists

| File | When |
|------|------|
| `seclists/Discovery/DNS/subdomains-top1million-5000.txt` | first DNS pass |
| `seclists/Discovery/DNS/subdomains-top1million-110000.txt` | exhaustive |
| `seclists/Discovery/DNS/bitquark-subdomains-top100000.txt` | smarter alt |
| `seclists/Discovery/Web-Content/raft-medium-directories.txt` | dirs |
| `seclists/Discovery/Web-Content/raft-medium-words.txt` | files+dirs |
| `seclists/Discovery/Web-Content/common.txt` | quick pass |
| `seclists/Discovery/Web-Content/big.txt` | broad |
| `seclists/Discovery/Web-Content/api/*` | API endpoints |

---

## Reference Tools Cheat

| Tool | Purpose |
|------|---------|
| `whois` | registrar / IANA ID |
| `dig` / `host` / `nslookup` | DNS records, AXFR |
| `gobuster dns` / `dnsenum` / `fierce` | subdomain brute |
| `ffuf` / `gobuster vhost` | vhost brute (Host header) |
| `crt.sh` / `amass` | passive subdomain enum |
| `whatweb` / `wappalyzer` / `nuclei` | tech fingerprint |
| `wafw00f` | WAF detect |
| `gospider` / `katana` / `hakrawler` | crawl |
| `ReconSpider` | crawl + email/comment extract |
| `waybackurls` / `gau` | archive URLs |
| `nikto` | dumb but effective vuln pass |
| `gitleaks` / `trufflehog` | repo secrets |

---

## References

- [19-Skills_Assessment.md](19-Skills_Assessment.md) — full walkthrough
- Per-section: [02-WHOIS.md](02-WHOIS.md), [04-DNS.md](04-DNS.md), [06-Subdomains.md](06-Subdomains.md), [07-Subdomain_Bruteforcing.md](07-Subdomain_Bruteforcing.md), [08-DNS_Zone_Transfers.md](08-DNS_Zone_Transfers.md), [09-Virtual_Hosts.md](09-Virtual_Hosts.md), [11-Fingerprinting.md](11-Fingerprinting.md), [12-Crawling.md](12-Crawling.md), [13-robots_txt.md](13-robots_txt.md), [14-Well_Known_URIs.md](14-Well_Known_URIs.md), [15-Creepy_Crawlies.md](15-Creepy_Crawlies.md), [16-Search_Engine_Discovery.md](16-Search_Engine_Discovery.md), [17-Web_Archives.md](17-Web_Archives.md), [18-Automating_Recon.md](18-Automating_Recon.md)
