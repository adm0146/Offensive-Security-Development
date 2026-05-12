# Section 7 — Sub-domain Fuzzing

> Fuzz for public subdomains (*.domain.com) by placing FUZZ in the subdomain position of the URL.

---

## Lab Answer

| Question | Answer |
|----------|--------|
| Customer sub-domain portal on inlanefreight.com | `customer.inlanefreight.com` |

---

## How It Works

Place `FUZZ` in the subdomain position of the URL. ffuf tries every wordlist entry as a subdomain and reports which ones resolve and respond.

```bash
ffuf -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u https://FUZZ.inlanefreight.com/ \
  -mc 200,301,302,307,401,403 \
  -t 100
```

**This only finds public subdomains** — ones that have a real DNS record pointing to a live server. It will not find internal/HTB lab vhosts this way.

---

## Wordlists for Subdomain Fuzzing

```bash
~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt    # fast — 5k entries, good starting point
~/SecLists/Discovery/DNS/subdomains-top1million-20000.txt   # medium — 20k entries
~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt  # thorough — 110k entries
~/SecLists/Discovery/DNS/dns-Jhaddix.txt                    # alternative broad list
```

Start with 5000. If nothing interesting, step up to 20000.

---

## Public vs. Private Subdomains

| Scenario | Method | Why |
|----------|--------|-----|
| Public domain (inlanefreight.com) | Subdomain fuzzing (`FUZZ.domain.com`) | DNS resolves hits to real IPs |
| HTB/internal domain (academy.htb) | Vhost fuzzing via `Host:` header | Not in public DNS — use next section |

Running subdomain fuzzing against `academy.htb` returns 4997 errors — not because there are no subdomains, but because they don't exist in public DNS. Use **vhost fuzzing** for those (Section 8).

---

## Exam Notes

- Subdomain fuzzing = DNS-based — only works on real public domains
- For HTB lab targets: always use vhost fuzzing (Section 8), not subdomain fuzzing
- `-mc 200,301,302,307,401,403` — include 403 as a hit (the subdomain exists, just restricted)
- A "customer portal" subdomain is a high-value target — likely has a login page worth attacking
- After finding a subdomain, visit it and enumerate further (dir fuzzing, login brute force, etc.)
