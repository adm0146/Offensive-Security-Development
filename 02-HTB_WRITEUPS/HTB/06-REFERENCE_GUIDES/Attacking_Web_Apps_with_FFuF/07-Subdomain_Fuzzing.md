# Section 7 — Sub-domain Fuzzing

> Fuzz for public subdomains (*.domain.com) by placing FUZZ in the subdomain position of the URL.

---

## Lab Answer

| Question | Answer |
|----------|--------|
| Customer sub-domain portal on inlanefreight.com | `customer.inlanefreight.com` |

---

## How It Works

Put `FUZZ` in the subdomain spot of the URL. ffuf tries every wordlist entry as a subdomain and reports which ones exist and respond.

```bash
ffuf -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u https://FUZZ.inlanefreight.com/ \
  -mc 200,301,302,307,401,403 \
  -t 100
```
> `FUZZ` sits in the subdomain position of the URL. Each wordlist entry is tried as a subdomain and DNS resolves it. Only works on real public domains — not HTB internal targets. Include 403 in `-mc` because restricted subdomains still confirm the subdomain exists.

**This only finds public subdomains.** Each result needs a real DNS record pointing to a live server. It will not find internal or HTB lab vhosts this way.

---

## Wordlists for Subdomain Fuzzing

```bash
~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt    # fast — 5k entries, good starting point
~/SecLists/Discovery/DNS/subdomains-top1million-20000.txt   # medium — 20k entries
~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt  # thorough — 110k entries
~/SecLists/Discovery/DNS/dns-Jhaddix.txt                    # alternative broad list
```
> Start small (5k). These are paths, not commands — paste them into the `-w` flag of your ffuf command. The larger lists are thorough but slow for external DNS-based fuzzing.

Start with 5000. If nothing interesting, step up to 20000.

---

## Public vs. Private Subdomains

| Scenario | Method | Why |
|----------|--------|-----|
| Public domain (inlanefreight.com) | Subdomain fuzzing (`FUZZ.domain.com`) | DNS resolves hits to real IPs |
| HTB/internal domain (academy.htb) | Vhost fuzzing via `Host:` header | Not in public DNS — use next section |

Running subdomain fuzzing against `academy.htb` returns 4997 errors. Not because there are no subdomains — but because they're not in public DNS. Use **vhost fuzzing** for those (Section 8).

---

## Exam Notes

- Subdomain fuzzing = DNS-based — only works on real public domains
- For HTB lab targets: always use vhost fuzzing (Section 8), not subdomain fuzzing
- `-mc 200,301,302,307,401,403` — include 403 as a hit (the subdomain exists, just restricted)
- A "customer portal" subdomain is a high-value target — likely has a login page worth attacking
- After finding a subdomain, visit it and enumerate further (dir fuzzing, login brute force, etc.)
