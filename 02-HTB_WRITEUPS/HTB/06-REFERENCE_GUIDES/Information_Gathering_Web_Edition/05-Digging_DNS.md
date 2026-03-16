# 🔍 Digging DNS

## Overview

`dig` (Domain Information Groper) is the primary tool for querying DNS records. Flexible, detailed output, supports all record types. This is your go-to for DNS recon.

---

## dig Command Reference

| Command | What It Does |
|---|---|
| `dig domain.com` | Default A record lookup |
| `dig domain.com A` | IPv4 address |
| `dig domain.com AAAA` | IPv6 address |
| `dig domain.com MX` | Mail servers |
| `dig domain.com NS` | Authoritative name servers |
| `dig domain.com TXT` | TXT records (SPF, DKIM, verification) |
| `dig domain.com CNAME` | Canonical name (aliases) |
| `dig domain.com SOA` | Start of Authority record |
| `dig domain.com ANY` | All available records (often blocked — RFC 8482) |
| `dig @1.1.1.1 domain.com` | Query a specific DNS server (Cloudflare) |
| `dig @<TARGET_NS> domain.com` | Query the target own name server |
| `dig +trace domain.com` | Full resolution path from root → answer |
| `dig -x 192.168.1.1` | Reverse lookup — IP → hostname |
| `dig +short domain.com` | Clean answer only, no extra output |
| `dig +noall +answer domain.com` | Show only the answer section |

> ⚠️ Some servers block excessive DNS queries. Respect rate limits. Always have authorization.

---

## Anatomy of a dig Response

```bash
dig google.com
```

```
; <<>> DiG 9.18.24-0ubuntu0.22.04.1-Ubuntu <<>> google.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16449
;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;google.com.                    IN      A

;; ANSWER SECTION:
google.com.             0       IN      A       142.251.47.142

;; Query time: 0 msec
;; SERVER: 172.23.176.1#53(172.23.176.1) (UDP)
;; WHEN: Thu Jun 13 10:45:58 SAST 2024
;; MSG SIZE  rcvd: 54
```

### What Each Section Tells You

| Section | What to Look At |
|---|---|
| **Header** | `status: NOERROR` = query succeeded. `NXDOMAIN` = domain does not exist |
| **Flags** | `qr` = response, `rd` = recursion desired, `ad` = data authenticated |
| **Question** | Confirms what you asked for (`google.com IN A`) |
| **Answer** | The actual result — `142.251.47.142` is google.com IP |
| **Server** | Which DNS server answered — `172.23.176.1#53` |
| **Query Time** | Response speed — useful for detecting latency issues |

---

## Quick Lookups with +short

Skip all the noise — just get the answer:

```bash
dig +short hackthebox.com
```

```
104.18.20.126
104.18.21.126
```

Use `+short` when you just need the IP or value. Use the full output when you need to analyse flags, TTL, or the responding server.

---

## Other DNS Tools

| Tool | Best For | Example |
|---|---|---|
| **`nslookup`** | Quick A/MX checks | `nslookup domain.com` |
| **`host`** | One-line answer | `host domain.com` |
| **`dnsenum`** | Automated enumeration + brute-force | `dnsenum domain.com` |
| **`fierce`** | Recursive subdomain discovery | `fierce --domain domain.com` |
| **`dnsrecon`** | Comprehensive DNS recon | `dnsrecon -d domain.com` |
| **`theHarvester`** | DNS + OSINT (emails, employees) | `theHarvester -d domain.com -b google` |

> `dig` for manual queries. `dnsenum`/`dnsrecon` for automated enumeration. Use both.

---

## Key Takeaways

- **`dig` is your primary DNS tool** — learn the command syntax, it is used constantly
- **`+short`** for quick answers, full output for analysis
- **`@<server>`** to query specific name servers (especially the target own NS)
- **`ANY`** queries are often blocked — query specific record types instead
- **`-x`** for reverse lookups (IP → hostname)
- Automated tools (`dnsenum`, `dnsrecon`, `theHarvester`) scale beyond what manual `dig` can do

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
