# 🔍 Digging DNS

## Overview

With a solid understanding of DNS fundamentals and record types, it's time to get practical. This section covers the **tools and techniques** for leveraging DNS in web reconnaissance — from manual lookups with `dig` to automated enumeration with specialized tools.

---

## DNS Reconnaissance Tools

| Tool | Key Features | Use Cases |
|------|-------------|-----------|
| **`dig`** | Versatile DNS lookup tool supporting various query types (A, MX, NS, TXT, etc.) with detailed output | Manual DNS queries, zone transfers (if allowed), troubleshooting DNS issues, in-depth analysis of DNS records |
| **`nslookup`** | Simpler DNS lookup tool, primarily for A, AAAA, and MX records | Basic DNS queries, quick checks of domain resolution and mail server records |
| **`host`** | Streamlined DNS lookup tool with concise output | Quick checks of A, AAAA, and MX records |
| **`dnsenum`** | Automated DNS enumeration tool with dictionary attacks, brute-forcing, zone transfers | Discovering subdomains and gathering DNS information efficiently |
| **`fierce`** | DNS reconnaissance and subdomain enumeration with recursive search and wildcard detection | User-friendly interface for DNS recon, identifying subdomains and potential targets |
| **`dnsrecon`** | Combines multiple DNS recon techniques, supports various output formats | Comprehensive DNS enumeration, identifying subdomains, gathering DNS records for further analysis |
| **`theHarvester`** | OSINT tool gathering info from various sources, including DNS records and email addresses | Collecting email addresses, employee information, and other data associated with a domain |
| **Online DNS Lookup Services** | User-friendly web interfaces for performing DNS lookups | Quick and easy DNS lookups when command-line tools aren't available, checking domain availability |

---

## The Domain Information Groper (`dig`)

The `dig` command (Domain Information Groper) is a versatile and powerful utility for querying DNS servers and retrieving various types of DNS records. Its flexibility and detailed, customizable output make it a go-to choice for DNS reconnaissance.

### Common `dig` Commands

| Command | Description |
|---------|-------------|
| `dig domain.com` | Performs a default A record lookup for the domain |
| `dig domain.com A` | Retrieves the IPv4 address (A record) associated with the domain |
| `dig domain.com AAAA` | Retrieves the IPv6 address (AAAA record) associated with the domain |
| `dig domain.com MX` | Finds the mail servers (MX records) responsible for the domain |
| `dig domain.com NS` | Identifies the authoritative name servers for the domain |
| `dig domain.com TXT` | Retrieves any TXT records associated with the domain |
| `dig domain.com CNAME` | Retrieves the canonical name (CNAME) record for the domain |
| `dig domain.com SOA` | Retrieves the start of authority (SOA) record for the domain |
| `dig @1.1.1.1 domain.com` | Specifies a specific name server to query (in this case Cloudflare's `1.1.1.1`) |
| `dig +trace domain.com` | Shows the full path of DNS resolution |
| `dig -x 192.168.1.1` | Performs a reverse lookup on the IP address to find the associated hostname |
| `dig +short domain.com` | Provides a short, concise answer to the query |
| `dig +noall +answer domain.com` | Displays only the answer section of the query output |
| `dig domain.com ANY` | Retrieves all available DNS records for the domain |

> ⚠️ **Caution:** Some servers can detect and block excessive DNS queries. Respect rate limits and always obtain permission before performing extensive DNS reconnaissance on a target.

> 📝 **Note:** Many DNS servers ignore `ANY` queries to reduce load and prevent abuse, as per RFC 8482.

---

## Anatomy of a `dig` Query

```bash
adm0146@htb[/htb]$ dig google.com

; <<>> DiG 9.18.24-0ubuntu0.22.04.1-Ubuntu <<>> google.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16449
;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;google.com.                    IN      A

;; ANSWER SECTION:
google.com.             0       IN      A       142.251.47.142

;; Query time: 0 msec
;; SERVER: 172.23.176.1#53(172.23.176.1) (UDP)
;; WHEN: Thu Jun 13 10:45:58 SAST 2024
;; MSG SIZE  rcvd: 54
```

### Breaking Down the Output

| Section | Content | Explanation |
|---------|---------|-------------|
| **Header** | `opcode: QUERY, status: NOERROR, id: 16449` | Query type, success status, and unique query identifier |
| **Flags** | `qr rd ad` | `qr` = Query Response, `rd` = Recursion Desired, `ad` = Authentic Data (resolver considers data authentic) |
| **Counts** | `QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0` | Number of entries in each section of the DNS response |
| **Warning** | `recursion requested but not available` | Server does not support recursive queries |
| **Question Section** | `google.com. IN A` | The question: "What is the IPv4 address (A record) for google.com?" |
| **Answer Section** | `google.com. 0 IN A 142.251.47.142` | The IP for google.com is `142.251.47.142`. The `0` is the TTL (time-to-live) for caching |
| **Query Time** | `0 msec` | Time taken to process the query and receive the response |
| **Server** | `172.23.176.1#53 (UDP)` | The DNS server that provided the answer and the protocol used |
| **Timestamp** | `Thu Jun 13 10:45:58 SAST 2024` | When the query was made |
| **Message Size** | `54 bytes` | Size of the DNS message received |

> 💡 **Tip:** An `OPT pseudosection` may sometimes appear in `dig` output. This is due to **Extension Mechanisms for DNS (EDNS)**, which allows additional features like larger message sizes and DNSSEC support.

### Quick Answer with `+short`

If you just want the answer without all the extra detail:

```bash
adm0146@htb[/htb]$ dig +short hackthebox.com

104.18.20.126
104.18.21.126
```

---

## Key Takeaways

1. **`dig` is your primary DNS recon tool** — flexible, detailed, and supports all record types
2. **Know the output sections** — Header, Question, Answer, and Footer each provide valuable context
3. **Use `+short` for quick lookups** and `+noall +answer` for clean output
4. **Automated tools** like `dnsenum`, `fierce`, and `dnsrecon` scale up DNS enumeration beyond manual queries
5. **`theHarvester`** combines DNS with OSINT for broader reconnaissance (emails, employee info)
6. **Always respect rate limits** — excessive DNS queries can get you blocked and may violate terms of service

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
