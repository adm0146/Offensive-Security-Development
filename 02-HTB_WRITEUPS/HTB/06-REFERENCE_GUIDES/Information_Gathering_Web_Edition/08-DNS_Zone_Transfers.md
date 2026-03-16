# 🔄 DNS Zone Transfers

## Overview

A DNS zone transfer (`AXFR`) copies **all DNS records** from a primary name server to a secondary. If misconfigured, anyone can request the full zone file — dumping every subdomain, IP, mail server, and service record in one query. Low effort, massive payoff.

---

## The Command

```bash
dig axfr @<nameserver> <domain>
```

| Part | What It Does |
|---|---|
| `axfr` | Request a full zone transfer |
| `@<nameserver>` | The DNS server to query (get this from NS records) |
| `<domain>` | The target domain |

### Step 1: Find the Name Servers

```bash
dig NS inlanefreight.com +short
```

### Step 2: Attempt the Zone Transfer

```bash
dig axfr @ns1.inlanefreight.com inlanefreight.com
```

---

## What a Successful Transfer Looks Like

```bash
dig axfr @nsztm1.digi.ninja zonetransfer.me
```

```
zonetransfer.me.        7200    IN  SOA     nsztm1.digi.ninja. robin.digi.ninja. 2019100801 172800 900 1209600 3600
zonetransfer.me.        300     IN  HINFO   "Casio fx-700G" "Windows XP"
zonetransfer.me.        301     IN  TXT     "google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"
zonetransfer.me.        7200    IN  MX      0 ASPMX.L.GOOGLE.COM.
zonetransfer.me.        7200    IN  A       5.196.105.14
zonetransfer.me.        7200    IN  NS      nsztm1.digi.ninja.
zonetransfer.me.        7200    IN  NS      nsztm2.digi.ninja.
asfdbbox.zonetransfer.me.       7200  IN  A       127.0.0.1
canberra-office.zonetransfer.me. 7200 IN  A       202.14.81.230
[...]
;; XFR size: 50 records (messages 1, bytes 2085)
```

> ⚠️ **This is a jackpot.** Every DNS record in one query — no brute-forcing needed.

---

## What to Look For in the Output

| Record Found | What It Tells You |
|---|---|
| **A records** for subdomains | IPs of every subdomain — new targets to scan |
| **CNAME records** | Aliases revealing linked infrastructure |
| **MX records** | Mail server infrastructure |
| **TXT records** | Verification tokens, SPF policies, service info |
| **SRV records** | Specific services and ports (SIP, LDAP) |
| **Internal IPs** (127.0.0.1, 10.x, 192.168.x) | Leaked internal infrastructure |
| **HINFO records** | OS and hardware info (rare but valuable) |

---

## What a Failed Transfer Looks Like

```
; Transfer failed.
```

or

```
;; communications error: connection reset
```

Most modern servers block unauthorized transfers. **Always try it anyway** — it costs one command and the payoff is massive if it works.

---

## Practice Target

`zonetransfer.me` is intentionally misconfigured for practice:

```bash
dig axfr @nsztm1.digi.ninja zonetransfer.me
```

This will return a full zone file — safe, legal, and a great way to get familiar with the output.

---

## Key Takeaways

- **`dig axfr @<nameserver> <domain>`** — one command, potentially every DNS record
- **Always attempt a zone transfer** during authorized engagements — low effort, high reward
- Most modern servers block it, but **misconfigurations still happen**
- A successful transfer reveals **subdomains, IPs, mail servers, services** — everything
- Even a **failed transfer** tells you the server is properly configured (still useful intel)
- Get name servers first with `dig NS domain.com +short`, then try AXFR against each one

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
