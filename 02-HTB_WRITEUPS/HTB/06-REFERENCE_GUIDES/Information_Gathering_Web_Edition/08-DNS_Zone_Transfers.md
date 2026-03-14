# 🔄 DNS Zone Transfers

## Overview

While brute-forcing is a powerful approach, DNS zone transfers offer a less invasive and potentially more efficient method for uncovering subdomains. This mechanism — designed for replicating DNS records between name servers — can inadvertently become a goldmine of information if misconfigured.

---

## What is a Zone Transfer?

A DNS zone transfer is a **wholesale copy of all DNS records** within a zone (a domain and its subdomains) from one name server to another. This process is essential for maintaining consistency and redundancy across DNS servers. However, if not adequately secured, unauthorised parties can download the entire zone file, revealing a complete list of subdomains, their associated IP addresses, and other sensitive DNS data.

### How Zone Transfers Work

```
secondaryServer                              primaryServer
       |                                           |
       |--- AXFR Request (Zone Transfer) --------->|
       |                                           |
       |<-- SOA Record (Start of Authority) -------|
       |                                           |
       |         ┌─── loop [transfer] ───┐         |
       |         |                       |         |
       |<--------|---- DNS Record -------|---------|
       |         |                       |         |
       |         └───────────────────────┘         |
       |                                           |
       |<-- Zone Transfer Complete ----------------|
       |                                           |
       |--- ACK (Acknowledgement) ---------------->|
       |                                           |
```

| Step | Action | Description |
|------|--------|-------------|
| 1 | **AXFR Request** | Secondary DNS server sends a zone transfer request to the primary server using AXFR (Full Zone Transfer) type |
| 2 | **SOA Record Transfer** | Primary server responds with its Start of Authority (SOA) record, containing the zone's serial number to help determine if data is current |
| 3 | **DNS Records Transmission** | Primary server transfers all DNS records (A, AAAA, MX, CNAME, NS, etc.) one by one |
| 4 | **Zone Transfer Complete** | Primary server signals the end of the transfer |
| 5 | **ACK** | Secondary server confirms successful receipt and processing of the zone data |

---

## The Zone Transfer Vulnerability

In the early days of the internet, allowing **any client** to request a zone transfer was common practice. This open approach simplified administration but created a massive security hole — anyone, including malicious actors, could request a complete copy of the zone file.

### What an Unauthorised Zone Transfer Reveals

| Information | Why It Matters |
|-------------|----------------|
| **Subdomains** | Complete list of subdomains, including hidden ones hosting dev servers, staging environments, admin panels, or other sensitive resources |
| **IP Addresses** | IPs associated with each subdomain — potential targets for further recon or attacks |
| **Name Server Records** | Details about authoritative name servers, revealing hosting providers and potential misconfigurations |

---

## Remediation

Most modern DNS servers are configured to **allow zone transfers only to trusted secondary servers**, keeping sensitive zone data confidential. However, misconfigurations still occur due to:

- Human error
- Outdated practices
- Legacy server configurations

> 💡 **Note:** Even an unsuccessful zone transfer attempt can reveal information about the DNS server's configuration and security posture.

---

## Exploiting Zone Transfers

Use the `dig` command to request a zone transfer:

```bash
adm0146@htb[/htb]$ dig axfr @nsztm1.digi.ninja zonetransfer.me
```

| Part | Explanation |
|------|-------------|
| `axfr` | Request a full zone transfer |
| `@nsztm1.digi.ninja` | The DNS server to query |
| `zonetransfer.me` | The target domain |

### Example Output (Misconfigured Server)

```
; <<>> DiG 9.18.12-1~bpo11+1-Debian <<>> axfr @nsztm1.digi.ninja zonetransfer.me
; (1 server found)
;; global options: +cmd
zonetransfer.me.    7200    IN  SOA nsztm1.digi.ninja. robin.digi.ninja. 2019100801 172800 900 1209600 3600
zonetransfer.me.    300     IN  HINFO   "Casio fx-700G" "Windows XP"
zonetransfer.me.    301     IN  TXT "google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"
zonetransfer.me.    7200    IN  MX  0 ASPMX.L.GOOGLE.COM.
...
zonetransfer.me.    7200    IN  A   5.196.105.14
zonetransfer.me.    7200    IN  NS  nsztm1.digi.ninja.
zonetransfer.me.    7200    IN  NS  nsztm2.digi.ninja.
_acme-challenge.zonetransfer.me. 301 IN TXT "6Oa05hbUJ9xSsvYy7pApQvwCUSSGgxvrbdizjePEsZI"
_sip._tcp.zonetransfer.me. 14000 IN SRV 0 0 5060 www.zonetransfer.me.
14.105.196.5.IN-ADDR.ARPA.zonetransfer.me. 7200 IN PTR www.zonetransfer.me.
asfdbauthdns.zonetransfer.me. 7900 IN   AFSDB   1 asfdbbox.zonetransfer.me.
asfdbbox.zonetransfer.me. 7200  IN  A   127.0.0.1
asfdbvolume.zonetransfer.me. 7800 IN    AFSDB   1 asfdbbox.zonetransfer.me.
canberra-office.zonetransfer.me. 7200 IN A  202.14.81.230
...
;; XFR size: 50 records (messages 1, bytes 2085)
```

> ⚠️ **This is a jackpot.** A successful zone transfer dumps **every DNS record** — subdomains, IPs, mail servers, service records — all in one query. No brute-forcing needed.

> 🔑 **Practice Target:** `zonetransfer.me` is a service specifically set up to demonstrate the risks of zone transfers. It is intentionally misconfigured so that `dig axfr` will return the full zone record — making it a safe, legal target for practising this technique.

---

## Key Takeaways

1. **Zone transfers replicate all DNS records** from a primary to secondary server — if misconfigured, anyone can request one
2. **`dig axfr @<nameserver> <domain>`** is the command to attempt a zone transfer
3. **A successful transfer reveals everything** — subdomains, IPs, mail servers, name servers, and service records
4. **Most modern servers block unauthorised transfers**, but misconfigurations still happen due to human error
5. **Always attempt a zone transfer** during authorised engagements — it's low effort, high reward
6. **Even a failed attempt provides intel** about the server's configuration and security posture

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
