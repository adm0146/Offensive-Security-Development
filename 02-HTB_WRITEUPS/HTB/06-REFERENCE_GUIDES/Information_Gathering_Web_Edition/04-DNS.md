# 🌐 DNS (Domain Name System)

## Overview

The Domain Name System (DNS) acts as the internet's GPS — translating human-readable domain names (like `www.example.com`) into numerical IP addresses (like `192.0.2.1`) that computers use to communicate. Without DNS, you'd need to memorize IP addresses for every website you visit.

---

## How DNS Works

The DNS resolution process is like a **relay race** — each server gets closer to the answer:

```
Your Computer → DNS Resolver → Root Name Server → TLD Name Server → Authoritative Name Server
     ↑                                                                        |
     └────────────────────── IP Address Returned ─────────────────────────────┘
```

### Step-by-Step Resolution

| Step | Actor | Action |
|------|-------|--------|
| 1 | **Your Computer** | Checks local cache for the IP address. If not found, sends DNS query to resolver |
| 2 | **DNS Resolver** | Checks its own cache. If not found, starts recursive lookup through the hierarchy |
| 3 | **Root Name Server** | Doesn't know the IP, but directs resolver to the correct TLD name server (e.g., `.com`) |
| 4 | **TLD Name Server** | Knows which authoritative name server handles the specific domain (e.g., `example.com`) |
| 5 | **Authoritative Name Server** | Holds the actual IP address — sends it back to the resolver |
| 6 | **DNS Resolver** | Returns the IP to your computer and caches it for future lookups |
| 7 | **Your Computer** | Connects to the web server using the IP address |

---

## The Hosts File

The hosts file provides **manual, local DNS overrides** — bypassing the DNS process entirely.

### Location

| OS | Path |
|----|------|
| **Windows** | `C:\Windows\System32\drivers\etc\hosts` |
| **Linux/macOS** | `/etc/hosts` |

### Format

```
<IP Address>    <Hostname> [<Alias> ...]
```

### Common Uses

```bash
# Local development
127.0.0.1       myapp.local

# Testing connectivity
192.168.1.20    testserver.local

# Blocking unwanted sites
0.0.0.0         unwanted-site.com
```

> **Note:** Changes take effect immediately — no restart required. Edit with admin/root privileges.

---

## Key DNS Concepts

| Concept | Description | Example |
|---------|-------------|---------|
| **Domain Name** | Human-readable label for an internet resource | `www.example.com` |
| **IP Address** | Unique numerical identifier for a device | `192.0.2.1` |
| **DNS Resolver** | Server that translates domain names to IPs | ISP's DNS, Google DNS (`8.8.8.8`) |
| **Root Name Server** | Top-level servers in the DNS hierarchy | 13 worldwide, named A-M (`a.root-servers.net`) |
| **TLD Name Server** | Servers for specific top-level domains | Verisign for `.com`, PIR for `.org` |
| **Authoritative Name Server** | Holds the actual IP for a domain | Managed by hosting providers or registrars |
| **DNS Record Types** | Different types of info stored in DNS | A, AAAA, CNAME, MX, NS, TXT, etc. |

---

## DNS Zones & Zone Files

A **zone** is a distinct part of the domain namespace managed by a specific entity. A **zone file** is a text file on a DNS server that defines the resource records within that zone.

### Example Zone File

```
$TTL 3600 ; Default Time-To-Live (1 hour)
@       IN SOA   ns1.example.com. admin.example.com. (
                2024060401 ; Serial number (YYYYMMDDNN)
                3600       ; Refresh interval
                900        ; Retry interval
                604800     ; Expire time
                86400 )    ; Minimum TTL

@       IN NS    ns1.example.com.
@       IN NS    ns2.example.com.
@       IN MX 10 mail.example.com.
www     IN A     192.0.2.1
mail    IN A     198.51.100.1
ftp     IN CNAME www.example.com.
```

> **What does "IN" mean?** — Stands for "Internet." It's a class field specifying the protocol family (IP). Other classes exist (CH for Chaosnet, HS for Hesiod) but are rarely used in modern DNS.

---

## DNS Record Types

| Record | Full Name | Description | Zone File Example |
|--------|-----------|-------------|-------------------|
| **A** | Address Record | Maps hostname to IPv4 address | `www.example.com. IN A 192.0.2.1` |
| **AAAA** | IPv6 Address Record | Maps hostname to IPv6 address | `www.example.com. IN AAAA 2001:db8:85a3::8a2e:370:7334` |
| **CNAME** | Canonical Name Record | Creates an alias pointing to another hostname | `blog.example.com. IN CNAME webserver.example.net.` |
| **MX** | Mail Exchange Record | Specifies mail server(s) for the domain | `example.com. IN MX 10 mail.example.com.` |
| **NS** | Name Server Record | Delegates zone to an authoritative name server | `example.com. IN NS ns1.example.com.` |
| **TXT** | Text Record | Stores arbitrary text (domain verification, SPF, etc.) | `example.com. IN TXT "v=spf1 mx -all"` |
| **SOA** | Start of Authority Record | Admin info about the zone (primary NS, serial, timers) | `example.com. IN SOA ns1.example.com. admin.example.com. ...` |
| **SRV** | Service Record | Defines hostname and port for specific services | `_sip._udp.example.com. IN SRV 10 5 5060 sipserver.example.com.` |
| **PTR** | Pointer Record | Reverse DNS — maps IP to hostname | `1.2.0.192.in-addr.arpa. IN PTR www.example.com.` |

---

## Why DNS Matters for Web Recon

| Use Case | Description | Example |
|----------|-------------|---------|
| **Uncovering Assets** | DNS records reveal subdomains, mail servers, and name servers | A CNAME record `dev.example.com → oldserver.example.net` could lead to a vulnerable system |
| **Mapping Network Infrastructure** | Analyse DNS data to map how systems connect | NS records reveal hosting providers; A records for `loadbalancer.example.com` pinpoint load balancers |
| **Monitoring for Changes** | Track DNS changes to spot new infrastructure | New subdomain `vpn.example.com` = new network entry point; TXT record `_1password=...` reveals password manager usage |

---

## Key Takeaways

1. DNS translates domain names to IP addresses through a **hierarchical resolution process**
2. The **hosts file** provides local overrides — useful for development, testing, and blocking sites
3. **Zone files** define all DNS records for a domain — understanding their structure is essential for enumeration
4. **Record types matter** — A records give IPs, MX gives mail servers, CNAME reveals aliases, TXT can leak security policies
5. DNS recon can **uncover hidden assets** (subdomains, old servers) and **map infrastructure** (hosting, load balancers)
6. **Monitor DNS changes** over time to detect new entry points and infrastructure shifts

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
