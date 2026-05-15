# DNS Enumeration Reference Guide

## Overview

The **Domain Name System (DNS)** is an integral part of the Internet, translating computer names into IP addresses. DNS is often referred to as the "phonebook of the Internet." Unlike a phone book where we search for a name to find the number, DNS allows us to query with a computer name (domain) to get the IP address and vice versa (reverse lookup).

DNS operates as a **distributed hierarchical system** with several types of DNS servers working together globally.

---

## DNS Server Types

| Server Type | Description |
|-------------|-------------|
| **DNS Root Server** | Responsible for top-level domains (TLDs). Requested only if name server doesn't respond. Acts as central interface between users and Internet content. Links domains and IP addresses. 13 root servers exist globally (named with letters A-M), coordinated by ICANN |
| **Authoritative Nameserver** | Holds authority for a particular zone. Answers queries only from its area of responsibility. Information is binding. If it cannot answer, root name server takes over |
| **Non-authoritative Nameserver** | Not responsible for a particular DNS zone. Collects information about specific zones using recursive or iterative queries |
| **Caching DNS Server** | Caches information from other name servers for a set period (determined by authoritative nameserver). Stores DNS records temporarily |
| **Forwarding Server** | Forwards DNS queries to another DNS server. Acts as intermediary, doesn't resolve queries itself |
| **Resolver** | Not an authoritative DNS server. Performs name resolution locally in the computer or router. The client-side component that initiates queries |

---

## DNS Records

| Record Type | Description |
|-------------|-------------|
| **A** | Returns an IPv4 address of the requested domain |
| **AAAA** | Returns an IPv6 address of the requested domain |
| **MX** | Returns the mail servers responsible for the domain |
| **NS** | Returns the DNS servers (nameservers) of the domain |
| **TXT** | Contains various information (verification, SPF, DKIM, etc.) |
| **CNAME** | Alias that points one domain to another domain |
| **PTR** | Reverse DNS lookup - converts IP addresses into domain names |
| **SOA** | Start of Authority - provides information about the DNS zone (primary nameserver, admin email, serial number, refresh timers) |

---

## Default Configuration

DNS servers work with three different types of configuration files:

### 1. Local DNS Configuration (`named.conf.local`)

```bash
# View local DNS configuration
cat /etc/bind/named.conf.local
```
> Shows the zone definitions — which domains this server is authoritative for and where their zone files are stored. During a pentest on a DNS server, read this first to map the zone structure.

```
//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";
zone "domain.com" {
    type master;
    file "/etc/bind/db.domain.com";
    allow-update { key rndc-key; };
};
```

**Key Elements:**
- **zone** - Defines a DNS zone
- **type master** - This server is the primary (authoritative) for the zone
- **file** - Path to the zone file containing DNS records
- **allow-update** - Defines who can dynamically update the zone (uses rndc-key for authentication)

### 2. DNS Options Configuration (`named.conf.options`)

```bash
# View DNS options
cat /etc/bind/named.conf.options
```
> Shows the global BIND options — forwarding config, DNSSEC settings, and listening interfaces. Look for `allow-transfer`, `allow-query`, and `allow-recursion` entries that might be set too permissively.

```
options {
        directory "/var/cache/bind";

        // If there is a firewall between you and nameservers you want
        // to talk to, you may need to fix the firewall to allow multiple
        // ports to talk.  See http://www.kb.cert.org/vuls/id/800113

        // If your ISP provided one or more IP addresses for stable
        // nameservers, you probably want to use them as forwarders.
        // Uncomment the following block, and insert the addresses replacing
        // the all-0's placeholder.

        // forwarders {
        //      0.0.0.0;
        // };

        //========================================================================
        // If BIND logs error messages about the root key being expired,
        // you will need to update your keys.  See https://www.isc.org/bind-keys
        //========================================================================
        dnssec-validation auto;

        listen-on-v6 { any; };
};
```

**Key Options:**
- **directory** - Working directory for BIND (cache storage)
- **forwarders** - DNS servers to forward queries to (if enabled)
- **dnssec-validation** - Enables DNSSEC for cryptographic verification
- **listen-on-v6** - IPv6 listening configuration

### 3. DNS Logging Configuration (`named.conf.log`)

```bash
# View logging configuration
cat /etc/bind/named.conf.log
```
> Shows what BIND logs and where. Log files may contain recent query history, zone transfer attempts, and error messages useful during post-exploitation on a DNS server.

```
logging {
        channel default_debug {
                file "data/named.run";
                severity dynamic;
        };
};
```

---

## Zone Files

Zone files are text files that describe a DNS zone with the BIND file format. They contain **Resource Records (RR)** that describe the zone. A zone file must contain exactly one **SOA record** as the first entry.

### Forward Lookup Zone File Example

```bash
# View zone file
cat /etc/bind/db.domain.com
```
> The zone file contains all DNS records for the domain. If you gain read access to a DNS server, zone files at `/etc/bind/` expose the full host inventory — all A records, mail servers, and internal hostnames.

```
;
; BIND reverse data file for local loopback interface
;
$ORIGIN domain.com.
$TTL 86400
@     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                    2001062501 ; serial
                    21600      ; refresh after 6 hours
                    3600       ; retry after 1 hour
                    604800     ; expire after 1 week
                    86400 )    ; minimum TTL of 1 day
;
@      IN      NS      ns1.domain.com.
@      IN      MX      10      mx.domain.com.
@      IN      A       10.129.14.5

;
server1        IN      A       10.129.14.5
server2        IN      A       10.129.14.7
ns1            IN      A       10.129.14.2
root           IN      A       10.129.14.222
mx             IN      A       10.129.14.10
www            IN      CNAME   server1
```

**Zone File Directives:**
| Directive | Description |
|-----------|-------------|
| `$ORIGIN` | Sets the default domain for all records (appended to unqualified names) |
| `$TTL` | Default Time-To-Live for records (how long resolvers should cache) |
| `@` | Placeholder for the zone's domain name itself |

**SOA Record Components:**
| Field | Description |
|-------|-------------|
| `dns1.domain.com.` | Primary nameserver for the zone |
| `hostmaster.domain.com.` | Admin email (@ replaced with .) |
| `serial` | Zone version number (increment on changes) |
| `refresh` | How often slaves check for updates (6 hours) |
| `retry` | Retry interval if refresh fails (1 hour) |
| `expire` | When slave data becomes invalid (1 week) |
| `minimum` | Minimum TTL for negative caching (1 day) |

### Reverse Lookup Zone File Example

Reverse lookup zones map IP addresses back to hostnames using **PTR records**.

```bash
# View reverse zone file
cat /etc/bind/db.10.129.14
```
> The reverse zone file maps IP addresses to hostnames using PTR records. Reading it during post-exploitation gives you the full IP-to-hostname mapping for the subnet — useful for identifying other targets.

```
;
; BIND reverse data file for local loopback interface
;
$ORIGIN 14.129.10.in-addr.arpa.
$TTL 86400
@     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                    2001062501 ; serial
                    21600      ; refresh after 6 hours
                    3600       ; retry after 1 hour
                    604800     ; expire after 1 week
                    86400 )    ; minimum TTL of 1 day
;
@      IN      NS      ns1.domain.com.
5      IN      PTR     server1.domain.com.
7      IN      PTR     server2.domain.com.
222    IN      PTR     root.domain.com.
10     IN      PTR     mx.domain.com.
2      IN      PTR     ns1.domain.com.
```

**Key Points:**
- `$ORIGIN` uses the special `in-addr.arpa` domain with octets reversed
- PTR records map the last octet to the full hostname
- Example: `5 IN PTR server1.domain.com.` means 10.129.14.5 → server1.domain.com

---

## Dangerous Settings

DNS can get very complicated and it is easy for errors to creep into this service. Administrators often work around problems with temporary solutions, prioritizing functionality over security. This leads to misconfigurations and vulnerabilities.

| Option | Description | Security Risk |
|--------|-------------|---------------|
| `allow-query` | Defines which hosts are allowed to send requests to the DNS server | If set too broadly, exposes internal DNS information |
| `allow-recursion` | Defines which hosts are allowed to send recursive requests | Open recursion enables DNS amplification attacks |
| `allow-transfer` | Defines which hosts are allowed to receive zone transfers | If misconfigured, allows attackers to dump entire zone |
| `zone-statistics` | Collects statistical data of zones | Can leak information about zone activity |

**Common Vulnerable Configurations:**
```bash
# DANGEROUS: Allows zone transfers from anyone
allow-transfer { any; };

# DANGEROUS: Allows queries from any host
allow-query { any; };

# DANGEROUS: Allows recursive queries from any host
allow-recursion { any; };
```

**Resources for DNS Vulnerabilities:**
- CVEdetails - BIND9 vulnerabilities
- SecurityTrails - Popular DNS server attacks

---

## Footprinting the Service

DNS footprinting is performed by sending various queries to the server. The information gathered can reveal:
- Other DNS servers in the infrastructure
- Internal hostnames and IP addresses
- Mail servers and other services
- Zone structure and organization

### dig Command Syntax

```bash
dig [query_type] [domain] @[dns_server] [options]
```
> General `dig` syntax template — replace `[query_type]` (e.g. `ns`, `axfr`, `any`), `[domain]` with the target domain, and `[dns_server]` with the DNS server IP to direct the query.

### Query Name Servers (NS Record)

Identify other DNS servers that may have different configurations or serve different zones.

```bash
dig ns inlanefreight.htb @10.129.14.128
```
> Queries for Name Server (NS) records. The `@10.129.14.128` part directs the query to a specific DNS server. NS records tell you which servers are authoritative — query each one separately as they may have different zone data or be misconfigured differently. Replace the domain and IP with your target.

**Example Output:**
```
; <<>> DiG 9.16.1-Ubuntu <<>> ns inlanefreight.htb @10.129.14.128
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45010
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: ce4d8681b32abaea0100000061475f73842c401c391690c7 (good)
;; QUESTION SECTION:
;inlanefreight.htb.             IN      NS

;; ANSWER SECTION:
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.

;; ADDITIONAL SECTION:
ns.inlanefreight.htb.   604800  IN      A       10.129.34.136

;; Query time: 0 msec
;; SERVER: 10.129.14.128#53(10.129.14.128)
;; WHEN: So Sep 19 18:04:03 CEST 2021
;; MSG SIZE  rcvd: 107
```

### Query DNS Server Version (CHAOS Query)

Useful for identifying specific vulnerabilities based on the BIND version.

```bash
dig CH TXT version.bind @10.129.120.85
```
> `CH` (Chaos class) queries the special `version.bind` TXT record that BIND servers expose. This reveals the exact BIND version so you can search for known CVEs. Only works if the server admin hasn't disabled it. Replace `10.129.120.85` with your target DNS server IP.

**Example Output:**
```
; <<>> DiG 9.10.6 <<>> CH TXT version.bind
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 47786
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; ANSWER SECTION:
version.bind.       0       CH      TXT     "9.10.6-P1"

;; ADDITIONAL SECTION:
version.bind.       0       CH      TXT     "9.10.6-P1-Debian"

;; Query time: 2 msec
;; SERVER: 10.129.120.85#53(10.129.120.85)
;; WHEN: Wed Jan 05 20:23:14 UTC 2023
;; MSG SIZE  rcvd: 101
```

**Note:** This only works if the `version.bind` entry exists on the DNS server (not always enabled).

### Query All Available Records (ANY)

View all records the server is willing to disclose for a domain.

```bash
dig any inlanefreight.htb @10.129.14.128
```
> `ANY` requests all record types the server is willing to return. This is a fast way to see MX, TXT, NS, A, and SOA records in one query. Modern servers may limit `ANY` responses, so you may still need per-type queries. Replace the domain and server IP with your target.

**Example Output:**
```
; <<>> DiG 9.16.1-Ubuntu <<>> any inlanefreight.htb @10.129.14.128
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7649
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 064b7e1f091b95120100000061476865a6026d01f87d10ca (good)
;; QUESTION SECTION:
;inlanefreight.htb.             IN      ANY

;; ANSWER SECTION:
inlanefreight.htb.      604800  IN      TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
inlanefreight.htb.      604800  IN      TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
inlanefreight.htb.      604800  IN      TXT     "MS=ms97310371"
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.

;; ADDITIONAL SECTION:
ns.inlanefreight.htb.   604800  IN      A       10.129.34.136

;; Query time: 0 msec
;; SERVER: 10.129.14.128#53(10.129.14.128)
;; WHEN: So Sep 19 18:42:13 CEST 2021
;; MSG SIZE  rcvd: 437
```

**Note:** Not all entries from the zone will be shown—only what the server is configured to disclose.

---

## Zone Transfers (AXFR)

**Zone transfer** is the mechanism for replicating DNS databases across servers. It transfers zones to another server over **TCP port 53** using the AXFR (Asynchronous Full Transfer Zone) protocol.

### Zone Transfer Concepts

| Term | Description |
|------|-------------|
| **Primary (Master)** | The authoritative source for zone data. Changes are made here |
| **Secondary (Slave)** | Receives zone data from the primary. Provides redundancy and load distribution |
| **rndc-key** | Secret key used to authenticate zone transfer communication |
| **Serial Number** | Version identifier in SOA record. Incremented on changes |
| **Refresh Time** | Interval at which slaves check master for updates (typically 1 hour) |

### Zone Transfer Process

1. Slave fetches SOA record from master at refresh intervals
2. Compares serial numbers between master and slave
3. If master's serial is greater, zone data has changed
4. Slave initiates AXFR to download updated zone

### Attempting Zone Transfer

```bash
dig axfr inlanefreight.htb @10.129.14.128
```
> `axfr` requests a full Asynchronous Full Transfer Zone (AXFR) — a copy of the entire DNS zone. If successful, every hostname, IP, and record in the domain is returned. Always try this before brute-forcing. Replace the domain and server IP with your target.

**Successful Zone Transfer Output:**
```
; <<>> DiG 9.16.1-Ubuntu <<>> axfr inlanefreight.htb @10.129.14.128
;; global options: +cmd
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.      604800  IN      TXT     "MS=ms97310371"
inlanefreight.htb.      604800  IN      TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
inlanefreight.htb.      604800  IN      TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.
app.inlanefreight.htb.  604800  IN      A       10.129.18.15
internal.inlanefreight.htb. 604800 IN   A       10.129.1.6
mail1.inlanefreight.htb. 604800 IN      A       10.129.18.201
ns.inlanefreight.htb.   604800  IN      A       10.129.34.136
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 4 msec
;; SERVER: 10.129.14.128#53(10.129.14.128)
;; WHEN: So Sep 19 18:51:19 CEST 2021
;; XFR size: 9 records (messages 1, bytes 520)
```

### Zone Transfer on Internal Zones

If `allow-transfer` is misconfigured, internal zones can also be extracted:

```bash
dig axfr internal.inlanefreight.htb @10.129.14.128
```
> Zone transfers work against each zone separately — `inlanefreight.htb` and `internal.inlanefreight.htb` are distinct zones. If the external zone transfer worked, always try internal zones too. Internal zones often expose domain controllers, VPN servers, and workstations. Replace the subdomain and server IP with your target.

**Example Output (Internal Zone):**
```
; <<>> DiG 9.16.1-Ubuntu <<>> axfr internal.inlanefreight.htb @10.129.14.128
;; global options: +cmd
internal.inlanefreight.htb. 604800 IN   SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
internal.inlanefreight.htb. 604800 IN   TXT     "MS=ms97310371"
internal.inlanefreight.htb. 604800 IN   TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
internal.inlanefreight.htb. 604800 IN   TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
internal.inlanefreight.htb. 604800 IN   NS      ns.inlanefreight.htb.
dc1.internal.inlanefreight.htb. 604800 IN A     10.129.34.16
dc2.internal.inlanefreight.htb. 604800 IN A     10.129.34.11
mail1.internal.inlanefreight.htb. 604800 IN A   10.129.18.200
ns.internal.inlanefreight.htb. 604800 IN A      10.129.34.136
vpn.internal.inlanefreight.htb. 604800 IN A     10.129.1.6
ws1.internal.inlanefreight.htb. 604800 IN A     10.129.1.34
ws2.internal.inlanefreight.htb. 604800 IN A     10.129.1.35
wsus.internal.inlanefreight.htb. 604800 IN A    10.129.18.2
internal.inlanefreight.htb. 604800 IN   SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 0 msec
;; SERVER: 10.129.14.128#53(10.129.14.128)
;; WHEN: So Sep 19 18:53:11 CEST 2021
;; XFR size: 15 records (messages 1, bytes 664)
```

**Critical Information Revealed:**
- Domain Controllers: `dc1`, `dc2`
- Mail servers: `mail1`
- VPN server: `vpn`
- Workstations: `ws1`, `ws2`
- WSUS server: `wsus`
- Internal IP ranges

---

## Subdomain Brute Forcing

When zone transfers are not allowed, brute forcing can discover subdomains by testing a wordlist of possible hostnames against the DNS server.

### Manual Brute Force with Bash Loop

```bash
for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt); do
    dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt
done
```
> Loops through a wordlist and queries each word as a subdomain of `inlanefreight.htb`. The `grep -v ';\|SOA'` removes comment lines and SOA records. `sed` removes blank lines. Only lines containing the tested subdomain name are kept. `tee -a` appends found subdomains to a file while also printing them. Slow but thorough — use `dnsenum` for a faster automated version.

**Command Breakdown:**
| Part | Purpose |
|------|---------|
| `for sub in $(cat wordlist.txt)` | Loop through each subdomain in the wordlist |
| `dig $sub.domain @dns_server` | Query DNS for each subdomain |
| `grep -v ';\|SOA'` | Filter out comments and SOA records |
| `sed -r '/^\s*$/d'` | Remove empty lines |
| `grep $sub` | Only show lines containing the subdomain |
| `tee -a subdomains.txt` | Output to screen and append to file |

**Example Output:**
```
ns.inlanefreight.htb.   604800  IN      A       10.129.34.136
mail1.inlanefreight.htb. 604800 IN      A       10.129.18.201
app.inlanefreight.htb.  604800  IN      A       10.129.18.15
```

### DNSenum - Automated DNS Enumeration

DNSenum is a comprehensive tool that automates DNS enumeration including:
- Host address lookup
- Name server lookup
- MX record lookup
- Zone transfer attempts
- Subdomain brute forcing

```bash
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```
> `dnsenum` automates all DNS enumeration steps: NS lookups, MX records, zone transfer attempts, and subdomain brute-forcing. `-p 0 -s 0` disables web scraping. `-o` saves results. The target domain goes last. Replace `10.129.14.128` with the DNS server IP and `inlanefreight.htb` with your target domain.

**DNSenum Options:**
| Option | Description |
|--------|-------------|
| `--dnsserver` | Target DNS server to query |
| `--enum` | Perform full enumeration |
| `-p 0` | Number of pages to scrape (0 = none) |
| `-s 0` | Number of subdomains from scraping (0 = none) |
| `-o` | Output file for results |
| `-f` | Wordlist file for brute forcing |

**Example Output:**
```
dnsenum VERSION:1.2.6

-----   inlanefreight.htb   -----


Host's addresses:
__________________



Name Servers:
______________

ns.inlanefreight.htb.                    604800   IN    A        10.129.34.136


Mail (MX) Servers:
___________________



Trying Zone Transfers and getting Bind Versions:
_________________________________________________

unresolvable name: ns.inlanefreight.htb at /usr/bin/dnsenum line 900 thread 1.

Trying Zone Transfer for inlanefreight.htb on ns.inlanefreight.htb ...
AXFR record query failed: no nameservers


Brute forcing with /home/cry0l1t3/Pentesting/SecLists/Discovery/DNS/subdomains-top1million-110000.txt:
_______________________________________________________________________________________________________

ns.inlanefreight.htb.                    604800   IN    A        10.129.34.136
mail1.inlanefreight.htb.                 604800   IN    A        10.129.18.201
app.inlanefreight.htb.                   604800   IN    A        10.129.18.15
ns.inlanefreight.htb.                    604800   IN    A        10.129.34.136

...SNIP...
done.
```

---

## DNS Enumeration Quick Reference

### Essential dig Commands

```bash
# Query specific record types
dig A domain.com @dns_server           # IPv4 address
dig AAAA domain.com @dns_server        # IPv6 address
dig MX domain.com @dns_server          # Mail servers
dig NS domain.com @dns_server          # Name servers
dig TXT domain.com @dns_server         # TXT records (SPF, DKIM, etc.)
dig SOA domain.com @dns_server         # Start of Authority

# Special queries
dig any domain.com @dns_server         # All available records
dig axfr domain.com @dns_server        # Zone transfer attempt
dig CH TXT version.bind @dns_server    # DNS server version

# Reverse lookup
dig -x 10.129.14.5 @dns_server         # PTR record lookup
```
> A complete `dig` reference. Replace `domain.com` with your target domain and `@dns_server` with the DNS server IP. Run these in order during enumeration: NS first (find all servers), then `any`, then `axfr` on every server found. `-x` does a reverse lookup to find the hostname for an IP.

### Enumeration Checklist

1. **Identify DNS Server**
   ```bash
   nmap -sV -p 53 -sC target
   ```
   > Scans port 53 with version detection and default scripts to confirm DNS is running and identify the server software. Replace `target` with the target IP.

2. **Query NS Records**
   ```bash
   dig ns domain.com @dns_server
   ```
   > Finds all name servers for the domain. Query each one independently — they may have different security configurations.

3. **Check Server Version**
   ```bash
   dig CH TXT version.bind @dns_server
   ```
   > Reveals the BIND version for CVE research. Doesn't work on all servers — depends on server configuration.

4. **Attempt Zone Transfer**
   ```bash
   dig axfr domain.com @dns_server
   ```
   > Tries to dump the full DNS zone. If it works, you get every hostname and IP in the domain for free.

5. **Query All Records**
   ```bash
   dig any domain.com @dns_server
   ```
   > Requests all record types at once — A, MX, TXT, NS, SOA. Faster than querying each type separately.

6. **Brute Force Subdomains**
   ```bash
   dnsenum --dnsserver dns_ip --enum -f wordlist.txt domain.com
   ```
   > Automated subdomain discovery using a wordlist. Use this when zone transfers are blocked.

7. **Check Internal Zones**
   ```bash
   dig axfr internal.domain.com @dns_server
   ```
   > Internal zones like `internal.domain.com` are separate from the public zone and often expose sensitive infrastructure. Always try AXFR on every discovered subdomain zone.

---

## Common Wordlists for DNS Brute Forcing

| Wordlist | Location | Use Case |
|----------|----------|----------|
| subdomains-top1million-110000.txt | SecLists/Discovery/DNS/ | Comprehensive subdomain list |
| subdomains-top1million-5000.txt | SecLists/Discovery/DNS/ | Quick scan |
| dns-Jhaddix.txt | SecLists/Discovery/DNS/ | Bug bounty focused |
| fierce-hostlist.txt | SecLists/Discovery/DNS/ | Smaller targeted list |

---

## Key Takeaways

1. **Zone transfers (AXFR)** can expose entire DNS databases if misconfigured
2. **Internal zones** often contain critical infrastructure information (DCs, mail servers, etc.)
3. **Version queries** can reveal vulnerable BIND versions
4. **Subdomain brute forcing** works when zone transfers are blocked
5. **Multiple DNS servers** may have different configurations—enumerate all of them
6. **DNS misconfigurations** often prioritize functionality over security

---

## Related Tools

- **dig** - DNS lookup utility (most versatile)
- **nslookup** - Basic DNS query tool
- **host** - Simple DNS lookup
- **dnsenum** - Automated DNS enumeration
- **dnsrecon** - DNS reconnaissance tool
- **fierce** - DNS reconnaissance and subdomain scanner
- **Sublist3r** - Subdomain enumeration using OSINT

---

## HTB Academy Lab Walkthrough

### Key Insight: Subdomain Brute Forcing Workflow

Most DNS enumeration is straightforward, but the **subdomain brute forcing workflow** requires understanding the multi-step process:

#### Step 1: Zone Transfer (AXFR) to Discover Subdomains

First, attempt a zone transfer to reveal all DNS records:

```bash
dig axfr inlanefreight.htb @10.129.14.128
```
> Zone transfer attempt against the target DNS server. If successful, returns every DNS record in the zone — all hostnames and IPs revealed in one shot. Note every A record as a potential scan target.

**Example Response:**
```
; <<>> DiG 9.16.1-Ubuntu <<>> axfr inlanefreight.htb @10.129.14.128
;; global options: +cmd
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.      604800  IN      TXT     "MS=ms97310371"
inlanefreight.htb.      604800  IN      TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
inlanefreight.htb.      604800  IN      TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.
app.inlanefreight.htb.  604800  IN      A       10.129.18.15
internal.inlanefreight.htb. 604800 IN   A       10.129.1.6
mail1.inlanefreight.htb. 604800 IN      A       10.129.18.201
ns.inlanefreight.htb.   604800  IN      A       10.129.34.136
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 4 msec
;; SERVER: 10.129.14.128#53(10.129.14.128)
;; XFR size: 9 records (messages 1, bytes 520)
```

#### Step 2: Identify Subdomains to Enumerate Further

From the zone transfer, note discovered subdomains:
- `app.inlanefreight.htb`
- `internal.inlanefreight.htb`
- `mail1.inlanefreight.htb`
- `ns.inlanefreight.htb`

> ⚠️ **Critical Understanding**: These subdomains may have **their own subdomains** (e.g., `dev.inlanefreight.htb` might have `api.dev.inlanefreight.htb`)

#### Step 3: Brute Force Subdomains of Discovered Domains

**Key Point**: When brute forcing, the **target domain goes at the END of the command**:

```bash
# Brute force subdomains OF dev.inlanefreight.htb
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt dev.inlanefreight.htb
```
> Brute-forces sub-subdomains under `dev.inlanefreight.htb`. The domain to enumerate always goes last. Run this against every subdomain you discovered in the AXFR — each may have its own nested subdomains not in the parent zone file. Replace the DNS server IP and target subdomain as needed.

**Command Breakdown:**
| Option | Purpose |
|--------|---------|
| `--dnsserver 10.129.14.128` | Target DNS server |
| `--enum` | Perform enumeration |
| `-p 0` | Disable Google scraping (0 pages) |
| `-s 0` | Disable Bing scraping (0 pages) |
| `-o subdomains.txt` | Output file |
| `-f <wordlist>` | Wordlist for brute forcing |
| `dev.inlanefreight.htb` | **Domain to brute force (LAST!)** |

#### Workflow Summary

```
Zone Transfer (AXFR)
        │
        ▼
┌───────────────────────────────────┐
│ Discovered Subdomains:            │
│ • app.inlanefreight.htb           │
│ • internal.inlanefreight.htb      │
│ • dev.inlanefreight.htb           │
└───────────────────────────────────┘
        │
        ▼
Brute Force EACH Subdomain for MORE Subdomains
        │
        ▼
dnsenum ... dev.inlanefreight.htb
        │
        ▼
┌───────────────────────────────────┐
│ Might Find:                       │
│ • api.dev.inlanefreight.htb       │
│ • admin.dev.inlanefreight.htb     │
│ • staging.dev.inlanefreight.htb   │
└───────────────────────────────────┘
```

> 💡 **Remember**: Zone transfer gives you the first layer of subdomains. Brute forcing each discovered subdomain can reveal **hidden nested subdomains** that weren't in the zone file!
