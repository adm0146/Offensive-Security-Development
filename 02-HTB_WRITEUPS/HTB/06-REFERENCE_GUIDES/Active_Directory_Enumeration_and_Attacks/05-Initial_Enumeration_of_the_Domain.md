# Section 05 — Initial Enumeration of the Domain

---

## QUICK REFERENCE — Full Workflow

```bash
# STEP 1 — Passive: identify hosts from wire traffic
sudo tcpdump -i ens224 -w capture.pcap
sudo responder -I ens224 -A        # analyze only, no poisoning

# STEP 2 — Active: sweep for live hosts
fping -asgq 172.16.5.0/23          # outputs clean live IP list

# STEP 3 — Service scan on live hosts
sudo nmap -v -A -iL hosts.txt -oA host-enum

# STEP 4 — Username enumeration (no creds needed)
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 /opt/jsmith.txt -o valid_users.txt
```
> `tcpdump` saves wire traffic for offline review. Responder `-A` is passive — it only watches, never poisons. `fping` pings a whole subnet and prints only live hosts. `nmap -A` runs OS detection and scripts; `-iL` reads the host list from a file; `-oA` saves all output formats at once. `kerbrute userenum` tests usernames against Kerberos to find valid accounts without triggering lockouts.

---

## Lab Context

| Item | Detail |
|------|--------|
| Starting creds | None (unauthenticated) |
| Scope | `172.16.5.0/23` |
| Testing style | Grey box, non-evasive |

---

## Phase 1 — Passive Host Identification

### tcpdump / Wireshark

```bash
sudo tcpdump -i ens224                      # live view
sudo tcpdump -i ens224 -w capture.pcap      # save for Wireshark analysis
```
> The first command shows traffic in real time. The second saves a `.pcap` file you can open in Wireshark later. Change `ens224` to match your actual interface name.

**What to look for:**
- ARP requests/replies → live IPs on local broadcast domain
- MDNS queries → hostnames (`ACADEMY-EA-WEB01.local`)
- NBT-NS / LLMNR → name resolution traffic (poisoning opportunity later)

### Responder Analyze Mode

```bash
sudo responder -I ens224 -A    # passive only — no poisoning
```
> `-A` puts Responder in analyze-only mode. It reads broadcast name requests and logs hostnames and IPs — it never responds or poisons. Safe to run on authorized tests.

Surfaces hosts making broadcast name resolution requests. Note every hostname and IP.

---

## Phase 2 — Active Host Discovery

### fping

```bash
fping -asgq 172.16.5.0/23
# -a = alive hosts only | -s = stats | -g = generate from CIDR | -q = quiet
```
> Pings every IP in the subnet. `-a` prints only the ones that replied. `-g` expands the CIDR into individual IPs. Redirect output to `hosts.txt` and feed it into Nmap.

Outputs clean IP list → save to `hosts.txt` → feed into Nmap.

### Nmap

```bash
sudo nmap -v -A -iL hosts.txt -oA host-enum
```
> `-A` enables OS detection, version scanning, and default scripts. `-iL` reads hosts from a file. `-oA` writes `.nmap`, `.xml`, and `.gnmap` output files — use all three formats for later reference.

**DC identification — look for this port combo:**
```
53    DNS
88    Kerberos
389   LDAP      ← shows domain name
445   SMB
3268  Global Catalog LDAP
```

**Legacy host indicators (potential EternalBlue):**
```
Windows Server 2008 R2 / Windows 7  → MS17-010
IIS 7.5                              → old web server
SQL Server 2008 RTM                  → unpatched
SMB signing: not required            → relay attack candidate
```

---

## Phase 3 — Username Enumeration (No Creds)

### Kerbrute

```bash
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 /opt/jsmith.txt -o valid_users.txt
```
> Tests each username in the wordlist against Kerberos. Valid usernames get a different response than invalid ones. `-d` is the domain, `--dc` points to the Domain Controller (DC), `-o` saves confirmed valid usernames.

**Why Kerbrute is stealthy:** Uses Kerberos pre-auth — failed attempts do NOT generate Event ID 4625. Does generate 4768 only if Kerberos audit is enabled.

**Warning:** Kerbrute enumeration = stealthy. Kerbrute spraying = counts toward lockout threshold.

---

## SYSTEM Access — Why It Matters

`NT AUTHORITY\SYSTEM` on any domain-joined host is roughly equal to a domain user. It can enumerate all of Active Directory (AD).

**Ways to get SYSTEM:**
- Remote exploits: EternalBlue (MS17-010), MS08-067
- Service abuse: SeImpersonate → Juicy Potato (not Server 2019)
- Local privilege escalation

**What SYSTEM gives you:** BloodHound collection, Kerberoasting, Inveigh hash capture, token impersonation, and Access Control List (ACL) attacks.

---

## Lab Results (INLANEFREIGHT.LOCAL)

```bash
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
# Result: 56 valid usernames from 48,705 tested in ~11 seconds
```
> Same command as above, run without `-o` to see output on screen. 56 valid usernames found from nearly 49,000 tested — takes about 11 seconds.

---

## Exam Notes

- DC = ports 53 + 88 + 389 + 445 together — that combo is unmistakable
- Always `-oA` with Nmap — saves all formats, feeds other tools
- Legacy hosts (2008, IIS 7.5, SQL 2008) = flag for EternalBlue — get written approval first
- Kerbrute is stealthier than LDAP for username enumeration — no 4625 events
- SYSTEM on any domain-joined host = effective domain user — pivot from there
