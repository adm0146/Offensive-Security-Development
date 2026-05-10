# Section 5 — Initial Enumeration of the Domain

## Engagement Context (Inlanefreight Setup)

| Item | Detail |
|------|--------|
| Attack host | Custom Linux VM inside their network (SSH in from jump host) |
| Windows host | Available for Windows tools if needed |
| Starting credentials | None (unauthenticated) — htb-student account provided for Windows host only |
| Scope | 172.16.5.0/23 |
| Testing style | Grey box, non-evasive |

---

## Key Data Points to Collect

| Data Point | Why |
|------------|-----|
| AD Users | Targets for password spraying |
| AD-Joined Computers | DCs, file servers, SQL, web, Exchange — map the environment |
| Key Services | Kerberos (88), DNS (53), LDAP (389/636), SMB (445), NetBIOS (139) |
| Vulnerable Hosts | Legacy OS, unpatched services — quick win for SYSTEM foothold |

---

## Phase 1 — Passive Host Identification

Goal: identify live hosts and traffic *without* sending anything active.

### Wireshark / tcpdump — Listen to the Wire
```bash
# GUI (if available)
sudo -E wireshark

# CLI — save to pcap for later Wireshark analysis
sudo tcpdump -i ens224
sudo tcpdump -i ens224 -w capture.pcap
```

What to look for:
- **ARP requests/replies** → reveals live IPs on the local broadcast domain
- **MDNS queries** → reveals hostnames (e.g. `ACADEMY-EA-WEB01.local`)
- **NBT-NS / LLMNR** → name resolution traffic, useful for poisoning later

### Responder — Passive Analysis Mode
```bash
sudo responder -I ens224 -A
```
`-A` = analyze only, no poisoning. Surfaces hosts making name resolution requests that Wireshark may miss. Note every unique hostname and IP.

---

## Phase 2 — Active Host Discovery

### fping — Fast ICMP Sweep
```bash
fping -asgq 172.16.5.0/23
```

| Flag | Meaning |
|------|---------|
| `-a` | Show only alive hosts |
| `-s` | Print stats at end |
| `-g` | Generate target list from CIDR |
| `-q` | Quiet — no per-target output |

Output a clean list of live IPs to feed into Nmap.

### Nmap — Service and Version Scan
```bash
# Save live IPs from fping to hosts.txt first, then:
sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum

# Always save output — use -oA for all formats
sudo nmap -v -A -iL hosts.txt -oA host-enum
```

**DC identification from Nmap output** — look for this port combination:
```
53    DNS
88    Kerberos
135   MSRPC
139   NetBIOS
389   LDAP  ← will show domain name
445   SMB
464   kpasswd5
636   LDAPS
3268  Global Catalog LDAP
3269  Global Catalog LDAPS
```

**Legacy host indicators** — potential EternalBlue / MS08-067 targets:
```
Windows Server 2008 R2 / Windows 7 → check for MS17-010
IIS 7.5 → old web server
SQL Server 2008 RTM (no service packs) → unpatched
SMB signing not required → relay attack candidate
```

> **Caution:** Some Nmap NSE scripts actively probe services in ways that can crash legacy hosts or PLCs. Know what your scripts do before running against client infra. Always alert the client and get written approval before exploiting legacy systems.

---

## Phase 3 — User Enumeration (Unauthenticated)

### Kerbrute — Kerberos Username Enumeration

Why Kerbrute over other methods:
- Exploits Kerberos pre-authentication — failed attempts often **don't trigger logs or alerts**
- Fast — tests thousands of usernames in seconds
- Confirms valid accounts without a password

**Install (if not present):**
```bash
# Check if installed
kerbrute --help

# If not — install via apt or compile from source
sudo apt install kerbrute

# Or compile manually:
sudo git clone https://github.com/ropnop/kerbrute.git
cd kerbrute && sudo make all
sudo mv dist/kerbrute_linux_amd64 /usr/local/bin/kerbrute
```

**Enumerate users:**
```bash
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```

**Useful username wordlists:**
```
~/SecLists/Usernames/xato-net-10-million-usernames.txt   # broad
~/SecLists/Usernames/Names/names.txt                     # name-based
# Also: Insidetrust jsmith.txt / jsmith2.txt (common AD formats)
```

> **Warning:** Failed Kerberos pre-auth **does count as a failed login** — it WILL lock out accounts if a lockout policy exists. Know the policy before spraying.

---

## SYSTEM Access — Why It Matters

`NT AUTHORITY\SYSTEM` on a domain-joined host ≈ domain user account. The machine account can authenticate to AD and enumerate it.

**Ways to get SYSTEM:**
- Remote exploits: EternalBlue (MS17-010), MS08-067, BlueKeep
- Service abuse: SeImpersonate → Juicy Potato (older OS only, not Server 2019)
- Local privesc: Windows 10 Task Scheduler 0-day
- Admin → Psexec SYSTEM shell

**What SYSTEM on a domain-joined host gets you:**
- AD enumeration (BloodHound, PowerView)
- Kerberoasting / AS-REP roasting
- NTLMv2 hash capture via Inveigh
- Token impersonation → hijack domain user sessions
- ACL attacks

---

## Workflow Summary

```
1. tcpdump / Wireshark  →  passive: IPs + hostnames from ARP/MDNS
2. Responder -A         →  passive: additional hosts from LLMNR/NBT-NS
3. fping -asgq          →  active: confirm all live IPs in scope
4. nmap -A -iL          →  active: services, versions, OS, DC identification
5. kerbrute userenum    →  unauthenticated: valid AD username list
6. → Password spray or hunt for SYSTEM foothold
```

---

## Exam Notes

- Always use `-oA` with Nmap — saves all formats, feeds into other tools
- DC = ports 53 + 88 + 389 + 445 together — that combo is unmistakable
- Legacy hosts (2008, IIS 7.5, SQL 2008) = flag for EternalBlue — get written approval before exploiting
- Kerbrute is stealthier than LDAP enumeration for username discovery
- SYSTEM on any domain-joined host = effective domain user — pivot from there
- Non-evasive engagement = noise is fine; evasive = slow down, minimize footprint
