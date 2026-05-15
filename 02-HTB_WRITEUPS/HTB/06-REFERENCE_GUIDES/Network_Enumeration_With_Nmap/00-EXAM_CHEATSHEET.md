# Network Enumeration with Nmap — Exam Cheatsheet

**Distilled from HTB Academy "Network Enumeration with Nmap" module.** Open this during the exam.

---

## The Universal Methodology

```
1. Host discovery   →  who's alive on the subnet?
2. Port discovery   →  full TCP, then top UDP
3. Service/version  →  -sV -sC on every open port
4. Deep enum        →  NSE scripts per service
5. Save everything  →  -oA so you never re-scan
```

> This is the five-stage workflow. Follow it in order — do not jump straight to service scanning without first confirming live hosts and open ports.

> **Forever rule:** Slow & accurate beats fast & wrong. `--min-rate 1000` is plenty on HTB; `--min-rate 5000+` drops packets.

---

## Stage 1 — Host Discovery

```bash
# Subnet sweep (no port scan, just alive check)
sudo nmap -sn 10.129.2.0/24 -oA hosts                       # ICMP + ARP + TCP-ACK 80/443

# From file
sudo nmap -sn -iL targets.txt -oA hosts

# When ICMP is blocked (HTB labs often filter ping)
sudo nmap -Pn 10.129.2.28                                   # treat as alive, scan anyway
sudo nmap -PS22,80,443 -PA80,443 -PU53 10.129.2.0/24        # mixed probes
sudo nmap -PE -PP -PM 10.129.2.0/24                         # ICMP echo/timestamp/netmask

# ARP only (same L2 subnet)
sudo nmap -PR -sn 10.129.2.0/24
```

> `-sn` skips port scanning and only checks which hosts are alive. `-iL` reads targets from a file. `-Pn` skips the ping check entirely — treat every host as alive. Replace `10.129.2.0/24` with your subnet or target IP.

> `-Pn` is a default reflex on HTB. Skipping host discovery saves time and avoids false negatives.

---

## Stage 2 — Port Scanning

### TCP (always do `-p-`)
```bash
sudo nmap -sS -p- --min-rate 1000 -Pn -n 10.129.2.28 -oA tcp_full
sudo nmap -sS -F  -Pn 10.129.2.28                            # top 100 (quick)
sudo nmap -sS --top-ports=1000 -Pn 10.129.2.28               # top 1000
```

> `-sS` sends SYN packets without completing the handshake (stealth scan, requires root). `-p-` scans all 65535 ports. `--min-rate 1000` sets minimum send rate. `-F` scans only the top 100 ports for a quick result. Replace `10.129.2.28` with your target IP.

| Flag | Meaning |
|------|---------|
| `-sS` | SYN stealth (default if root) |
| `-sT` | Full TCP connect (non-root) |
| `-sA` | ACK scan — maps firewall rules (open\|filtered) |
| `-sN` `-sF` `-sX` | NULL/FIN/Xmas — bypass stateless filters |
| `-sW` | Window scan |
| `-sM` | Maimon |

### UDP (slow but critical for SNMP/DNS/IPMI/IKE)
```bash
sudo nmap -sU --top-ports=100 --min-rate 1000 -Pn 10.129.2.28 -oA udp_top
sudo nmap -sU -p 53,67,68,69,123,137,161,500,1900,5353 -sV 10.129.2.28
```

> `-sU` runs a User Datagram Protocol (UDP) scan. `--top-ports=100` checks the 100 most common UDP ports. The second command targets specific high-value UDP ports including Domain Name System (DNS) port 53, Simple Network Management Protocol (SNMP) port 161, and Internet Key Exchange (IKE) port 500. Replace `10.129.2.28` with your target.

> **NIXHARD lesson:** Switch to **UDP OpenVPN** before scanning UDP — TCP-over-TCP tunnels drop UDP probes (false negatives).
> SNMP/161 invisible on TCP VPN; visible on UDP VPN.

### Port states quick-decode
| State | Meaning |
|-------|---------|
| `open` | service listening |
| `closed` | reachable, nothing listening (host alive!) |
| `filtered` | firewall dropped probe (no reply) |
| `open\|filtered` | UDP/NULL ambiguous |
| `unfiltered` | ACK scan saw RST — port reachable but state unknown |

---

## Stage 3 — Service/Version & Default Scripts

```bash
# The "actually useful" scan
sudo nmap -sC -sV -p<openports> -Pn -n --min-rate 1000 10.129.2.28 -oA services

# Full enum one-liner (use AFTER -p- found ports)
sudo nmap -sCV -A -O -p22,80,445 10.129.2.28 -oA full

# Aggressive (-A = -sC -sV -O --traceroute)
sudo nmap -A -p- 10.129.2.28
```

> `-sC` runs default Nmap Scripting Engine (NSE) scripts. `-sV` detects service versions. `-p<openports>` limits the scan to only the ports you already found open (faster and less noisy). `-A` combines version detection, script scanning, OS detection, and traceroute in one flag.

Version intensity: `--version-intensity 0..9` (default 7, `--version-all` = 9, `--version-light` = 2).

---

## Stage 4 — NSE Scripts (the killer features)

```bash
# Run a category
sudo nmap --script default       -p 80,443 TARGET
sudo nmap --script vuln          -p- TARGET                  # CVE checker
sudo nmap --script safe          TARGET
sudo nmap --script discovery,auth TARGET

# Search local NSE library
locate *.nse | xargs grep -l "smb-enum"
ls /usr/share/nmap/scripts | grep -i ftp

# Service-specific go-tos
sudo nmap --script "ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor" -p 21 TARGET
sudo nmap --script "smb-os-discovery,smb-enum-shares,smb-enum-users,smb2-security-mode,smb-vuln-*" -p 445 TARGET
sudo nmap --script "http-title,http-enum,http-headers,http-methods,http-shellshock,http-sql-injection" -p 80,443 TARGET
sudo nmap --script "ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle" -p 443 TARGET
sudo nmap --script "dns-zone-transfer,dns-recursion,dns-cache-snoop" -p 53 TARGET
sudo nmap --script "snmp-info,snmp-brute,snmp-sysdescr,snmp-processes" -sU -p 161 TARGET
sudo nmap --script "ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-tables" -p 1433 TARGET
sudo nmap --script "rdp-enum-encryption,rdp-vuln-ms12-020" -p 3389 TARGET

# Pass args to scripts
sudo nmap --script smb-brute --script-args userdb=users.txt,passdb=pws.txt -p 445 TARGET
```

> `--script` runs specific NSE scripts by name or category. Use `locate *.nse | xargs grep -l "keyword"` to find relevant scripts. `--script-args` passes parameters like credential lists. Replace `TARGET` with the target IP.

NSE script categories: `auth, broadcast, brute, default, discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, version, vuln`.

---

## Stage 5 — Performance & Timing

```bash
# Timing templates
-T0 paranoid  -T1 sneaky  -T2 polite  -T3 normal  -T4 aggressive  -T5 insane

# Manual tuning (better than -T flags)
--min-rate 1000             # packets/sec floor
--max-rate 5000             # don't drown the link
--min-parallelism 100       # concurrent probes
--max-retries 1             # default 10 — overkill on labs
--host-timeout 5m
--scan-delay 1s             # slow when WAF complaining

# Realistic HTB scan
sudo nmap -sS -p- --min-rate 1000 --max-retries 1 -Pn -n -T4 TARGET
```

> Timing controls: `-T0` through `-T5` are preset profiles from slowest (paranoid) to fastest (insane). On HTB, `-T4` is the practical maximum. `--min-rate`, `--max-rate`, `--max-retries`, and `--scan-delay` give finer control than timing templates alone.

> `-n` (no DNS) and `-Pn` (skip host discovery) cut 30%+ on HTB scans.

---

## Stage 6 — Firewall / IDS Evasion

```bash
# Decoys (mix real with fake source IPs)
sudo nmap -D RND:10 TARGET
sudo nmap -D 10.0.0.1,10.0.0.2,ME,10.0.0.3 TARGET

# Spoofed source / interface
sudo nmap -S 10.0.0.5 -e tun0 -Pn TARGET

# Source port spoof (firewalls often trust 53/80/443)
sudo nmap --source-port 53 TARGET
sudo nmap -g 53 TARGET

# Fragmentation
sudo nmap -f TARGET                     # 8-byte fragments
sudo nmap --mtu 24 TARGET               # custom MTU (multiple of 8)

# Slow + random + decoys (full evasion)
sudo nmap -sS -T1 --max-retries 1 --scan-delay 5s -D RND:10 -f --data-length 25 TARGET

# Check what triggered the firewall
sudo nmap --packet-trace --reason -Pn -n -p 445 TARGET
```

> `-D RND:10` generates 10 random decoy IP addresses to hide your real source. `-S` spoofs the source IP (pair with `-e` to specify the interface). `--source-port 53` makes packets look like DNS traffic — many firewalls allow this. `-f` fragments packets into 8-byte chunks. `--packet-trace` shows every packet sent and received. Replace `TARGET` with the target IP.

---

## Stage 7 — Saving & Converting Results

```bash
-oN file.nmap     # normal text
-oG file.gnmap    # greppable
-oX file.xml      # XML
-oA basename      # all three at once
-v / -vv          # verbosity
-d / -dd          # debug
--reason          # why a port is in that state

# Convert XML → HTML
xsltproc scan.xml -o scan.html

# Greppable port extraction
cat scan.gnmap | grep open | awk '{print $2}'                 # alive hosts
grep -oP '\d+/open' scan.gnmap | sort -u                      # unique ports
```

> `-oN` saves normal text output. `-oG` saves greppable format. `-oX` saves XML. `-oA basename` saves all three at once — use this by default. `xsltproc` converts XML output to an HTML report. Replace `scan` with your filename base.

---

## Stage 8 — High-value Recipes (memorize)

### "Fastest full TCP" (HTB go-to)
```bash
sudo nmap -sS -p- --min-rate 1000 --max-retries 1 -Pn -n -oA full TARGET
```

> The fastest reliable full port scan for HTB. Scans all 65535 ports with a stealth SYN scan. Saves all output formats via `-oA`. Replace `TARGET` with the target IP.

### "Then enrich the open ports"
```bash
ports=$(grep -oP '\d+/open' full.gnmap | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
sudo nmap -sCV -p$ports -oA deep TARGET
```

> Extracts open port numbers from the greppable output file (`full.gnmap`), then runs version detection and default scripts against only those ports. Much faster than re-scanning all 65535 ports. Run this immediately after the full port scan.

### "UDP top-100" (don't forget!)
```bash
sudo nmap -sU --top-ports=100 --min-rate 1000 -Pn -n -oA udp TARGET
```

> Always run a UDP scan — SNMP (161), DNS (53), and IPMI (623) are critical services that only appear on UDP. `--top-ports=100` checks the 100 most common UDP ports. Replace `TARGET` with the target IP.

### "Quick subnet sweep + service enum"
```bash
sudo nmap -sn 10.129.2.0/24 -oA sweep
sudo nmap -sS -F -sV -iL <(grep -oP '\d+\.\d+\.\d+\.\d+' sweep.gnmap) -oA quick
```

> First discovers all alive hosts in the subnet with `-sn`, then immediately runs a fast service scan against every live host. `grep -oP` extracts IP addresses from the sweep output and feeds them to the second scan via process substitution.

### "Vuln pass on every open port"
```bash
sudo nmap --script vuln -p$ports -oA vulns TARGET
```

> Runs all scripts in the `vuln` NSE category against every open port. This checks for known CVEs and misconfigurations. Run this after you have the full port list in `$ports`. Replace `TARGET` with the target IP.

---

## STUCK? Triage

| Symptom | Fix |
|---------|-----|
| All ports `filtered` | host firewalled — try `-Pn`, fragment `-f`, `--source-port 53`, slow timing |
| Scan never finishes | drop `-A`, lower `--max-retries 1`, narrow ports |
| UDP scan empty | switch to UDP OpenVPN; rate-limited responses look closed |
| `-sV` says "tcpwrapped" | host wraps service detection — try `-sV --version-all`, manual banner grab `nc -nv TARGET PORT` |
| OS detection wrong | needs ≥1 open + 1 closed TCP port; add `-O --osscan-guess` |
| NSE script "no reply" | wrong port/state; check with `--reason --packet-trace` |
| Host shown down but you can ping | ICMP allowed, TCP probes blocked — `-Pn` |
| Scan kills VPN | lower rate (`--max-rate 500`), reconnect VPN |

---

## Common Ports Quick Reference

| Port | Service | Quick win |
|------|---------|-----------|
| 21 | FTP | anonymous, `ftp-anon` NSE |
| 22 | SSH | banner → CVE; never brute first |
| 25/465/587 | SMTP | `VRFY`/`EXPN`/`RCPT` user enum |
| 53 | DNS | AXFR, subdomain brute |
| 80/443 | HTTP(S) | gobuster, `whatweb`, headers |
| 88 | Kerberos | AD! → user enum, AS-REP |
| 110/995 | POP3 | cred reuse from Linux PAM |
| 111/2049 | NFS | `showmount -e` |
| 135/139/445 | SMB/RPC | `nxc smb -u guest -p ''` |
| 161 | SNMP | `onesixtyone`, `snmpwalk -v2c -c public` |
| 389/636/3268 | LDAP | `ldapsearch -x` |
| 443 | HTTPS | cert SANs → hostnames |
| 1433 | MSSQL | `mssqlclient.py -windows-auth` |
| 1521 | Oracle TNS | `odat`, default SIDs |
| 2049 | NFS | mount `-t nfs -o vers=3` |
| 3306 | MySQL | `mysql -h TARGET -u root` |
| 3389 | RDP | `xfreerdp /u:U /p:P /v:T` |
| 5432 | PostgreSQL | `psql -h TARGET -U postgres` |
| 5985/5986 | WinRM | `evil-winrm`, `nxc winrm` |
| 6379 | Redis | `redis-cli -h TARGET` |
| 8080/8443 | HTTP-alt | Tomcat manager, Jenkins |

---

## References

- [README.md](README.md) — module section index
- [Service_Enumeration.md](Service_Enumeration.md)
- [NSE_Scripts.md](NSE_Scripts.md)
- [Firewall_IDS_Evasion.md](Firewall_IDS_Evasion.md)
- [Saving_and_Converting_Results.md](Saving_and_Converting_Results.md)
