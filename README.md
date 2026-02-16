# Offensive Security Development

Documenting my path through security certifications and hands-on penetration testing in 2026.

| Certification | Status | Target |
|---------------|--------|--------|
| Security+ | Passed (768/900, 85.3%) | Jan 2026 |
| CPTS | In Progress | April 2026 |
| OSCP | Planned | August 2026 |
| CRTO | Planned | October 2026 |

---

## Repository Structure

```
Cybersecurity_Professional_Development/
|
|-- 01-SECURITY_PLUS/              Security+ study notes (completed)
|
|-- 02-HTB_WRITEUPS/HTB/
|   |-- 01-FOUNDATIONAL/           Very Easy boxes (19 completed)
|   |-- 02-EASY/                   Easy boxes (3 completed)
|   |-- 06-REFERENCE_GUIDES/
|   |   |-- Foundation/            Core methodology guides
|   |   |-- Network_Enumeration_With_Nmap/   7 Nmap module guides
|   |   |-- Footprinting/          5 Footprinting module guides
|   |   |-- MASTER_ENUMERATION_CHEATSHEET.md
|   |-- README.md                  CPTS hours and progress tracker
|
|-- 00-archived/                   Old materials
```

---

## Current Status (February 16, 2026)

| Metric | Status |
|--------|--------|
| Total Hours | 150 / 400 (37%) |
| Machines Completed | 22 (19 Very Easy, 3 Easy) |
| Academy Modules | 1 complete (Nmap), 1 in progress (Footprinting) |
| Writeups Published | 22 |
| Target Exam | April 1-10, 2026 |

---

## Completed Boxes

### Very Easy (19)

| Box | Key Skills |
|-----|------------|
| MEOW | Telnet, default creds |
| FAWN | FTP anonymous access |
| DANCING | SMB null session |
| REDEEMER | Redis enumeration |
| EXPLOSION | Windows RDP |
| PREIGNITION | Directory brute force (Gobuster) |
| MONGOD | MongoDB enumeration |
| SYNCED | Rsync enumeration |
| APPOINTMENT | SQL injection auth bypass |
| SEQUEL | MySQL/MariaDB enumeration |
| CROCODILE | FTP credential exfil + web login |
| RESPONDER | NTLM capture with Responder |
| THREE | AWS S3 bucket exploitation |
| IGNITION | Web enumeration |
| BIKE | SSTI exploitation |
| FUNNEL | SSH tunneling |
| PENNYWORTH | Jenkins script console RCE |
| TACTICS | SMB + PSExec |
| ARCHETYPE | SMB + MSSQL + xp_cmdshell + WinPEAS + PSExec |

### Easy (3)

| Box | Key Skills |
|-----|------------|
| NIBBLES | Web exploitation, Linux privilege escalation |
| GETTING_STARTED | Theme injection, RCE |
| LAME | SMB Samba 3.0.20 usermap_script (CVE-2007-2447), direct root |

---

## Academy Modules

### Network Enumeration with Nmap -- Complete (All Labs Passed)

7 sections + 3 skill assessment labs (Easy, Medium, Hard) covering the full Nmap module from the CPTS Academy path.

| Section | Guide | Topics |
|---------|-------|--------|
| 1 | Host_Discovery.md | Network range scans, IP lists, ICMP/ARP |
| 2 | Host_and_Port_Scanning.md | TCP states, SYN/Connect/UDP scans, filtered ports |
| 3 | Saving_and_Converting_Results.md | Output formats (-oN, -oG, -oX), xsltproc |
| 4 | Service_Enumeration.md | Version detection (-sV), banner grabbing, tcpdump |
| 5 | NSE_Scripts.md | 14 categories, WordPress enum, vuln scanning |
| 6 | Scanning_Performance.md | Timing templates (T0-T5), timeout tuning, packet rates |
| 7 | Firewall_IDS_Evasion.md | ACK scans, decoys, source spoofing, DNS port 53 abuse |

**Skill Assessment Labs:**

| Lab | Difficulty | Key Technique |
|-----|-----------|---------------|
| Easy | Easy | Standard enumeration |
| UDP DNS Enumeration | Medium | `-sU -sV` to trigger DNSVersionBindReq on port 53 |
| Filtered Port Bypass | Hard | `-g 53` source port abuse + ncat manual connection to filtered db2 port |

---

## Footprinting Module (In Progress)

| Section | Guide | Topics |
|---------|-------|--------|
| 1 | Enumeration_Principles.md | What we see vs don't see, active vs passive recon |
| 2 | Enumeration_Methodology.md | Six-layer framework (Internet → OS Setup) |
| 3 | Domain_Information.md | SSL certs, crt.sh, DNS records, Shodan |
| 4 | FTP.md | Ports 20/21, active vs passive, anonymous access, vsFTPd |
| 5 | SMB.md | SMB/CIFS, Samba, smbclient, rpcclient, enum4linux-ng, CrackMapExec |

---

## Reference Guides

### Foundation

| Guide | Description |
|-------|-------------|
| Enumeration_Process.md | Systematic 5-phase enumeration |
| Service_Scanning_Enumeration.md | Nmap, FTP, SMB, SNMP service enumeration |
| Web_Enumeration.md | HTTP/HTTPS, directory brute force, fingerprinting |
| File_Transfer.md | wget, curl, SCP, Base64, SMB transfers |
| Privilege_Escalation.md | Linux and Windows privilege escalation |
| Public_Exploits.md | Finding and using public CVE exploits |
| Types_of_Shells.md | Comprehensive shell type guide |
| MASTER_ENUMERATION_CHEATSHEET.md | Full enumeration flowchart |

---

## Tools

Nmap, Gobuster, FFuF, Nikto, SMBclient, enum4linux, Hydra, Responder, Impacket (mssqlclient.py, psexec.py), LinPEAS, WinPEAS, Netcat, Ncat, Metasploit, WhatWeb, SearchSploit, tcpdump

---

## Links

- [CPTS Progress Tracker](02-HTB_WRITEUPS/HTB/README.md)
- [Master Enumeration Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/MASTER_ENUMERATION_CHEATSHEET.md)
- [Nmap Guides](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Network_Enumeration_With_Nmap/)
- [Footprinting Guides](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Footprinting/)
- [Privilege Escalation Guide](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Foundation/Privilege_Escalation.md)

---

Last Updated: February 16, 2026
