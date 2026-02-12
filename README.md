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
|   |-- 02-EASY/                   Easy boxes (2 completed)
|   |-- 06-REFERENCE_GUIDES/
|   |   |-- Foundation/            Core methodology guides
|   |   |-- Network_Enumeration_With_Nmap/   7 Nmap module guides
|   |   |-- MASTER_ENUMERATION_CHEATSHEET.md
|   |-- CPTS_PROGRESS.md           Hours and progress tracker
|
|-- 00-archived/                   Old materials
```

---

## Current Status (February 12, 2026)

| Metric | Status |
|--------|--------|
| Total Hours | 122 / 400 |
| Machines Completed | 21 (19 Very Easy, 2 Easy) |
| Academy Modules | 1 complete (Network Enumeration with Nmap -- all labs) |
| Writeups Published | 21 |
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

### Easy (2)

| Box | Key Skills |
|-----|------------|
| NIBBLES | Web exploitation, Linux privilege escalation |
| GETTING_STARTED | Theme injection, RCE |

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

- [CPTS Progress Tracker](02-HTB_WRITEUPS/HTB/CPTS_PROGRESS.md)
- [Master Enumeration Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/MASTER_ENUMERATION_CHEATSHEET.md)
- [Nmap Guides](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Network_Enumeration_With_Nmap/)
- [Privilege Escalation Guide](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Foundation/Privilege_Escalation.md)

---

Last Updated: February 12, 2026
