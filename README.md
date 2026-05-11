# Offensive Security Development

Documenting my path through security certifications and hands-on penetration testing in 2026.

| Certification | Status | Target |
|---------------|--------|--------|
| Security+ | ✅ Passed (768/900, 85.3%) | Jan 2026 |
| CPTS | 📖 In Progress (~50%) | June 2026 |
| CRTO | Planned | After CPTS |
| CRTE | Planned | After CRTO |
| CARTP | Planned | After CRTE |

---

## Current Status (May 11, 2026)

```
CPTS Learning Pathway: ████████████████████░░░░░░░░░░░░░░░░░░░░ ~50%
```

| Metric | Status |
|--------|--------|
| Machines Completed | 22 (19 Very Easy, 3 Easy) |
| Academy Modules Complete | 11 / 26 |
| Academy Module In Progress | None — between modules |
| Reference Guides | 250+ |
| Target Exam | June 21, 2026 |

---

## Academy Module Progress

| Module | Status |
|--------|--------|
| Network Enumeration with Nmap | ✅ Complete |
| Footprinting | ✅ Complete |
| Information Gathering - Web Edition | ✅ Complete |
| Vulnerability Assessment | ✅ Complete |
| File Transfers | ✅ Complete |
| Shells & Payloads | ✅ Complete |
| Using the Metasploit Framework | ✅ Complete |
| Password Attacks | ✅ Complete |
| Attacking Common Services | ✅ Complete |
| Pivoting, Tunneling & Port Forwarding | ✅ Complete |
| Active Directory Enumeration & Attacks | ✅ Complete (36/36) |
| Using Web Proxies | ⬚ Not Started |
| Attacking Web Applications with FFuF | ⬚ Not Started |
| Login Brute Forcing | ⬚ Not Started |
| SQL Injection Fundamentals | ⬚ Not Started |
| SQLMap Essentials | ⬚ Not Started |
| Cross-Site Scripting (XSS) | ⬚ Not Started |
| File Inclusion | ⬚ Not Started |
| File Upload Attacks | ⬚ Not Started |
| Command Injections | ⬚ Not Started |
| Web Attacks | ⬚ Not Started |
| Attacking Common Applications | ⬚ Not Started |
| Linux Privilege Escalation | ⬚ Not Started |
| Windows Privilege Escalation | ⬚ Not Started |
| Documentation & Reporting | ⬚ Not Started |
| Attacking Enterprise Networks | ⬚ Not Started |

---

## Repository Structure

```
Offensive-Security-Development/
|
|-- 01-SECURITY_PLUS/              Security+ study notes (completed Jan 2026)
|
|-- 02-HTB_WRITEUPS/HTB/
|   |-- 01-FOUNDATIONAL/           Very Easy boxes (19 completed)
|   |-- 02-EASY/                   Easy boxes (3 completed)
|   |-- 06-REFERENCE_GUIDES/
|   |   |-- Foundation/
|   |   |-- Network_Enumeration_With_Nmap/
|   |   |-- Footprinting/
|   |   |-- Information_Gathering_Web_Edition/
|   |   |-- File_Transfers/
|   |   |-- Shells_and_Payloads/
|   |   |-- Using_Metasploit_Framework/
|   |   |-- Password_Attacks/
|   |   |-- Attacking_Common_Services/
|   |   |-- Pivoting_Tunneling_and_Port_Forwarding/
|   |   |-- Active_Directory_Enumeration_and_Attacks/  ← 37 guides (complete)
|   |   |-- Vulnerability_Assessment/
|   |-- README.md                  CPTS progress tracker
|
|-- 00-archived/                   Old planning materials
```

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

## Reference Guides

### Foundation
| Guide | Description |
|-------|-------------|
| MASTER_ENUMERATION_CHEATSHEET.md | Full enumeration flowchart |
| Enumeration_Process.md | Systematic 5-phase enumeration |
| Service_Scanning_Enumeration.md | Nmap, FTP, SMB, SNMP service enumeration |
| Web_Enumeration.md | HTTP/HTTPS, directory brute force, fingerprinting |
| File_Transfer.md | Comprehensive file transfer methods |
| Privilege_Escalation.md | Linux and Windows privilege escalation |
| Public_Exploits.md | Finding and using public CVE exploits |
| Types_of_Shells.md | Shell types reference |

### Network Enumeration with Nmap
| Guide | Description |
|-------|-------------|
| Host_Discovery.md | Network range scans, ICMP/ARP |
| Host_and_Port_Scanning.md | TCP states, SYN/Connect/UDP scans |
| Saving_and_Converting_Results.md | Output formats, xsltproc |
| Service_Enumeration.md | Version detection, banner grabbing |
| NSE_Scripts.md | 14 categories, WordPress enum, vuln scanning |
| Scanning_Performance.md | Timing templates, packet rates |
| Firewall_IDS_Evasion.md | ACK scans, decoys, DNS port 53 abuse |

### Footprinting
| Guide | Description |
|-------|-------------|
| Enumeration_Principles.md | Active vs passive recon |
| Enumeration_Methodology.md | Six-layer framework |
| Domain_Information.md | SSL certs, crt.sh, Shodan |
| FTP.md | Anonymous access, vsFTPd config |
| SMB.md | smbclient, rpcclient, enum4linux-ng |
| NFS.md | NFS share enumeration |
| DNS.md | Zone transfers, record types |
| SMTP.md | User enumeration, relay testing |
| IMAP_POP3.md | Mail service enumeration |
| SNMP.md | Community strings, MIB walking |
| MySQL.md | MySQL enumeration and attacks |
| MSSQL.md | MSSQL enumeration and attacks |
| Oracle_TNS.md | Oracle TNS enumeration |
| IPMI.md | IPMI enumeration, hash extraction |
| Linux_Remote_Management.md | SSH, Rsync, NFS |
| Windows_Remote_Management.md | WinRM, RDP, WMI |

### Information Gathering - Web Edition
| Guide | Description |
|-------|-------------|
| WHOIS, DNS, subdomain brute forcing | Domain intelligence gathering |
| Virtual host enumeration | Internal hostname discovery via ffuf |
| Certificate Transparency | crt.sh for subdomain discovery |
| Web fingerprinting | whatweb, Wappalyzer, response headers |
| Crawling & Google dorking | Automated recon and OSINT |

### File Transfers
| Guide | Description |
|-------|-------------|
| Windows download methods | PowerShell, certutil, BITS, Base64 |
| Linux download methods | wget, curl, SCP, /dev/tcp |
| Code-based transfers | Python, PHP, Ruby HTTP servers |
| Miscellaneous methods | Netcat, SMB, FTP, Impacket |
| LOLBins | Living off the Land for file transfer |
| Encrypted transfers | AES, OpenSSL, HTTPS |

### Shells & Payloads
| Guide | Description |
|-------|-------------|
| Bind & reverse shells | Shell fundamentals and mechanics |
| Payload crafting | MSFvenom, staged vs stageless |
| Windows infiltration | EternalBlue, ASPX shells |
| Web shells | Laudanum, Antak (PowerShell), PHP variants |
| TTY upgrade | Spawning interactive shells from dumb shells |

### Using the Metasploit Framework
| Guide | Description |
|-------|-------------|
| MSFconsole navigation | Modules, search, sessions |
| Payloads & encoders | Staged/stageless, IDS/IPS evasion |
| Meterpreter | Post-exploitation commands, pivoting |
| MSFvenom | Custom payload generation |

### Password Attacks
| Guide | Description |
|-------|-------------|
| John the Ripper & Hashcat | Cracking methodology, rules, masks |
| SAM, LSASS, NTDS.dit | Windows credential extraction |
| Pass-the-Hash / Pass-the-Ticket | NTLM and Kerberos lateral movement |
| Pass-the-Certificate | ADCS certificate abuse |
| Credential hunting | Windows and Linux cleartext credential hunting |

### Attacking Common Services
| Guide | Description |
|-------|-------------|
| SMB attacks | Brute force, RCE, relay |
| SQL database attacks | SQLi, xp_cmdshell, UDF escalation |
| RDP attacks | Brute force, session hijacking |
| DNS & email attacks | Zone transfer, open relay, enumeration |

### Pivoting, Tunneling & Port Forwarding
| Guide | Description |
|-------|-------------|
| SSH SOCKS / local/remote forwarding | Tunnel traffic through SSH |
| Chisel | HTTP-based SOCKS proxy |
| Sshuttle | Transparent VPN-over-SSH |
| Socat & Rpivot | TCP relays and HTTP pivots |
| SocksOverRDP | Pivot using RDP sessions |
| Meterpreter pivoting | MSF route and portfwd |

### Active Directory Enumeration & Attacks ✅ (36/36 complete)
| Guide | Description |
|-------|-------------|
| 00-EXAM_CHEATSHEET.md | Full AD attack cheatsheet — all commands in one place |
| 01-16: Enumeration | LLMNR/NBT-NS poisoning, password spraying, BloodHound, CME, PowerView, LOLAD |
| 17-18: Kerberoasting | GetUserSPNs.py, Rubeus, hash cracking (Linux + Windows) |
| 19-21: ACL Abuse | GenericAll/GenericWrite/WriteDACL/ForceChangePassword, targeted Kerberoasting |
| 22: DCSync | secretsdump.py, Mimikatz lsadump::dcsync |
| 23: Privileged Access | WinRM, RDP, PSExec, WMI, DCOM, SQL Server |
| 24: Kerberos Double Hop | CredSSP workaround, Invoke-Command nested sessions |
| 25: Bleeding Edge | NoPac, PrintNightmare (CVE-2021-1675), PetitPotam + ADCS relay |
| 26: Misc Misconfigurations | PASSWD_NOTREQD, AS-REP Roasting, Group Policy abuse |
| 27-31: Domain Trusts | Child→Parent ExtraSids, cross-forest Kerberoasting, foreign group membership |
| 32-33: Defense & Auditing | Hardening controls, BloodHound/PingCastle/Group3r/ADRecon |
| 34-35: Skills Assessments | Two full attack chains from zero creds to domain compromise |

### Vulnerability Assessment
| Guide | Description |
|-------|-------------|
| Nessus setup & scan config | Templates, credentialed scans, prioritization |
| OpenVAS setup & scan config | Policy-based scanning, NVT database |
| CVSS scoring | Risk calculation, vulnerability prioritization |
| Professional reporting | Assessment report structure |

---

## Skills Developed

| Category | Skills | Source |
|----------|--------|--------|
| Reconnaissance | Nmap mastery, service enumeration, banner grabbing, firewall evasion | Nmap ✅ |
| Service Enumeration | FTP, SMB, NFS, DNS, SMTP, MySQL, MSSQL, Oracle, SNMP, IPMI, WinRM | Footprinting ✅ |
| Web Recon | WHOIS, subdomain discovery, vhost enumeration, CT logs, fingerprinting, dorking | Info Gathering ✅ |
| Vulnerability Assessment | Nessus, OpenVAS, CVSS, risk prioritization | Vuln Assessment ✅ |
| File Transfers | HTTP, SMB, FTP, base64, PowerShell, LOLBins, encrypted channels | File Transfers ✅ |
| Shells & Payloads | Bind/reverse shells, MSFvenom, web shells, TTY upgrade, Windows infiltration | Shells ✅ |
| Metasploit | MSFconsole, modules, Meterpreter, MSFvenom, IDS/IPS evasion | Metasploit ✅ |
| Password Attacks | John, Hashcat, SAM/LSASS/NTDS.dit dumping, PtH, PtT, PtC, credential hunting | Passwords ✅ |
| Common Service Attacks | FTP, SMB, SQL, RDP, DNS, email exploitation | Common Services ✅ |
| Pivoting & Tunneling | SSH SOCKS, Chisel, Sshuttle, Socat, SocksOverRDP, Meterpreter pivoting | Pivoting ✅ |
| AD Enumeration | LLMNR/NBT-NS poisoning, password spraying, BloodHound, CME, PowerView, LOLAD | AD ✅ |
| AD Credential Attacks | Kerberoasting, AS-REP Roasting, LSASS dump, DCSync, Pass-the-Hash | AD ✅ |
| AD Lateral Movement | WinRM, PSExec, WMI, DCOM, SQL Server, RDP, Kerberos PTT | AD ✅ |
| AD Privilege Escalation | ACL abuse, GenericAll/WriteDACL, Kerberos delegation abuse, SeImpersonatePrivilege | AD ✅ |
| Bleeding Edge AD | NoPac, PrintNightmare, PetitPotam, NTLM relay to ADCS | AD ✅ |
| Domain Trust Attacks | ExtraSids (child→parent), cross-forest Kerberoasting, SID history injection | AD ✅ |
| AD Defense & Auditing | Hardening controls, PingCastle, Group3r, ADRecon, Protected Users group | AD ✅ |
| Web Exploitation | SQLi, XSS, file inclusion, command injection, file upload | Upcoming |
| Privilege Escalation | Linux/Windows privesc techniques | Upcoming |

---

## Tools

**Network & Recon:** Nmap, Gobuster, FFuF, Nikto, Whatweb, DNSenum, DNSrecon, Onesixtyone, Snmpwalk

**AD & Windows:** Responder, Inveigh, CrackMapExec/Netexec, BloodHound, SharpHound, bloodhound-python, PowerView, SharpView, Mimikatz, Rubeus, Kerbrute, Evil-WinRM, Certipy-AD, Snaffler, Windapsearch, PingCastle, Group3r, ADRecon, AD Explorer

**Impacket Suite:** psexec.py, wmiexec.py, smbexec.py, secretsdump.py, GetUserSPNs.py, GetNPUsers.py, ticketer.py, lookupsid.py, ntlmrelayx.py, mssqlclient.py, smbclient.py

**Exploitation:** Metasploit, MSFvenom, SQLmap, PrintSpoofer, JuicyPotato, Chisel

**Password Cracking:** John the Ripper, Hashcat, pypykatz

**Pivoting:** Chisel, Sshuttle, Socat, Proxychains, Plink, Rpivot

**Web:** Burp Suite, FFuF, Gobuster, Nikto, WPScan, WhatWeb

---

## Links

- [CPTS Progress Tracker](02-HTB_WRITEUPS/HTB/README.md)
- [Master Enumeration Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Foundation/00-MASTER_ENUMERATION_CHEATSHEET.md)
- [AD Exam Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Active_Directory_Enumeration_and_Attacks/00-EXAM_CHEATSHEET.md)
- [Password Attacks Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Password_Attacks/00-EXAM_CHEATSHEET.md)
- [Pivoting Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Pivoting_Tunneling_and_Port_Forwarding/00-EXAM_CHEATSHEET.md)

---

Last Updated: May 11, 2026
