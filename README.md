# Offensive Security Development

Documenting my path through security certifications and hands-on penetration testing in 2026.

| Certification | Status | Target |
|---------------|--------|--------|
| Security+ | ✅ Passed (768/900, 85.3%) | Jan 2026 |
| CPTS | 📖 In Progress (~55.8%, 15/28 modules) | June 2026 |
| CRTO | Planned | After CPTS |
| CRTE | Planned | After CRTO |
| CARTP | Planned | After CRTE |

---

## Current Status (May 11, 2026)

```
CPTS Learning Pathway: ██████████████████████░░░░░░░░░░░░░░░░░░ ~55.8%
```

| Metric | Status |
|--------|--------|
| Machines Completed | 22 (19 Very Easy, 3 Easy) |
| Academy Modules Complete | 15 / 28 |
| Academy Module In Progress | None — between modules |
| Reference Guides | 280+ |
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
| Using Web Proxies | ✅ Complete (15/15) |
| Attacking Web Applications with FFuF | ✅ Complete (13/13) |
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
|   |   |-- Using_Web_Proxies/                         ← 15 guides (complete)
|   |   |-- Attacking_Web_Apps_with_FFuF/              ← 13 guides (complete)
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
Host discovery, port scanning, NSE scripts, firewall evasion, performance tuning, 3 skill assessment labs.

### Footprinting
FTP, SMB, NFS, DNS, SMTP, IMAP/POP3, SNMP, MySQL, MSSQL, Oracle TNS, IPMI, Linux/Windows remote management.

### Information Gathering - Web Edition
WHOIS, DNS, subdomains, vhosts, CT logs, crawling, Google dorking, Wayback Machine.

### Vulnerability Assessment
Nessus, OpenVAS, CVSS scoring, vulnerability reporting methodology.

### File Transfers
Windows/Linux methods, LOLBins, encrypted transfers, detection evasion.

### Shells & Payloads
Bind/reverse shells, MSFvenom, web shells (Laudanum, Antak), TTY upgrade, Windows infiltration.

### Using the Metasploit Framework
MSFconsole, modules, payloads, encoders, Meterpreter, MSFvenom, IDS/IPS evasion.

### Password Attacks
John, Hashcat, SAM/LSASS/NTDS.dit, Pass-the-Hash, Pass-the-Ticket, Pass-the-Certificate, credential hunting.

### Attacking Common Services
FTP, SMB, SQL, RDP, DNS, email attacks. Skills assessments: Easy/Medium/Hard.

### Pivoting, Tunneling & Port Forwarding
SSH SOCKS, Chisel, Sshuttle, Socat, SocksOverRDP, plink, ICMP tunneling.

### Active Directory Enumeration & Attacks ✅ (37 guides)
| Guide | Description |
|-------|-------------|
| 00-EXAM_CHEATSHEET.md | Full AD attack cheatsheet — 5-phase attack flow, every tool explained |
| Sections 01–16 | Enumeration: Responder, Inveigh, spraying, BloodHound, CME, PowerView, LOLAD |
| Sections 17–18 | Kerberoasting (Linux + Windows) |
| Sections 19–21 | ACL abuse: ForceChangePassword, GenericAll, targeted Kerberoasting |
| Section 22 | DCSync |
| Section 23 | Privileged Access: WinRM, PSExec, WMI, DCOM, MSSQL |
| Section 24 | Kerberos Double Hop |
| Section 25 | Bleeding Edge: NoPac, PrintNightmare, PetitPotam + ADCS |
| Section 26 | Misc Misconfigs: PASSWD_NOTREQD, GPP, AS-REP Roasting |
| Sections 27–31 | Domain Trusts: ExtraSids child→parent, cross-forest Kerberoasting |
| Sections 32–33 | Hardening + Auditing (PingCastle, Group3r, ADRecon) |
| Sections 34–35 | Skills Assessments I & II (full attack chains) |

### Using Web Proxies ✅ (15 guides)
| Guide | Description |
|-------|-------------|
| 01-03 | Setup, FoxyProxy, CA certificate installation |
| 04 | Intercepting requests — bypass client-side validation |
| 05 | Intercepting responses — modify HTML before browser renders |
| 06 | Automatic modification — Match & Replace / Replacer rules |
| 07 | Repeating requests — Burp Repeater / ZAP Request Editor |
| 08 | Encoding/Decoding — Burp Decoder, ZAP E-D-H, multi-layer decoding |
| 09 | Proxying tools — proxychains, MSF PROXIES flag |
| 10 | Burp Intruder — web fuzzing, directory brute force, payload processing |
| 11 | ZAP Fuzzer — MD5/hash-based cookie fuzzing, built-in wordlists |
| 12 | Burp Scanner — crawler, passive scan, active scan, reporting (Pro) |
| 13 | ZAP Scanner — free active scanner, Spider, Ajax Spider |
| 14 | Extensions — BApp Store (Burp) + ZAP Marketplace |
| 15 | Skills Assessment — disabled buttons, multi-encoded cookies, hash fuzzing |

### Attacking Web Applications with FFuF ✅ (13 guides)
| Guide | Description |
|-------|-------------|
| 00-EXAM_CHEATSHEET.md | Full ffuf workflow: vhost → extension → page → param → value fuzzing |
| 01-02 | Introduction and core fuzzing concepts, FUZZ keyword, filtering basics |
| 03 | Directory fuzzing — flags, wordlists, reading 301/403 results |
| 04 | Page fuzzing — two-step: extension fuzzing first, then page names |
| 05 | Recursive fuzzing — `-recursion -recursion-depth 1 -e .php` |
| 06 | DNS records — adding HTB targets to `/etc/hosts` |
| 07 | Sub-domain fuzzing — public DNS-based subdomain discovery |
| 08 | Vhost fuzzing — `Host: FUZZ.domain.htb` header manipulation |
| 09 | Filtering results — `-fs` to remove noise from vhost scans |
| 10 | Parameter fuzzing GET — `?FUZZ=key` in URL |
| 11 | Parameter fuzzing POST — `-X POST -d 'FUZZ=key'` with Content-Type |
| 12 | Value fuzzing — `id=FUZZ` with numeric / names wordlists |
| 13 | Skills Assessment — full chain: vhosts → extensions → pages → params → flag |

### Vulnerability Assessment
Nessus, OpenVAS, CVSS, CVE/OVAL, professional reporting.

---

## Skills Developed

| Category | Skills | Source |
|----------|--------|--------|
| Reconnaissance | Nmap mastery, service enumeration, banner grabbing, firewall evasion | Nmap ✅ |
| Service Enumeration | FTP, SMB, NFS, DNS, SMTP, MySQL, MSSQL, Oracle, SNMP, IPMI, WinRM | Footprinting ✅ |
| Web Recon | WHOIS, subdomain discovery, vhost enumeration, CT logs, fingerprinting | Info Gathering ✅ |
| Vulnerability Assessment | Nessus, OpenVAS, CVSS, risk prioritization | Vuln Assessment ✅ |
| File Transfers | HTTP, SMB, FTP, base64, PowerShell, LOLBins, encrypted channels | File Transfers ✅ |
| Shells & Payloads | Bind/reverse shells, MSFvenom, web shells, TTY upgrade | Shells ✅ |
| Metasploit | MSFconsole, modules, Meterpreter, MSFvenom, IDS/IPS evasion | Metasploit ✅ |
| Password Attacks | John, Hashcat, SAM/LSASS/NTDS.dit, PtH, PtT, PtC | Passwords ✅ |
| Common Service Attacks | FTP, SMB, SQL, RDP, DNS, email exploitation | Common Services ✅ |
| Pivoting & Tunneling | SSH SOCKS, Chisel, Sshuttle, Socat, SocksOverRDP | Pivoting ✅ |
| AD Enumeration | LLMNR/NBT-NS poisoning, password spraying, BloodHound, CME, PowerView | AD ✅ |
| AD Credential Attacks | Kerberoasting, AS-REP Roasting, LSASS dump, DCSync, Pass-the-Hash | AD ✅ |
| AD Lateral Movement | WinRM, PSExec, WMI, DCOM, SQL Server, RDP, Kerberos PTT | AD ✅ |
| AD Privilege Escalation | ACL abuse, GenericAll/WriteDACL, SeImpersonatePrivilege | AD ✅ |
| Bleeding Edge AD | NoPac, PrintNightmare, PetitPotam + ADCS relay | AD ✅ |
| Domain Trust Attacks | ExtraSids child→parent, cross-forest Kerberoasting, SID history | AD ✅ |
| Web Proxy — Interception | Intercept/modify requests and responses, bypass client-side validation | Web Proxies ✅ |
| Web Proxy — Automation | Match & Replace rules, automatic payload injection | Web Proxies ✅ |
| Web Proxy — Fuzzing | Burp Intruder, ZAP Fuzzer, wordlists, payload processors | Web Proxies ✅ |
| Web Proxy — Scanning | Burp Scanner (Pro), ZAP active scanner (free), Spider, Ajax Spider | Web Proxies ✅ |
| Web Proxy — Encoding | Multi-layer decode/encode, MD5 cookie fuzzing, JWT manipulation | Web Proxies ✅ |
| Web Fuzzing | Vhost discovery, extension fuzzing, recursive page fuzzing, param/value fuzzing | FFuF ✅ |
| Web Exploitation | SQLi, XSS, file inclusion, command injection, file upload | Upcoming |
| Privilege Escalation | Linux/Windows privesc techniques | Upcoming |

---

## Tools

**Network & Recon:** Nmap, Gobuster, FFuF (vhost/dir/param/value fuzzing), Nikto, Whatweb, DNSenum, DNSrecon, Onesixtyone, Snmpwalk

**Web Proxies:** Burp Suite, ZAP (OWASP), FoxyProxy, Burp Intruder, ZAP Fuzzer, Burp Repeater

**AD & Windows:** Responder, Inveigh, CrackMapExec/Netexec, BloodHound, SharpHound, bloodhound-python, PowerView, Mimikatz, Rubeus, Kerbrute, Evil-WinRM, Certipy-AD, Snaffler, Windapsearch, PingCastle, Group3r, ADRecon

**Impacket Suite:** psexec.py, wmiexec.py, smbexec.py, secretsdump.py, GetUserSPNs.py, GetNPUsers.py, ticketer.py, lookupsid.py, ntlmrelayx.py, mssqlclient.py

**Exploitation:** Metasploit, MSFvenom, SQLmap, PrintSpoofer, JuicyPotato, Chisel

**Password Cracking:** John the Ripper, Hashcat, pypykatz

**Pivoting:** Chisel, Sshuttle, Socat, Proxychains, Plink, Rpivot

---

## Links

- [CPTS Progress Tracker](02-HTB_WRITEUPS/HTB/README.md)
- [Master Enumeration Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Foundation/00-MASTER_ENUMERATION_CHEATSHEET.md)
- [AD Exam Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Active_Directory_Enumeration_and_Attacks/00-EXAM_CHEATSHEET.md)
- [Password Attacks Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Password_Attacks/00-EXAM_CHEATSHEET.md)
- [Pivoting Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Pivoting_Tunneling_and_Port_Forwarding/00-EXAM_CHEATSHEET.md)
- [FFuF Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Attacking_Web_Apps_with_FFuF/00-EXAM_CHEATSHEET.md)

---

Last Updated: May 12, 2026
