# Offensive Security Development

Documenting my hands-on penetration-testing training as I build toward cleared-defense software engineering, with reverse engineering / vulnerability research as the long-term specialization.

| Certification | Status | Target |
|---------------|--------|--------|
| CompTIA Security+ | ✅ Passed (768/900, 85.3%) | Jan 2026 |
| OSCP (OffSec PEN-200) | 📖 In progress | Exam Sep 23, 2026 |
| OSED (EXP-301, exploit dev → RE) | Planned | Post-graduation |

*Foundation built via the full HTB Academy CPTS pathway (28/28 modules); OSCP is the current exam focus.*

---

## Current Status (August 2026)

```
HTB Academy CPTS Pathway: ████████████████████████████████████████ 100%
OSCP (PEN-200) Prep:      ██████████████████░░░░░░░░░░░░░░░░░░░░░░  in progress
```

| Metric | Status |
|--------|--------|
| Current focus | OSCP / PEN-200 — exam Sep 23, 2026 |
| Machines Completed | 33 (19 Very Easy, 3 Easy, 11 AD boxes) |
| Academy Modules Complete | 28 / 28 (full CPTS pathway) |
| Reference Guides | 460+ |
| AD Box Practice | Active, Forest, Sauna, Cicada, Support, Manager, Cascade, Certified, Escape, Authority, Blackfield |

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
| Login Brute Forcing | ✅ Complete (13/13) |
| SQL Injection Fundamentals | ✅ Complete (17/17) |
| SQLMap Essentials | ✅ Complete (11/11) |
| Cross-Site Scripting (XSS) | ✅ Complete (10/10) |
| File Inclusion | ✅ Complete (11/11) |
| File Upload Attacks | ✅ Complete (11/11) |
| Command Injections | ✅ Complete (12/12) |
| Web Attacks | ✅ Complete (18/18) |
| Attacking Common Applications | ✅ Complete (33/33) |
| Linux Privilege Escalation | ✅ Complete (28/28) |
| Windows Privilege Escalation | ✅ Complete (33/33) |
| Documentation & Reporting | ✅ Complete (8/8) |
| Attacking Enterprise Networks | ✅ Complete |

---

## Repository Structure

```
Offensive-Security-Development/
|
|-- 01-SECURITY_PLUS/              Security+ study notes (completed Jan 2026)
|
|-- 02-HTB_WRITEUPS/HTB/
|   |-- 01-FOUNDATIONAL/           Very Easy boxes (19 completed)
|   |-- 02-EASY/                   Easy boxes (3 + 6 AD)
|   |-- 03-MEDIUM/                 Medium AD boxes (5 completed)
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
|   |   |-- Login_Brute_Forcing/                       ← 13 guides (complete)
|   |   |-- SQL_Injection_Fundamentals/                ← 17 guides (complete)
|   |   |-- SQLMap_Essentials/                         ← 11 guides (complete)
|   |   |-- Cross_Site_Scripting/                      ← 10 guides (complete)
|   |   |-- File_Inclusion/                            ← 11 guides (complete)
|   |   |-- File_Upload_Attacks/                       ← 11 guides (complete)
|   |   |-- Command_Injections/                        ← 12 guides (complete)
|   |   |-- Web_Attacks/                               ← 18 guides (complete)
|   |   |-- Attacking_Common_Applications/             ← 34 guides (complete)
|   |   |-- Linux_Privilege_Escalation/                ← 29 guides (complete)
|   |   |-- Windows_Privilege_Escalation/              ← 34 guides (complete)
|   |   |-- Documentation_and_Reporting/              ← 9 guides (complete)
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

### Easy (9)

| Box | Key Skills |
|-----|------------|
| NIBBLES | Web exploitation, Linux privilege escalation |
| GETTING_STARTED | Theme injection, RCE |
| LAME | SMB Samba 3.0.20 usermap_script (CVE-2007-2447), direct root |
| ACTIVE | GPP cpassword decrypt, Kerberoast, PSExec |
| FOREST | AS-REP roast, BloodHound ACL chain → DCSync, PtH |
| SAUNA | AS-REP roast, autologon registry, DCSync, PtH |
| CICADA | LDAP enum, password spray |
| SUPPORT | .NET reversing, RBCD |
| MANAGER | MSSQL, ADCS ESC7 |

### Medium (5)

| Box | Key Skills |
|-----|------------|
| CASCADE | LDAP anonymous enum, TightVNC decrypt, .NET reversing, AD Recycle Bin |
| CERTIFIED | ACL chaining (WriteOwner → DACL → group), Shadow Credentials, ADCS ESC9 |
| ESCAPE | MSSQL xp_dirtree coercion, Responder NTLMv2, ADCS ESC1 |
| AUTHORITY | Ansible vault, PWM config redirect, ADCS ESC1, PassTheCert |
| BLACKFIELD | AS-REP Roasting, ForceChangePassword, LSASS dump analysis, SeBackupPrivilege → ntds.dit |

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

### Login Brute Forcing ✅ (13 guides)
| Guide | Description |
|-------|-------------|
| 00-EXAM_CHEATSHEET.md | Full brute-forcing playbook: wordlist selection, Hydra/Medusa/ffuf commands per protocol |
| 01-04 | Default creds, username/password enumeration, wordlist building (CeWL, username-anarchy) |
| 05-07 | Hydra basics, syntax modules, web login forms (HTTP-POST-FORM with success/failure strings) |
| 08-10 | Service brute force: SSH, FTP, SMB, RDP, MSSQL, VNC, POP3 |
| 11-12 | Custom wordlists, password mutation (hashcat rules), hybrid attacks |
| 13 | Skills Assessment — full chain: username harvest → spray → admin login |

### SQL Injection Fundamentals ✅ (17 guides)
| Guide | Description |
|-------|-------------|
| 00-EXAM_CHEATSHEET.md | Complete SQLi payload reference: auth bypass, UNION extraction, file ops, web shell |
| 01-05 | SQL basics, MySQL CLI, statements, query results, operators |
| 06-08 | Intro to SQLi, subverting query logic, comments, parenthesis handling |
| 09-11 | UNION clause mechanics, column count, visible columns, UNION injection |
| 12-13 | Database enumeration via INFORMATION_SCHEMA: schemata, tables, columns |
| 14-15 | File ops: LOAD_FILE for source code leak, INTO OUTFILE for web shell |
| 16 | Mitigations: parameterized queries, sanitization, least privilege, WAF |
| 17 | Skills Assessment — chattr.htb: invitation bypass → UNION → admin hash → RCE |

### SQLMap Essentials ✅ (11 guides)
| Guide | Description |
|-------|-------------|
| 00-EXAM_CHEATSHEET.md | All sqlmap flags by category: input, tuning, bypass, enumeration, OS exploitation |
| 01-03 | Overview, BEUSTQ techniques, getting started, output interpretation |
| 04 | Request types — GET/POST/cookie/JSON/header/-r request file |
| 05 | Error handling: --parse-errors, -t traffic.txt, -v 6, --proxy |
| 06 | Attack tuning: --prefix/--suffix for non-standard boundaries, --level/--risk, --tamper |
| 07-08 | DB enumeration: --schema, --search, --dump, password hash cracking |
| 09 | Bypasses: --csrf-token, --randomize, --random-agent, tamper scripts |
| 10 | OS exploitation: --file-read, --file-write, --os-shell, --os-cmd |
| 11 | Skills Assessment — Minishop JSON action.php with `>` filter, `--tamper=between` |

### Cross-Site Scripting (XSS) ✅ (10 guides)
| Guide | Description |
|-------|-------------|
| 00-EXAM_CHEATSHEET.md | Full XSS playbook: types, breakouts, cookie stealer, phishing form, defacing |
| 01-04 | Theory: Stored / Reflected / DOM-based — detection payloads per type |
| 05 | Discovery: XSStrike, manual probing, SecLists XSS wordlists, error-path reflection |
| 06 | Defacing: document.body.style, document.title, innerHTML body replacement |
| 07 | Phishing: inject login form, redirect listener, credential capture |
| 08 | Session Hijacking: blind XSS field probing (unique paths), cookie exfil, replay |
| 09 | Prevention: htmlspecialchars, DOMPurify, CSP, HttpOnly cookies |
| 10 | Skills Assessment — WordPress blog, blind XSS via comment `url` field (`http://x"` breakout) |

### File Inclusion ✅ (11 guides)
| Guide | Description |
|-------|-------------|
| 00-EXAM_CHEATSHEET.md | Full LFI/RFI playbook: wrappers, log poisoning, automated scanning |
| 01-03 | LFI intro, path traversal, basic bypasses (null bytes, encoding, approved paths) |
| 04-05 | PHP filters (`php://filter` base64 read) and PHP wrappers (data://, input://, expect://) |
| 06 | Remote File Inclusion — hosted shells, Windows UNC paths |
| 07-08 | LFI + file uploads for RCE; log poisoning (Apache/SSH/mail logs) |
| 09 | Automated scanning with ffuf and LFI wordlists |
| 10 | Prevention: input validation, disable_functions, WAF |
| 11 | Skills Assessment — LFI chain to RCE via log poisoning |

### File Upload Attacks ✅ (11 guides)
| Guide | Description |
|-------|-------------|
| 00-EXAM_CHEATSHEET.md | Full upload attack decision tree: absent → client → blacklist → whitelist → type filters |
| 01-03 | Intro, absent validation (direct .php upload), basic exploitation |
| 04 | Client-side bypass — intercept in Burp, change Content-Type |
| 05 | Blacklist bypass — `.php5`, `.phtml`, `.phar`, `.shtml` extensions |
| 06 | Whitelist bypass — double extensions (`shell.jpg.php`), null bytes |
| 07 | Type filter bypass — magic bytes (`FF D8 FF`), exiftool metadata injection |
| 08 | Limited uploads — XML XXE, SVG XSS, PDF/ZIP injection |
| 09 | Other attacks — zip slip, directory traversal in filename |
| 10 | Prevention: allowlist validation, storage separation, Content-Type server-check |
| 11 | Skills Assessment — full bypass chain to RCE |

### Command Injections ✅ (12 guides)
| Guide | Description |
|-------|-------------|
| 00-EXAM_CHEATSHEET.md | Full injection playbook: operators, space bypass, char bypass, obfuscation |
| 01-04 | Intro, detection (error-based/blind), injection operators (`;`, `||`, `&&`, `\|`) |
| 05 | Identifying filters — which chars/commands are blocked |
| 06 | Bypassing space filters — `${IFS}`, `%09` (tab), brace expansion |
| 07 | Bypassing blacklisted chars — `$'c'at`, variable manipulation, path tricks |
| 08 | Bypassing blacklisted commands — case manipulation, `w'h'o'a'm'i'`, `who$@ami` |
| 09 | Advanced obfuscation — reverse strings, base64, `$(rev<<<...)` |
| 10 | Evasion tools — Bashfuscator, DOSfuscation (Windows) |
| 11 | Prevention: input sanitization, `escapeshellcmd()`, server-side allowlists |
| 12 | Skills Assessment — blind injection, filter bypass chain to RCE |

### Web Attacks ✅ (18 guides)
| Guide | Description |
|-------|-------------|
| 00-EXAM_CHEATSHEET.md | Full cheatsheet: HTTP verb tampering, IDOR, XXE — attacks + bypasses |
| 01-05 | HTTP Verb Tampering: intro, exploiting, bypass basic auth, bypass security filters, prevention |
| 06-12 | IDOR: intro, identifying IDORs, mass enumeration, encoded reference bypass, API IDORs, chaining, prevention |
| 13-17 | XXE: intro, local file disclosure, advanced file disclosure, blind exfiltration (DNS/OOB), prevention |
| 18 | Skills Assessment — chain HTTP verb + IDOR + XXE for full compromise |

### Attacking Common Applications ✅ (34 guides)
| Guide | Description |
|-------|-------------|
| 00-EXAM_CHEATSHEET.md | Quick-reference for all 15+ application types |
| 01-02 | Discovery & enumeration methodology, application fingerprinting |
| 03-04 | WordPress: WPScan, plugin upload RCE, CVE-2021-29447 XXE |
| 05-06 | Joomla: template editor RCE, CVE-2019-10945 |
| 07-08 | Drupal: Drupalgeddon2 CVE-2018-7600, PHP filter module RCE |
| 09-10 | Tomcat: manager WAR upload, CVE-2019-0232 CGI, Ghostcat |
| 11-12 | Jenkins: script console Groovy RCE |
| 13-14 | Splunk: malicious app upload, Free mode REST API RCE |
| 15 | PRTG: CVE-2018-9276 cmd injection → SYSTEM |
| 16 | osTicket: email harvesting, closed ticket data extraction |
| 17-18 | GitLab: CVE-2021-22205 ExifTool RCE, self-registration bypass |
| 19-20 | Shellshock CVE-2014-6271, Tomcat CGI CVE-2019-0232 |
| 21-24 | ColdFusion traversal/upload, IIS Tilde 8.3, LDAP injection |
| 25-29 | Mass assignment, thick clients, WebLogic CVE-2020-14882 |
| 30-33 | Nagios XI, vCenter, skills assessments |

### Linux Privilege Escalation ✅ (29 guides)
| Guide | Description |
|-------|-------------|
| 00-EXAM_CHEATSHEET.md | Full privesc priority checklist — sudo→SUID→cron→creds→kernel |
| 01-04 | Enumeration: environment, services/internals, credential hunting |
| 05-07 | Path abuse, wildcard abuse, restricted shell escape |
| 08-09 | SUID/SGID + GTFOBins, sudo rights abuse |
| 10-11 | Privileged groups (docker/lxd/disk/adm), capabilities |
| 12-13 | Vulnerable services (Screen 4.5.0), cron job abuse |
| 14-16 | Containers: LXC/LXD, Docker, Kubernetes |
| 17-18 | Logrotate, misc techniques (NFS, tmux hijacking) |
| 19 | Kernel exploits (OverlayFS, Dirty COW) |
| 20-22 | Shared libraries (LD_PRELOAD, RUNPATH, Python hijacking) |
| 23-24 | Sudo CVEs (14287, Baron Samedit), Polkit/PwnKit |
| 25-26 | Dirty Pipe CVE-2022-0847, Netfilter CVEs |
| 27 | Linux hardening (defensive reference) |
| 28 | Skills assessment (5-flag chain) |

### Windows Privilege Escalation ✅ (34 guides)
| Guide | Description |
|-------|-------------|
| 00-EXAM_CHEATSHEET.md | Full privesc priority checklist — privileges→groups→services→creds→kernel |
| 01-06 | Enumeration: situational awareness, initial enum, privileges overview, process communication |
| 07-09 | Token privileges: SeImpersonate/Potato, SeDebug/Mimikatz, SeTakeOwnership |
| 10-15 | Groups: Backup Operators, Event Log Readers, DnsAdmins, Hyper-V, Print/Server Operators |
| 16 | UAC bypass techniques |
| 17-20 | Service attacks: weak permissions, kernel exploits, vulnerable services, DLL injection |
| 21-23 | Credential hunting: config files, other files, further credential theft |
| 24 | Citrix breakout |
| 25 | Interacting with users — SCF file attacks, Responder hash capture |
| 26 | Pillaging — mRemoteNG, Firefox cookies, SAM/SYSTEM dump, pass-the-hash |
| 27 | Miscellaneous — LOLBAS, AlwaysInstallElevated, CVE-2019-1388, user descriptions |
| 28-30 | Legacy OS: Server 2008 + Windows 7 case studies, MS16-032 exploitation |
| 32-33 | Skills Assessments I & II (full attack chains) |

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
| Login Brute Force | Hydra, Medusa, ffuf web logins, wordlist crafting, custom rules | Login Brute Forcing ✅ |
| SQL Injection | UNION extraction, auth bypass, INFORMATION_SCHEMA enum, INTO OUTFILE web shells | SQL Injection ✅ |
| SQLMap Automation | All injection types, --tamper bypass, --file-read/write, --os-shell | SQLMap Essentials ✅ |
| XSS Exploitation | Stored / Reflected / DOM-based, cookie theft, phishing form injection, blind XSS | XSS ✅ |
| File Inclusion | LFI/RFI path traversal, PHP wrappers/filters, log poisoning, RCE via upload+LFI | File Inclusion ✅ |
| File Upload Attacks | Validation bypass (client/blacklist/whitelist/type), magic bytes, metadata injection | File Upload ✅ |
| Command Injection | Operator injection, space/char/command filter bypass, blind injection, obfuscation | Cmd Injection ✅ |
| HTTP Verb Tampering | Auth bypass via GET/POST/HEAD/PUT method switching | Web Attacks ✅ |
| IDOR | Mass enumeration, encoded reference bypass, IDOR in APIs, chaining IDORs | Web Attacks ✅ |
| XXE Injection | Local file read, SSRF via XXE, blind OOB exfiltration via DNS | Web Attacks ✅ |
| Application Attacks | WordPress/Joomla/Drupal/Tomcat/Jenkins/Splunk/PRTG/osTicket/GitLab/ColdFusion/WebLogic/Nagios | Common Apps ✅ |
| Linux Privilege Escalation | Sudo/SUID/cron/capabilities/groups, LD_PRELOAD, Python hijacking, kernel CVEs, containers | Linux PrivEsc ✅ |
| Windows Privilege Escalation | SeImpersonate/Potato, SeDebug/LSASS, SeBackup/NTDS.dit, AlwaysInstallElevated, kernel CVEs, credential hunting | Win PrivEsc ✅ |

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
- [Login Brute Forcing Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Login_Brute_Forcing/00-EXAM_CHEATSHEET.md)
- [SQL Injection Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/SQL_Injection_Fundamentals/00-EXAM_CHEATSHEET.md)
- [SQLMap Essentials Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/SQLMap_Essentials/00-EXAM_CHEATSHEET.md)
- [XSS Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Cross_Site_Scripting/00-EXAM_CHEATSHEET.md)
- [File Inclusion Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/File_Inclusion/00-EXAM_CHEATSHEET.md)
- [File Upload Attacks Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/File_Upload_Attacks/00-EXAM_CHEATSHEET.md)
- [Command Injections Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Command_Injections/00-EXAM_CHEATSHEET.md)
- [Web Attacks Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Web_Attacks/00-EXAM_CHEATSHEET.md)
- [Attacking Common Applications Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Attacking_Common_Applications/00-EXAM_CHEATSHEET.md)
- [Linux Privilege Escalation Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Linux_Privilege_Escalation/00-EXAM_CHEATSHEET.md)
- [Windows Privilege Escalation Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Windows_Privilege_Escalation/00-EXAM_CHEATSHEET.md)
- [Documentation & Reporting Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Documentation_and_Reporting/00-EXAM_CHEATSHEET.md)

---

Last Updated: July 26, 2026
