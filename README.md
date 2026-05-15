# Offensive Security Development

Documenting my path through security certifications and hands-on penetration testing in 2026.

| Certification | Status | Target |
|---------------|--------|--------|
| Security+ | ✅ Passed (768/900, 85.3%) | Jan 2026 |
| CPTS | 📖 In Progress (~80%, 23/28 modules) | June 2026 |
| CRTO | Planned | After CPTS |
| CRTE | Planned | After CRTO |
| CARTP | Planned | After CRTE |

---

## Current Status (May 14, 2026)

```
CPTS Learning Pathway: ████████████████████████████████░░░░░░░░ ~80%
```

| Metric | Status |
|--------|--------|
| Machines Completed | 22 (19 Very Easy, 3 Easy) |
| Academy Modules Complete | 23 / 28 |
| Academy Module In Progress | Attacking Common Applications (17/33 sections) |
| Reference Guides | 370+ |
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
| Login Brute Forcing | ✅ Complete (13/13) |
| SQL Injection Fundamentals | ✅ Complete (17/17) |
| SQLMap Essentials | ✅ Complete (11/11) |
| Cross-Site Scripting (XSS) | ✅ Complete (10/10) |
| File Inclusion | ✅ Complete (11/11) |
| File Upload Attacks | ✅ Complete (11/11) |
| Command Injections | ✅ Complete (12/12) |
| Web Attacks | ✅ Complete (18/18) |
| Attacking Common Applications | 🔄 In Progress (17/33) |
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
|   |   |-- Login_Brute_Forcing/                       ← 13 guides (complete)
|   |   |-- SQL_Injection_Fundamentals/                ← 17 guides (complete)
|   |   |-- SQLMap_Essentials/                         ← 11 guides (complete)
|   |   |-- Cross_Site_Scripting/                      ← 10 guides (complete)
|   |   |-- File_Inclusion/                            ← 11 guides (complete)
|   |   |-- File_Upload_Attacks/                       ← 11 guides (complete)
|   |   |-- Command_Injections/                        ← 12 guides (complete)
|   |   |-- Web_Attacks/                               ← 18 guides (complete)
|   |   |-- Attacking_Common_Applications/             ← 17 guides (in progress)
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

### Attacking Common Applications 🔄 (17/33 guides)
| Guide | Description |
|-------|-------------|
| 00-EXAM_CHEATSHEET.md | Quick-reference for all covered applications |
| 01-02 | Discovery & enumeration methodology, application fingerprinting |
| 03-04 | WordPress: enumeration (WPScan, manual), exploitation (plugin upload, CVEs) |
| 05-06 | Joomla: discovery, exploitation (template editor RCE, CVE-2019-10945) |
| 07-08 | Drupal: discovery, exploitation (Drupalgeddon2 CVE-2018-7600, Drupa queen CVE-2019-6340) |
| 09-10 | Tomcat: discovery, exploitation (manager WAR upload, CVE-2019-0232 CGI) |
| 11-12 | Jenkins: discovery, exploitation (script console RCE, Groovy reverse shell) |
| 13-14 | Splunk: discovery, exploitation (malicious app upload, Free mode RCE via REST API) |
| 15 | PRTG: discovery + CVE-2018-9276 authenticated command injection → SYSTEM |
| 16 | osTicket: email harvesting, credential reuse, closed ticket data extraction |
| 17 | GitLab: version fingerprint, unauthenticated/authenticated enumeration, CVEs |

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
| Application Attacks | WordPress/Joomla/Drupal/Tomcat/Jenkins/Splunk/PRTG/osTicket/GitLab | Common Apps 🔄 |
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
- [Login Brute Forcing Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Login_Brute_Forcing/00-EXAM_CHEATSHEET.md)
- [SQL Injection Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/SQL_Injection_Fundamentals/00-EXAM_CHEATSHEET.md)
- [SQLMap Essentials Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/SQLMap_Essentials/00-EXAM_CHEATSHEET.md)
- [XSS Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Cross_Site_Scripting/00-EXAM_CHEATSHEET.md)
- [File Inclusion Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/File_Inclusion/00-EXAM_CHEATSHEET.md)
- [File Upload Attacks Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/File_Upload_Attacks/00-EXAM_CHEATSHEET.md)
- [Command Injections Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Command_Injections/00-EXAM_CHEATSHEET.md)
- [Web Attacks Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Web_Attacks/00-EXAM_CHEATSHEET.md)
- [Attacking Common Applications Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Attacking_Common_Applications/00-EXAM_CHEATSHEET.md)

---

Last Updated: May 14, 2026
