# Offensive Security Development

Documenting my path through security certifications and hands-on penetration testing in 2026.

| Certification | Status | Target |
|---------------|--------|--------|
| Security+ | ✅ Passed (768/900, 85.3%) | Jan 2026 |
| CPTS | 📖 In Progress (46.1%) | June 2026 |
| CRTO | Planned | After CPTS |
| CRTE | Planned | After CRTO |
| CARTP | Planned | After CRTE |

---

## Current Status (May 9, 2026)

```
CPTS Learning Pathway: ██████████████████░░░░░░░░░░░░░░░░░░░░░░ 46.1%
```

| Metric | Status |
|--------|--------|
| Machines Completed | 22 (19 Very Easy, 3 Easy) |
| Academy Modules Complete | 10 / 26 |
| Academy Module In Progress | Active Directory Enumeration & Attacks (16/36 sections) |
| Reference Guides | 200+ |
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
| Active Directory Enumeration & Attacks | 🔄 In Progress (16/36) |
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
|   |   |-- Active_Directory_Enumeration_and_Attacks/
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
| 01-Introduction.md | Web recon overview |
| 02-WHOIS.md | Registrar data, privacy services |
| 03-Utilising_WHOIS.md | Practical WHOIS analysis |
| 04-DNS.md | DNS fundamentals, record types |
| 05-Digging_DNS.md | dig command reference |
| 06-Subdomains.md | Active vs passive enumeration |
| 07-Subdomain_Bruteforcing.md | dnsenum, wordlists |
| 08-DNS_Zone_Transfers.md | AXFR exploitation |
| 09-Virtual_Hosts.md | Vhost discovery, ffuf |
| 10-Certificate_Transparency.md | CT log analysis |
| 11-Fingerprinting.md | whatweb, wappalyzer |
| 12-Crawling.md | Spider tools, link extraction |
| 13-robots_txt.md | Hidden directories |
| 14-Well_Known_URIs.md | /.well-known/ paths |
| 15-Creepy_Crawlies.md | Advanced crawling |
| 16-Search_Engine_Discovery.md | Google dorking |
| 17-Web_Archives.md | Wayback Machine |
| 18-Automating_Recon.md | Tool chaining, scripted recon |
| 19-Skills_Assessment.md | Practical assessment |

### File Transfers
| Guide | Description |
|-------|-------------|
| 02-Windows_File_Transfer_Methods_Downloads.md | PowerShell, certutil, BITS |
| 03-Linux_File_Transfer_Methods.md | wget, curl, SCP, base64 |
| 04-Transferring_Files_with_Code.md | Python, PHP, Ruby servers |
| 05-Miscellaneous_File_Transfer_Methods.md | Netcat, SMB, FTP |
| 06-Protected_File_Transfers.md | Encrypted transfers |
| 07-Catching_Files_over_HTTP_S.md | Nginx, Apache upload handlers |
| 08-Living_off_the_Land.md | LOLBins for transfer |
| 09-Detection.md | AV/EDR evasion considerations |
| 10-Evading_Detection.md | Encoding, obfuscation |

### Shells & Payloads
| Guide | Description |
|-------|-------------|
| 04-Bind_Shells.md | Target listens, attacker connects |
| 05-Reverse_Shells.md | Attacker listens, target connects back |
| 06-Introduction_to_Payloads.md | Payload types and delivery |
| 07-Automating_Payloads_with_Metasploit.md | MSF payload automation |
| 08-Crafting_Payloads_with_MSFvenom.md | Custom payload generation |
| 09-Infiltrating_Windows.md | EternalBlue, ASPX shells |
| 10-Spawning_Interactive_Shells.md | TTY upgrade, Perl/AWK/VIM escape |
| 11-Introduction_to_Web_Shells.md | Browser-based shell access |
| 12-Laudanum_Web_Shells.md | ASPX/PHP shells |
| 13-Antak_Webshell.md | Nishang PowerShell web shell |
| 14-PHP_Web_Shells.md | PHP shell variants |
| SKILLS_ASSESSMENT_WRITEUP.md | Skills assessment writeup |

### Using the Metasploit Framework
| Guide | Description |
|-------|-------------|
| 03-Introduction_to_MSFconsole.md | Console navigation, commands |
| 04-Modules.md | Module types, search, use |
| 05-Targets.md | Target selection |
| 06-Payloads.md | Staged vs stageless, encoders |
| 09-Plugins.md | Plugin ecosystem |
| 10-Sessions.md | Session management, backgrounding |
| 11-Meterpreter.md | Meterpreter commands, post-exploitation |
| 13-Introduction_to_MSFVenom.md | Payload crafting |
| 14-Firewall_and_IDS_IPS_Evasion.md | Encoding, obfuscation |

### Password Attacks
| Guide | Description |
|-------|-------------|
| 02-Introduction_to_Password_Cracking.md | Hash types, cracking methodology |
| 03-Introduction_to_John_The_Ripper.md | John rules, wordlists, formats |
| 04-Introduction_to_Hashcat.md | Hashcat modes, rules, masks |
| 05-Writing_Custom_Wordlists_and_Rules.md | CeWL, CUPP, custom rules |
| 10-Windows_Authentication_Process.md | NTLM, Kerberos, SAM, LSASS |
| 11-Attacking_SAM_SYSTEM_and_SECURITY.md | Registry hive extraction |
| 12-Attacking_LSASS.md | Mimikatz, task manager dump |
| 14-Attacking_Active_Directory_and_NTDS.dit.md | Volume shadow copy, secretsdump |
| 15-Credential_Hunting_in_Windows.md | LaZagne, registry, config files |
| 17-Credential_Hunting_in_Linux.md | SSH keys, bash history, config files |
| 20-Pass_the_Hash.md | PtH with Impacket, CrackMapExec |
| 21-Pass_the_Ticket_Windows.md | Kerberos ticket abuse |
| 22-Pass_the_Ticket_Linux.md | ccache files, keytab abuse |
| 23-Pass_the_Certificate.md | ADCS certificate abuse |

### Attacking Common Services
| Guide | Description |
|-------|-------------|
| 07-Attacking_SMB.md | Brute force, RCE, relay |
| 09-Attacking_SQL_Databases.md | SQLi, xp_cmdshell, UDF |
| 11-Attacking_RDP.md | Brute force, session hijacking |
| 13-Attacking_DNS.md | Zone transfer, cache poisoning |
| 15-Attacking_Email_Services.md | SMTP enum, open relay, phishing |
| 17-Skills_Assessment_Easy.md | Easy assessment writeup |
| 18-Skills_Assessment_Medium.md | Medium assessment writeup |
| 19-Skills_Assessment_Hard.md | Hard assessment writeup |

### Pivoting, Tunneling & Port Forwarding
| Guide | Description |
|-------|-------------|
| 03-Dynamic_Port_Forwarding_with_SSH_and_SOCKS_Tunneling.md | SSH -D, proxychains |
| 04-Remote_Reverse_Port_Forwarding_with_SSH.md | SSH -R |
| 05-Meterpreter_Tunneling_and_Port_Forwarding.md | MSF pivoting |
| 06-Socat_Redirection_with_a_Reverse_Shell.md | Socat relay |
| 08-SSH_for_Windows_plink.exe.md | Plink pivoting |
| 09-SSH_Pivoting_with_Sshuttle.md | Transparent VPN-over-SSH |
| 10-Web_Server_Pivoting_with_Rpivot.md | HTTP tunnel |
| 13-SOCKS5_Tunneling_with_Chisel.md | Chisel HTTP tunnel |
| 14-ICMP_Tunneling_with_SOCKS.md | ptunnel-ng |
| 15-RDP_and_SOCKS_Tunneling_with_SocksOverRDP.md | SocksOverRDP |
| 16-Skills_Assessment.md | Skills assessment writeup |

### Active Directory Enumeration & Attacks (In Progress — 16/36)
| Guide | Description |
|-------|-------------|
| 00-EXAM_CHEATSHEET.md | Full AD attack cheatsheet |
| 04-External_Recon_and_Enumeration_Principles.md | OSINT, ASN, breach data |
| 05-Initial_Enumeration_of_the_Domain.md | fping, kerbrute, tcpdump |
| 06-LLMNR_NBT-NS_Poisoning_Linux.md | Responder, NTLMv2 cracking |
| 07-LLMNR_NBT-NS_Poisoning_Windows.md | Inveigh |
| 08-Password_Spraying_Overview.md | Methodology, lockout awareness |
| 09-Enumerating_Password_Policy.md | rpcclient, enum4linux, LDAP |
| 10-Password_Spraying_Building_User_List.md | kerbrute, CME, LDAP, RPC |
| 11-Internal_Password_Spraying_Linux.md | kerbrute, CrackMapExec |
| 12-Internal_Password_Spraying_Windows.md | DomainPasswordSpray |
| 13-Enumerating_Security_Controls.md | Defender, AppLocker, LAPS |
| 14-Credentialed_Enumeration_Linux.md | CME, BloodHound, windapsearch |
| 15-Credentialed_Enumeration_Windows.md | PowerView, SharpHound, Snaffler |
| 16-Living_Off_the_Land.md | dsquery, net commands, PS history |

### Vulnerability Assessment
| Guide | Description |
|-------|-------------|
| 04-CVSS.md | CVSS scoring, risk calculation |
| 05-CVE_and_OVAL.md | CVE research, OVAL definitions |
| 07-Getting_Started_with_Nessus.md | Nessus setup, first scan |
| 08-Nessus_Scan_Configuration.md | Scan templates, advanced settings |
| 10-Working_with_Nessus_Scan_Output.md | Result analysis, prioritization |
| 13-Getting_Started_with_OpenVAS.md | OpenVAS setup, configuration |
| 14-OpenVAS_Scan_Configuration_and_Execution.md | Scan policies, NVT database |
| 16-Vulnerability_Assessment_Reporting.md | Professional reporting |

---

## Tools

Nmap, Gobuster, FFuF, Nikto, SMBclient, enum4linux, enum4linux-ng, Hydra, Responder, Inveigh, Impacket suite (psexec/wmiexec/secretsdump/GetNPUsers/GetUserSPNs), CrackMapExec/Netexec, BloodHound, SharpHound, PowerView, Mimikatz, Evil-WinRM, Chisel, Sshuttle, Socat, Proxychains, LinPEAS, WinPEAS, Netcat, Metasploit, MSFvenom, SQLmap, John the Ripper, Hashcat, Kerbrute, Certipy-AD, Snaffler, Windapsearch

---

## Links

- [CPTS Progress Tracker](02-HTB_WRITEUPS/HTB/README.md)
- [Master Enumeration Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Foundation/00-MASTER_ENUMERATION_CHEATSHEET.md)
- [AD Exam Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Active_Directory_Enumeration_and_Attacks/00-EXAM_CHEATSHEET.md)
- [Password Attacks Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Password_Attacks/00-EXAM_CHEATSHEET.md)
- [Pivoting Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Pivoting_Tunneling_and_Port_Forwarding/00-EXAM_CHEATSHEET.md)

---

Last Updated: May 9, 2026
