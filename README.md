# Offensive Security Development

Documenting my path through security certifications and hands-on penetration testing in 2026.

| Certification | Status | Target |
|---------------|--------|--------|
| Security+ | ✅ Passed (768/900, 85.3%) | Jan 2026 |
| CPTS | 📖 In Progress | May 2026 |
| CRTO | Planned | After CPTS |
| CRTE | Planned | After CRTO |
| CARTP | Planned | After CRTE |

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
|   |   |-- Information_Gathering_Web_Edition/  8 Web recon guides
|   |   |-- MASTER_ENUMERATION_CHEATSHEET.md
|   |-- README.md                  CPTS hours and progress tracker
|
|-- 00-archived/                   Old materials
```

---

## Current Status (March 17, 2026)

| Metric | Status |
|--------|--------|
| Machines Completed | 22 (19 Very Easy, 3 Easy) |
| Academy Modules | 4 complete (Nmap, Footprinting, Information Gathering - Web Edition, Vulnerability Assessment) |
| Writeups Published | 22 |
| Reference Guides | 50+ |
| Target Exam | May 20, 2026 |

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

## Footprinting Module -- Complete

| Section | Guide | Topics |
|---------|-------|--------|
| 1 | Enumeration_Principles.md | What we see vs don't see, active vs passive recon |
| 2 | Enumeration_Methodology.md | Six-layer framework (Internet → OS Setup) |
| 3 | Domain_Information.md | SSL certs, crt.sh, DNS records, Shodan |
| 4 | FTP.md | Ports 20/21, active vs passive, anonymous access, vsFTPd |
| 5 | SMB.md | SMB/CIFS, Samba, smbclient, rpcclient, enum4linux-ng, CrackMapExec |

---

## Vulnerability Assessment Module -- Complete (All Labs Passed)

16 sections covering comprehensive vulnerability assessment methodology from the CPTS Academy path.

| Section | Guide | Topics |
|---------|-------|--------|
| 1 | 01-Security_Assessments.md | Assessment types, methodologies, frameworks |
| 2 | 02-Vulnerability_Assessment_Methodology.md | Systematic assessment approach, planning |
| 3 | 03-Assessment_Standards.md | Industry standards, compliance frameworks |
| 4 | 04-CVSS.md | Common Vulnerability Scoring System, risk calculation |
| 5 | 05-CVE_and_OVAL.md | Common Vulnerabilities and Exposures, OVAL definitions |
| 6 | 06-Vulnerability_Scanning_Overview.md | Scanning platforms comparison, tool selection |
| 7 | 07-Getting_Started_with_Nessus.md | Nessus installation, configuration, first scan |
| 8 | 08-Nessus_Scan_Configuration.md | Scan templates, policy configuration, advanced settings |
| 9 | 09-Nessus_Advanced_Settings_and_Features.md | Authenticated scanning, custom plugins |
| 10 | 10-Working_with_Nessus_Scan_Output.md | Result analysis, filtering, prioritization |
| 11 | 11-Nessus_Scanning_Issues_and_Network_Impact.md | Performance monitoring, network impact measurement |
| 12 | 12-Nessus_Skills_Assessment.md | Practical assessment, hands-on evaluation |
| 13 | 13-Getting_Started_with_OpenVAS.md | OpenVAS setup, interface, initial configuration |
| 14 | 14-OpenVAS_Scan_Configuration_and_Execution.md | Scan policies, NVT database, execution |
| 15 | 15-Exporting_OpenVAS_Scan_Results.md | Report generation, export formats, analysis |
| 16 | 16-Vulnerability_Assessment_Reporting.md | Professional reporting, risk communication |

---

## Information Gathering - Web Edition Module -- Complete (All Labs Passed)

19 sections covering comprehensive web reconnaissance from the CPTS Academy path.

| Section | Guide | Topics |
|---------|-------|--------|
| 1 | 01-Introduction.md | Web recon overview, OSINT fundamentals |
| 2 | 02-WHOIS.md | WHOIS protocol, registrar data, privacy services |
| 3 | 03-Utilising_WHOIS.md | Practical WHOIS queries, data analysis |
| 4 | 04-DNS.md | DNS fundamentals, record types, zone files |
| 5 | 05-Digging_DNS.md | DNS recon tools, dig command reference, output analysis |
| 6 | 06-Subdomains.md | Subdomain enumeration, active vs passive techniques |
| 7 | 07-Subdomain_Bruteforcing.md | Brute-force techniques, dnsenum, wordlists |
| 8 | 08-DNS_Zone_Transfers.md | AXFR exploitation, zone transfer vulnerability, dig axfr |
| 9 | 09-Virtual_Hosts.md | Vhost discovery, HTTP headers, fuzzing techniques |
| 10 | 10-Certificate_Transparency.md | CT logs, certificate analysis, domain discovery |
| 11 | 11-Fingerprinting.md | Technology stack identification, whatweb, wappalyzer |
| 12 | 12-Crawling.md | Automated website mapping, link extraction, spider tools |
| 13 | 13-robots_txt.md | Robots.txt analysis, disallowed paths, hidden directories |
| 14 | 14-Well_Known_URIs.md | /.well-known/ paths, security.txt, standard endpoints |
| 15 | 15-Creepy_Crawlies.md | Advanced crawling techniques, JavaScript parsing |
| 16 | 16-Search_Engine_Discovery.md | Google dorking, search operators, OSINT via search |
| 17 | 17-Web_Archives.md | Wayback Machine, historical data, archived content |
| 18 | 18-Automating_Recon.md | Automation frameworks, tool chaining, scripted recon |
| 19 | 19-Skills_Assessment.md | Comprehensive practical assessment |

---

## Information Gathering - Web Edition (Complete)

| Section | Guide | Topics |
|---------|-------|--------|
| 1 | 01-Introduction.md | Web recon overview, OSINT fundamentals |
| 2 | 02-WHOIS.md | WHOIS protocol, registrar data, privacy services |
| 3 | 03-Utilising_WHOIS.md | Practical WHOIS queries, data analysis |
| 4 | 04-DNS.md | DNS fundamentals, record types, zone files |
| 5 | 05-Digging_DNS.md | DNS recon tools, dig command reference, output analysis |
| 6 | 06-Subdomains.md | Subdomain enumeration, active vs passive techniques |
| 7 | 07-Subdomain_Bruteforcing.md | Brute-force techniques, dnsenum, wordlists |
| 8 | 08-DNS_Zone_Transfers.md | AXFR exploitation, zone transfer vulnerability, dig axfr |

---

## Reference Guides

### Foundation

| Guide | Description |
|-------|-------------|
| Enumeration_Process.md | Systematic 5-phase enumeration |
| Service_Scanning_Enumeration.md | Nmap, FTP, SMB, SNMP service enumeration |
| Web_Enumeration.md | HTTP/HTTPS, directory brute force, fingerprinting |
| File_Transfer.md | Comprehensive file transfer methods (wget/curl, SCP, Base64, integrity validation) |
| Privilege_Escalation.md | Linux and Windows privilege escalation |
| Public_Exploits.md | Finding and using public CVE exploits |
| Types_of_Shells.md | Comprehensive shell type guide |
| MASTER_ENUMERATION_CHEATSHEET.md | Full enumeration flowchart |

### Network Enumeration With Nmap

| Guide | Description |
|-------|-------------|
| Host_Discovery.md | Network range scans, IP lists, ICMP/ARP |
| Host_and_Port_Scanning.md | TCP states, SYN/Connect/UDP scans, filtered ports |
| Saving_and_Converting_Results.md | Output formats (-oN, -oG, -oX), xsltproc |
| Service_Enumeration.md | Version detection (-sV), banner grabbing, tcpdump |
| NSE_Scripts.md | 14 categories, WordPress enum, vuln scanning |
| Scanning_Performance.md | Timing templates (T0-T5), timeout tuning, packet rates |
| Firewall_IDS_Evasion.md | ACK scans, decoys, source spoofing, DNS port 53 abuse |

### Footprinting

| Guide | Description |
|-------|-------------|
| Enumeration_Principles.md | What we see vs don't see, active vs passive recon |
| Enumeration_Methodology.md | Six-layer framework (Internet → OS Setup) |
| Domain_Information.md | SSL certs, crt.sh, DNS records, Shodan |
| FTP.md | Ports 20/21, active vs passive, anonymous access, vsFTPd |
| SMB.md | SMB/CIFS, Samba, smbclient, rpcclient, enum4linux-ng, CrackMapExec |

### Information Gathering - Web Edition

| Guide | Description |
|-------|-------------|
| 01-Introduction.md | Web recon overview, OSINT fundamentals |
| 02-WHOIS.md | WHOIS protocol, registrar data, privacy services |
| 03-Utilising_WHOIS.md | Practical WHOIS queries, data analysis |
| 04-DNS.md | DNS fundamentals, record types, zone files |
| 05-Digging_DNS.md | DNS recon tools, dig command reference, output analysis |
| 06-Subdomains.md | Subdomain enumeration, active vs passive techniques |
| 07-Subdomain_Bruteforcing.md | Brute-force techniques, dnsenum, wordlists |
| 08-DNS_Zone_Transfers.md | AXFR exploitation, zone transfer vulnerability, dig axfr |
| 09-Virtual_Hosts.md | Vhost discovery, HTTP headers, fuzzing techniques |
| 10-Certificate_Transparency.md | CT logs, certificate analysis, domain discovery |
| 11-Fingerprinting.md | Technology stack identification, whatweb, wappalyzer |
| 12-Crawling.md | Automated website mapping, link extraction, spider tools |
| 13-robots_txt.md | Robots.txt analysis, disallowed paths, hidden directories |
| 14-Well_Known_URIs.md | /.well-known/ paths, security.txt, standard endpoints |
| 15-Creepy_Crawlies.md | Advanced crawling techniques, JavaScript parsing |
| 16-Search_Engine_Discovery.md | Google dorking, search operators, OSINT via search |
| 17-Web_Archives.md | Wayback Machine, historical data, archived content |
| 18-Automating_Recon.md | Automation frameworks, tool chaining, scripted recon |
| 19-Skills_Assessment.md | Comprehensive practical assessment |

### Vulnerability Assessment

| Guide | Description |
|-------|-------------|
| 01-Security_Assessments.md | Assessment types, methodologies, frameworks |
| 02-Vulnerability_Assessment_Methodology.md | Systematic assessment approach, planning |
| 03-Assessment_Standards.md | Industry standards, compliance frameworks |
| 04-CVSS.md | Common Vulnerability Scoring System, risk calculation |
| 05-CVE_and_OVAL.md | Common Vulnerabilities and Exposures, OVAL definitions |
| 06-Vulnerability_Scanning_Overview.md | Scanning platforms comparison, tool selection |
| 07-Getting_Started_with_Nessus.md | Nessus installation, configuration, first scan |
| 08-Nessus_Scan_Configuration.md | Scan templates, policy configuration, advanced settings |
| 09-Nessus_Advanced_Settings_and_Features.md | Authenticated scanning, custom plugins |
| 10-Working_with_Nessus_Scan_Output.md | Result analysis, filtering, prioritization |
| 11-Nessus_Scanning_Issues_and_Network_Impact.md | Performance monitoring, network impact measurement |
| 12-Nessus_Skills_Assessment.md | Practical assessment, hands-on evaluation |
| 13-Getting_Started_with_OpenVAS.md | OpenVAS setup, interface, initial configuration |
| 14-OpenVAS_Scan_Configuration_and_Execution.md | Scan policies, NVT database, execution |
| 15-Exporting_OpenVAS_Scan_Results.md | Report generation, export formats, analysis |
| 16-Vulnerability_Assessment_Reporting.md | Professional reporting, risk communication |

**New Additions (March 2026):**
- **Complete Vulnerability Assessment Module**: 16 comprehensive sections covering Nessus Professional, OpenVAS, CVSS scoring, CVE research, and professional reporting
- **Extensive File Transfer Guide**: 400+ lines covering wget/curl, SCP, Base64 encoding, integrity validation with MD5 hashes, troubleshooting, and practical CTF examples
- **Web Reconnaissance Mastery**: Complete Information Gathering - Web Edition with 19 sections covering WHOIS, DNS, subdomains, virtual hosts, certificate transparency, crawling, automation

---

## Tools

Nmap, Gobuster, FFuF, Nikto, SMBclient, enum4linux, Hydra, Responder, Impacket (mssqlclient.py, psexec.py), LinPEAS, WinPEAS, Netcat, Ncat, Metasploit, WhatWeb, SearchSploit, tcpdump

---

## Links

- [CPTS Progress Tracker](02-HTB_WRITEUPS/HTB/README.md)
- [Master Enumeration Cheatsheet](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/MASTER_ENUMERATION_CHEATSHEET.md)
- [Nmap Guides](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Network_Enumeration_With_Nmap/)
- [Footprinting Guides](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Footprinting/)
- [Information Gathering Guides](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Information_Gathering_Web_Edition/)
- [Vulnerability Assessment Guides](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Vulnerability_Assessment/)
- [Privilege Escalation Guide](02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Foundation/Privilege_Escalation.md)

---

Last Updated: March 17, 2026

## Recent Progress Summary (March 2026)

**🎯 Major Achievements:**
- ✅ **Completed Vulnerability Assessment Module** (16 sections + skills assessment covering Nessus, OpenVAS, CVSS, reporting)
- ✅ **Completed Information Gathering - Web Edition** (19 sections + skills assessment)
- ✅ **Completed Footprinting Module** (5 sections covering enumeration principles, methodology, domains, FTP, SMB)
- 📚 **Enhanced File Transfer Mastery** - Built comprehensive 400+ line guide covering all transfer methods
- 🔍 **Web Reconnaissance Expertise** - Mastered WHOIS, DNS enumeration, subdomain discovery, virtual host identification, certificate transparency, web crawling, and automation

**📊 Current CPTS Progress:**
- **4/X Academy Modules Complete** (Network Enumeration with Nmap, Footprinting, Information Gathering - Web Edition, Vulnerability Assessment)
- **50+ Reference Guides** created for rapid knowledge reference
- **22 HTB Boxes Completed** (19 Very Easy, 3 Easy)
- **Target Exam Date:** May 20, 2026 (2 months remaining)

**🛠️ New Technical Skills Acquired:**
- **Vulnerability Assessment Mastery**: Nessus Professional, OpenVAS scanning, authenticated vs unauthenticated scans
- **Risk Analysis**: CVSS scoring, CVE research, OVAL definitions, vulnerability prioritization
- **Professional Reporting**: Vulnerability assessment reports, risk communication, remediation guidance
- DNS zone transfer exploitation (AXFR)
- Certificate transparency log analysis
- Advanced subdomain enumeration techniques
- Virtual host discovery and fuzzing
- Automated web reconnaissance workflows
- File integrity validation (MD5 hashing)
- Multi-method file transfer strategies
