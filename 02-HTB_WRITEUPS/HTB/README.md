# CPTS Progress Tracking

**Start Date:** January 22, 2026  
**Target Exam:** May 20, 2026  
**Current Date:** April 3, 2026

---

## Exam Strategy

⚠️ **Important:** The CPTS exam tests knowledge from **Academy modules**, NOT box-solving ability. Labs/boxes are supplementary practice to reinforce module concepts.

**Priority:**
1. **Academy Modules** — Primary focus (exam content comes from here)
2. **Module Labs** — Skill assessments within modules
3. **HTB Boxes** — Supplementary practice (evening/weekend)

---

## Total Hours

| Metric | Value |
|--------|-------|
| **Current Hours** | 210 |
| **Target Hours** | 680 |
| **Remaining** | 470 |
| **Exam Date** | May 20, 2026 |

```
Progress: ████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 31%
```

---

## Academy Module Progress (Primary Focus)

| Module | Status | Sections | Labs |
|--------|--------|----------|------|
| Network Enumeration with Nmap | ✅ Complete | 7/7 | 3/3 (E/M/H) |
| Footprinting | ✅ Complete | All | — |
| Information Gathering - Web | ✅ Complete | All | — |
| Vulnerability Assessment | ✅ Complete | All | — |
| File Transfers | ✅ Complete | All | — |
| Shells & Payloads | 🔄 In Progress | 13/17 | — |
| Using the Metasploit Framework | ⬚ Not Started | — | — |
| Password Attacks | ⬚ Not Started | — | — |
| Attacking Common Services | ⬚ Not Started | — | — |
| Pivoting, Tunneling, Port Forwarding | ⬚ Not Started | — | — |
| Active Directory Enumeration & Attacks | ⬚ Not Started | — | — |
| Using Web Proxies | ⬚ Not Started | — | — |
| Attacking Web Applications with FFuF | ⬚ Not Started | — | — |
| Login Brute Forcing | ⬚ Not Started | — | — |
| SQL Injection Fundamentals | ⬚ Not Started | — | — |
| SQLMap Essentials | ⬚ Not Started | — | — |
| Cross-Site Scripting (XSS) | ⬚ Not Started | — | — |
| File Inclusion | ⬚ Not Started | — | — |
| File Upload Attacks | ⬚ Not Started | — | — |
| Command Injections | ⬚ Not Started | — | — |
| Web Attacks | ⬚ Not Started | — | — |
| Attacking Common Applications | ⬚ Not Started | — | — |
| Linux Privilege Escalation | ⬚ Not Started | — | — |
| Windows Privilege Escalation | ⬚ Not Started | — | — |
| Documentation & Reporting | ⬚ Not Started | — | — |
| Attacking Enterprise Networks | ⬚ Not Started | — | — |

---

## Current Module: Shells & Payloads (13/17 Sections)

| # | Section | Status | Key Concepts |
|---|---------|--------|--------------|
| 1 | Introduction | ✅ | Module overview |
| 2 | Engagement Preparation | ✅ | Shell selection, environment prep |
| 3 | Anatomy of a Shell | ✅ | How shells work |
| 4 | Bind Shells | ✅ | Target listens, attacker connects |
| 5 | Reverse Shells | ✅ | Attacker listens, target connects back |
| 6 | Introduction to Payloads | ✅ | Payload types and delivery |
| 7 | Automating Payloads with Metasploit | ✅ | MSF payload automation |
| 8 | Crafting Payloads with MSFvenom | ✅ | Custom payload generation |
| 9 | Infiltrating Windows | ✅ | Windows-specific attacks, EternalBlue |
| 10 | Spawning Interactive Shells | ✅ | TTY upgrade, escape methods (Perl, AWK, VIM) |
| 11 | Introduction to Web Shells | ✅ | Browser-based shell access |
| 12 | Laudanum Web Shells | ✅ | ASPX/PHP shells, allowedIps config |
| 13 | Antak Webshell | ✅ | Nishang PowerShell web shell |
| 14 | PHP Web Shells | ⬚ | — |
| 15 | Detection & Prevention | ⬚ | — |
| 16 | Skills Assessment | ⬚ | — |
| 17 | Summary | ⬚ | — |

---

## Supplementary Box Practice

| Metric | Completed |
|--------|-----------|
| Very Easy | 19 |
| Easy | 3 |
| Medium | 0 |
| Hard/AD | 0 |
| **Total** | **22** |

*Boxes reinforce module concepts but are not the exam focus.*

---

## Completed Modules Detail

### Network Enumeration with Nmap ✅

| # | Section | Concepts |
|---|---------|----------|
| 1 | Host Discovery | Network range scans, IP lists, ICMP/ARP analysis |
| 2 | Host & Port Scanning | TCP states, SYN/Connect/UDP scans, filtered port analysis |
| 3 | Saving & Converting Results | Output formats (-oN, -oG, -oX, -oA), xsltproc HTML conversion |
| 4 | Service Enumeration | Version detection (-sV), banner grabbing, tcpdump packet analysis |
| 5 | NSE Scripts | 14 categories, WordPress enumeration, vulnerability scanning |
| 6 | Scanning Performance | Timing templates (T0-T5), timeout tuning, packet rate optimization |
| 7 | Firewall/IDS Evasion | SYN vs ACK scans, decoy scanning, source IP spoofing, DNS port 53 abuse |

**Skill Assessment Labs:**

| Lab | Difficulty | Technique |
|-----|-----------|-----------|
| Easy | Easy | Standard service enumeration |
| UDP DNS Enumeration | Medium | `-sU -sV` triggered DNSVersionBindReq on port 53 |
| Filtered Port Bypass | Hard | `-g 53` DNS source port abuse + ncat `--source-port 53` |

### Footprinting ✅

| # | Section | Concepts |
|---|---------|----------|
| 1 | Enumeration Principles | What we see vs don't see, active vs passive recon |
| 2 | Enumeration Methodology | Six-layer framework (Internet → OS Setup) |
| 3 | Domain Information | SSL certs, crt.sh, DNS records, Shodan |
| 4 | FTP | Ports 20/21, active vs passive, anonymous access, vsFTPd config |
| 5 | SMB | SMB/CIFS, Samba, smbclient, rpcclient, enum4linux-ng |
| 6+ | NFS, DNS, SMTP, IMAP/POP3, SNMP, MySQL, MSSQL, Oracle, IPMI | Service-specific enumeration |

### Information Gathering - Web ✅

WHOIS, DNS enumeration, subdomain discovery, virtual hosts, web fingerprinting

### Vulnerability Assessment ✅

Nessus configuration, vulnerability scanning, assessment methodologies

### File Transfers ✅

Linux/Windows transfers, HTTP, SMB, FTP, base64, PowerShell methods

---

## Skills Developed

| Category | Skills | Source Module |
|----------|--------|---------------|
| Reconnaissance | Nmap mastery, service enumeration, banner grabbing | Nmap ✅ |
| Firewall Evasion | Source port spoofing, DNS trust abuse, filtered port bypass | Nmap ✅ |
| Service Enumeration | FTP, SMB, NFS, DNS, SMTP, databases, SNMP, IPMI | Footprinting ✅ |
| Web Recon | WHOIS, subdomain discovery, vhost enumeration, fingerprinting | Info Gathering ✅ |
| Vulnerability Assessment | Nessus, scanning methodologies, risk assessment | Vuln Assessment ✅ |
| File Transfers | HTTP, SMB, FTP, base64, PowerShell, Linux/Windows methods | File Transfers ✅ |
| Shells & Payloads | Bind/reverse shells, MSFvenom, web shells, TTY upgrade | Shells & Payloads 🔄 |
| Windows Exploitation | EternalBlue (MS17-010), ASPX shells, PowerShell | Shells & Payloads 🔄 |
| Web Exploitation | SQLi, directory brute-forcing, plugin enumeration | Upcoming |
| Privilege Escalation | Linux/Windows privesc techniques | Upcoming |
| Active Directory | Kerberos, Bloodhound, lateral movement | Upcoming |

---

## Post-CPTS Goals

- OSCP course access setup (June 1)
- PWK labs enrollment (June 15)
- OSCP intensive begins (July 1)
