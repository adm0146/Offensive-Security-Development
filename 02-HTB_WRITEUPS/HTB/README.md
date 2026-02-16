# CPTS Progress Tracking

**Start Date:** January 22, 2026  
**Target Exam:** May 20, 2026  
**Current Date:** February 16, 2026

---

## Exam Strategy

⚠️ **Important:** The CPTS exam tests knowledge from **Academy modules**, NOT box-solving ability. Labs/boxes are supplementary practice to reinforce module concepts.

**Priority:**
1. **Academy Modules** — Primary focus (exam content comes from here)
2. **Module Labs** — Skill assessments within modules
3. **HTB Boxes** — Supplementary practice (evening/weekend)

---

## Total Hours

| Period | Hours | Target |
|--------|-------|--------|
| Week 1 (Jan 22-28) | 50 | 40 |
| Week 2 (Jan 29-Feb 4) | 38 | 40 |
| Week 3-4 (Feb 5-18) | 62 / 80 | 80 |
| Week 5-6 (Feb 19-Mar 4) | — | 80 |
| Week 7-8 (Mar 5-18) | — | 80 |
| Week 9-10 (Mar 19-Apr 1) | — | 80 |
| Week 11-12 (Apr 2-15) | — | 80 |
| Week 13-14 (Apr 16-29) | — | 80 |
| Week 15-16 (Apr 30-May 13) | — | 80 |
| Week 17 (May 14-20) | — | 40 |
| **Total** | **150 / 680** | **680** |

```
Progress: █████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 22%
```

---

## Academy Module Progress (Primary Focus)

| Module | Status | Sections | Labs |
|--------|--------|----------|------|
| Network Enumeration with Nmap | ✅ Complete | 7/7 | 3/3 (E/M/H) |
| Footprinting | 🔄 In Progress | 5/? | — |
| Information Gathering - Web | ⬚ Not Started | — | — |
| Vulnerability Assessment | ⬚ Not Started | — | — |
| File Transfers | ⬚ Not Started | — | — |
| Shells & Payloads | ⬚ Not Started | — | — |
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

## Weekly Plan

### Week 3-4 — Feb 5-18 | 62 hrs (in progress)

**Module Focus:** Footprinting (complete all sections + labs)

| Module | Status |
|--------|--------|
| **Footprinting** | 🔄 5 sections complete |

**Sections Completed:**

| # | Section | Concepts |
|---|---------|----------|
| 1 | Enumeration Principles | What we see vs don't see, active vs passive recon |
| 2 | Enumeration Methodology | Six-layer framework (Internet → OS Setup) |
| 3 | Domain Information | SSL certs, crt.sh, DNS records, Shodan |
| 4 | FTP | Ports 20/21, active vs passive, anonymous access, vsFTPd config |
| 5 | SMB | SMB/CIFS, Samba, smbclient, rpcclient, enum4linux-ng, CrackMapExec |

---

### Week 5-6 — Feb 19-Mar 4 | Upcoming

**Module Focus:** Complete Footprinting → Information Gathering - Web → File Transfers

---

### Week 7-8 — Mar 5-18 | Upcoming

**Module Focus:** Shells & Payloads → Using the Metasploit Framework → Password Attacks

---

### Week 9-10 — Mar 19-Apr 1 | Upcoming

**Module Focus:** Attacking Common Services → Pivoting/Tunneling → Linux Privilege Escalation

---

### Week 11-12 — Apr 2-15 | Upcoming

**Module Focus:** Windows Privilege Escalation → Active Directory Enumeration & Attacks

---

### Week 13-14 — Apr 16-29 | Upcoming

**Module Focus:** Web Attacks (SQLi, XSS, File Inclusion, Command Injection, File Upload)

---

### Week 15-16 — Apr 30-May 13 | Upcoming

**Module Focus:** Attacking Common Applications → Attacking Enterprise Networks → Documentation

---

### Week 17 — May 14-20 | Exam Week

**Focus:** Review weak modules, rest, CPTS exam

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

---

## Skills Developed

| Category | Skills | Source Module |
|----------|--------|---------------|
| Reconnaissance | Nmap mastery, service enumeration, banner grabbing | Nmap ✅ |
| Firewall Evasion | Source port spoofing, DNS trust abuse, filtered port bypass | Nmap ✅ |
| Service Enumeration | FTP, SMB, protocols, Samba tools | Footprinting 🔄 |
| Web Exploitation | SQLi, directory brute-forcing, plugin enumeration | Upcoming |
| Privilege Escalation | Linux/Windows privesc techniques | Upcoming |
| Active Directory | Kerberos, Bloodhound, lateral movement | Upcoming |

---

## Post-CPTS Goals

- OSCP course access setup (June 1)
- PWK labs enrollment (June 15)
- OSCP intensive begins (July 1)
