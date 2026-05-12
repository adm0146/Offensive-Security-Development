# CPTS Progress Tracking

**Start Date:** January 22, 2026  
**Target Exam:** June 21, 2026  
**Last Updated:** May 11, 2026

---

## Exam Strategy

⚠️ **Important:** The CPTS exam tests knowledge from **Academy modules**, NOT box-solving ability. Labs/boxes are supplementary practice to reinforce module concepts.

**Priority:**
1. **Academy Modules** — Primary focus (exam content comes from here)
2. **Module Labs** — Skill assessments within modules
3. **HTB Boxes** — Supplementary practice (evening/weekend)

---

```
CPTS Learning Pathway: █████████████████████░░░░░░░░░░░░░░░░░░░ ~54%
```

---

## Academy Module Progress (Primary Focus)

| Module | Status | Sections | Notes |
|--------|--------|----------|-------|
| Network Enumeration with Nmap | ✅ Complete | 7/7 | Labs: E/M/H |
| Footprinting | ✅ Complete | All | |
| Information Gathering - Web | ✅ Complete | All | |
| Vulnerability Assessment | ✅ Complete | All | |
| File Transfers | ✅ Complete | All | |
| Shells & Payloads | ✅ Complete | 17/17 | Skills Assessment ✅ |
| Using the Metasploit Framework | ✅ Complete | All | |
| Password Attacks | ✅ Complete | All | |
| Attacking Common Services | ✅ Complete | All | Labs: E/M/H ✅ |
| Pivoting, Tunneling, Port Forwarding | ✅ Complete | All | Skills Assessment ✅ |
| Active Directory Enumeration & Attacks | ✅ Complete | 36/36 | Skills Assessments I & II ✅ |
| **Using Web Proxies** | ✅ **Complete** | **15/15** | **Skills Assessment ✅** |
| Attacking Web Applications with FFuF | ⬚ Not Started | — | |
| Login Brute Forcing | ⬚ Not Started | — | |
| SQL Injection Fundamentals | ⬚ Not Started | — | |
| SQLMap Essentials | ⬚ Not Started | — | |
| Cross-Site Scripting (XSS) | ⬚ Not Started | — | |
| File Inclusion | ⬚ Not Started | — | |
| File Upload Attacks | ⬚ Not Started | — | |
| Command Injections | ⬚ Not Started | — | |
| Web Attacks | ⬚ Not Started | — | |
| Attacking Common Applications | ⬚ Not Started | — | |
| Linux Privilege Escalation | ⬚ Not Started | — | |
| Windows Privilege Escalation | ⬚ Not Started | — | |
| Documentation & Reporting | ⬚ Not Started | — | |
| Attacking Enterprise Networks | ⬚ Not Started | — | Final capstone |

---

## Using Web Proxies — Complete ✅

All 15 sections finished May 11, 2026. Full reference guides at:
`06-REFERENCE_GUIDES/Using_Web_Proxies/`

### Techniques Covered

| Technique | Tool(s) | Section |
|-----------|---------|---------|
| Request interception & modification | Burp Proxy, ZAP | 04 |
| Response interception (modify HTML) | Burp Proxy, ZAP | 05 |
| Automatic Match & Replace rules | Burp Match/Replace, ZAP Replacer | 06 |
| Request repeating / replaying | Burp Repeater, ZAP Request Editor | 07 |
| Multi-layer encoding/decoding | Burp Decoder, ZAP E-D-H, Python | 08 |
| Proxying CLI tools | proxychains, MSF PROXIES | 09 |
| Directory/file fuzzing | Burp Intruder, ZAP Fuzzer, ffuf | 10–11 |
| Web scanning (passive + active) | Burp Scanner (Pro), ZAP Scanner | 12–13 |
| Extensions & add-ons | BApp Store, ZAP Marketplace | 14 |
| Disabled button bypass | Response intercept, direct POST | 15 |
| MD5 cookie fuzzing with encoding | ZAP Fuzzer + MD5 processor | 11, 15 |

### Skills Assessment Results

**Q1:** `/lucky.php` — disabled button bypassed by POSTing directly (client-side `disabled` is meaningless to the server)

**Q2:** `/admin.php` cookie decoded: Hex → Base64 → `3dac93b8cd250aa8c1a36fffc79a17a` (31-char MD5)

**Q3:** Fuzzed last char of 31-char MD5 hash → char `d` → `3dac93b8cd250aa8c1a36fffc79a17ad` → flag via re-encoded cookie (plaintext → base64 → hex per request)

**Q4:** MSF `coldfusion_locale_traversal` proxied through Burp — directory in path is `CFIDE`

---

## Active Directory Enumeration & Attacks — Complete ✅

All 36 sections finished May 11, 2026. Skills Assessments I & II completed.
Full guides at: `06-REFERENCE_GUIDES/Active_Directory_Enumeration_and_Attacks/`

### Key Attack Chains Mastered

| Chain | Technique |
|-------|-----------|
| No creds → foothold | Responder/Inveigh LLMNR capture + hashcat |
| One user → DA | BloodHound → ACL abuse → targeted Kerberoast → DCSync |
| MSSQL → SYSTEM | xp_cmdshell + SeImpersonatePrivilege + PrintSpoofer |
| Child domain → parent | ExtraSids Golden Ticket (ticketer.py) |
| Cross-forest | Kerberoasting with -target-domain |
| Internal pivot | Chisel SOCKS proxy + proxychains Impacket |

---

## Supplementary Box Practice

| Difficulty | Completed |
|------------|-----------|
| Very Easy | 19 |
| Easy | 3 |
| Medium | 0 |
| **Total** | **22** |

---

## Certification Roadmap

| # | Cert | Focus | Status |
|---|------|-------|--------|
| 1 | Security+ | Foundations | ✅ Jan 2026 (768/900) |
| 2 | **CPTS** | Penetration Testing | 🔄 ~54% — exam June 21, 2026 |
| 3 | CRTO | Red Team Ops | ⬚ After CPTS |
| 4 | CRTE | Red Team Expert | ⬚ After CRTO |
| 5 | CARTP | Azure Red Team | ⬚ After CRTE |
