# CPTS Progress Tracking

**Start Date:** January 22, 2026  
**Target Exam:** June 21, 2026  
**Last Updated:** May 15, 2026

---

## Exam Strategy

⚠️ **Important:** The CPTS exam tests knowledge from **Academy modules**, NOT box-solving ability. Labs/boxes are supplementary practice to reinforce module concepts.

**Priority:**
1. **Academy Modules** — Primary focus (exam content comes from here)
2. **Module Labs** — Skill assessments within modules
3. **HTB Boxes** — Supplementary practice (evening/weekend)

---

```
CPTS Learning Pathway: ████████████████████████████████████░░░░ 88.9%
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
| Using Web Proxies | ✅ Complete | 15/15 | Skills Assessment ✅ |
| Attacking Web Applications with FFuF | ✅ Complete | 13/13 | Skills Assessment ✅ |
| Login Brute Forcing | ✅ Complete | 13/13 | Skills Assessment ✅ |
| SQL Injection Fundamentals | ✅ Complete | 17/17 | Skills Assessment ✅ (chattr.htb) |
| SQLMap Essentials | ✅ Complete | 11/11 | Skills Assessment ✅ (Minishop) |
| **Cross-Site Scripting (XSS)** | ✅ **Complete** | **10/10** | **Skills Assessment ✅ (WordPress)** |
| File Inclusion | ✅ Complete | 11/11 | Skills Assessment ✅ |
| File Upload Attacks | ✅ Complete | 11/11 | Skills Assessment ✅ |
| Command Injections | ✅ Complete | 12/12 | Skills Assessment ✅ |
| Web Attacks | ✅ Complete | 18/18 | Skills Assessment ✅ |
| **Attacking Common Applications** | ✅ **Complete** | **33/33** | All apps + exam cheatsheet |
| **Linux Privilege Escalation** | ✅ **Complete** | **28/28** | All guides + exam cheatsheet |
| Windows Privilege Escalation | ⬚ Not Started | — | |
| Documentation & Reporting | ⬚ Not Started | — | |
| Attacking Enterprise Networks | ⬚ Not Started | — | Final capstone |

---

## Attacking Common Applications — Complete ✅

All 33 sections finished May 14, 2026. Guides at:
`06-REFERENCE_GUIDES/Attacking_Common_Applications/`

### Covered Applications

| Application | Attack Technique |
|-------------|----------------|
| WordPress | WPScan enum, plugin upload RCE, CVE-2021-29447 (XXE), xmlrpc brute force |
| Joomla | Template editor RCE, CVE-2019-10945 directory traversal, config.php creds |
| Drupal | Drupalgeddon2 (CVE-2018-7600), Drupa queen (CVE-2019-6340), PHP filter module RCE |
| Tomcat | Manager WAR upload RCE, CVE-2019-0232 CGI RCE, AJP Ghostcat (CVE-2020-1938) |
| Jenkins | Script console Groovy RCE, `cmd.exe /c` shell, declarative pipeline injection |
| Splunk | Malicious app upload, Free mode REST API RCE (Python 3 `.decode()` fix required) |
| PRTG | CVE-2018-9276 notification cmd injection → SYSTEM, `objecttype=notification` required |
| osTicket | Email harvesting for account registration, closed ticket credential extraction |
| GitLab | CVE-2021-22205 ExifTool RCE, self-registration bypass |
| Shellshock | CVE-2014-6271 CGI User-Agent injection |
| ColdFusion | CVE-2010-2861 traversal, CVE-2009-2265 FCKeditor upload |
| IIS Tilde | Short filename enumeration (8.3) |
| WebLogic | CVE-2020-14882+14883 unauth RCE |
| Nagios XI | CVE-2020-35578 plugin filename injection |

---

## Linux Privilege Escalation — Complete ✅

All 28 sections finished May 15, 2026. Full reference guides at:
`06-REFERENCE_GUIDES/Linux_Privilege_Escalation/`

### Techniques Covered

| Category | Techniques |
|----------|-----------|
| Enumeration | Environment, services/internals, credential hunting, hidden files |
| Permissions | SUID/SGID + GTFOBins, sudo rights, capabilities, privileged groups |
| Abuse Vectors | PATH abuse, wildcard abuse, cron job abuse, restricted shell escape |
| Services & Misc | Screen 4.5.0, NFS no_root_squash, tmux hijacking, logrotate |
| Libraries | LD_PRELOAD, shared object hijacking (RUNPATH), Python library hijacking |
| Containers | LXC/LXD, Docker, Kubernetes |
| Kernel/CVE | OverlayFS, Dirty Pipe, Dirty COW, PwnKit, Netfilter CVEs |
| Sudo/Polkit | CVE-2019-14287, Baron Samedit, CVE-2021-4034 |
| Skills Assessment | 5-flag chain: hidden files → cred reuse → group privs → Tomcat → sudo pager escape |

---

## File Inclusion — Complete ✅

All 11 sections finished May 14, 2026. Full reference guides at:
`06-REFERENCE_GUIDES/File_Inclusion/`

### Techniques Covered

| Technique | Key Detail |
|-----------|------------|
| Path traversal (LFI) | `../../etc/passwd`, null bytes, encoding bypasses, approved path bypass |
| PHP filters | `php://filter/convert.base64-encode/resource=config.php` |
| PHP wrappers | `data://`, `input://`, `expect://` for code execution |
| Remote File Inclusion | Hosted PHP shell, Windows UNC path RFI |
| LFI + file upload | Upload image with PHP in EXIF, include via LFI |
| Log poisoning | Apache/Nginx access log, SSH auth log, `/proc/self/environ` |
| Automated scanning | ffuf with LFI wordlists, fuzzing for traversal depth |

---

## File Upload Attacks — Complete ✅

All 11 sections finished May 14, 2026. Full reference guides at:
`06-REFERENCE_GUIDES/File_Upload_Attacks/`

### Techniques Covered

| Bypass Method | Technique |
|---------------|-----------|
| Absent validation | Direct `.php` shell upload |
| Client-side bypass | Intercept in Burp, change extension/Content-Type |
| Blacklist bypass | `.php5`, `.phtml`, `.phar`, `.shtml` alt extensions |
| Whitelist bypass | Double extension (`shell.jpg.php`), null byte (`shell.php%00.jpg`) |
| Type filter bypass | Magic bytes (`FF D8 FF`), exiftool comment injection |
| SVG/XML injection | XXE via SVG, XSS via SVG `<script>` |
| Zip slip | Directory traversal via zip entry filename |

---

## Command Injections — Complete ✅

All 12 sections finished May 14, 2026. Full reference guides at:
`06-REFERENCE_GUIDES/Command_Injections/`

### Techniques Covered

| Technique | Detail |
|-----------|--------|
| Injection operators | `;`, `||`, `&&`, `\|`, newline (`%0a`) |
| Space filter bypass | `${IFS}`, `%09`, brace expansion `{cmd,}` |
| Char filter bypass | `$'c'at`, variable slicing `${PATH:0:1}`, `/???/c?t` |
| Command filter bypass | Case manipulation, `w'h'o'a'm'i`, `who$@ami`, `$(rev<<<imaohw)` |
| Blind injection | Time-based (`sleep 5`), OOB DNS/HTTP exfil |
| Obfuscation tools | Bashfuscator, DOSfuscation |

---

## Web Attacks — Complete ✅

All 18 sections finished May 14, 2026. Full reference guides at:
`06-REFERENCE_GUIDES/Web_Attacks/`

### Techniques Covered

| Category | Techniques |
|----------|-----------|
| HTTP Verb Tampering | GET/POST/HEAD bypass auth, bypass security filters |
| IDOR | Insecure direct object references, encoded reference bypass, API IDOR |
| XXE Injection | Local file read, SSRF, blind OOB exfil via DNS, error-based XXE |

---

## Attacking Web Applications with FFuF — Complete ✅

All 13 sections finished May 12, 2026. Full reference guides at:
`06-REFERENCE_GUIDES/Attacking_Web_Apps_with_FFuF/`

### Techniques Covered

| Technique | Tool | Section |
|-----------|------|---------|
| Vhost/subdomain discovery | ffuf `-H 'Host: FUZZ.domain.htb'` | 07–09 |
| Extension fuzzing | ffuf `-u /indexFUZZ` | 04 |
| Recursive page fuzzing | ffuf `-recursion -recursion-depth 1 -e .php` | 05 |
| GET parameter fuzzing | ffuf `?FUZZ=key` | 10 |
| POST parameter fuzzing | ffuf `-X POST -d 'FUZZ=key'` | 11 |
| Value fuzzing (numeric + names) | ffuf `param=FUZZ` with ids.txt / names.txt | 12 |
| Response filtering | `-fs SIZE` to cut noise | 09 |

### Skills Assessment Results

**Q1:** Vhosts — `archive`, `test`, `faculty` (filtered default 985-byte response)

**Q2:** Extensions — `.php` and `.phps` on all; `.php7` additionally on `faculty`

**Q3:** Page — `http://faculty.academy.htb:PORT/courses/linux-security.php7`

**Q4:** Parameters — `user` and `username` (POST, burp-parameter-names.txt)

**Q5:** Flag — `HTB{w3b_fuzz1n6_m4573r}` (`username=harry`, names.txt wordlist)

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
| 2 | **CPTS** | Penetration Testing | 🔄 88.9% (25/28) — exam June 21, 2026 |
| 3 | CRTO | Red Team Ops | ⬚ After CPTS |
| 4 | CRTE | Red Team Expert | ⬚ After CRTO |
| 5 | CARTP | Azure Red Team | ⬚ After CRTE |
