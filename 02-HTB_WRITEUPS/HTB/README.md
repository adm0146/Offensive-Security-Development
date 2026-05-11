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
CPTS Learning Pathway: ████████████████████░░░░░░░░░░░░░░░░░░░░ ~50%
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
| **Active Directory Enumeration & Attacks** | ✅ **Complete** | **36/36** | **Skills Assessments I & II ✅** |
| Using Web Proxies | ⬚ Not Started | — | |
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

## Active Directory Enumeration & Attacks — Complete ✅

All 36 sections finished May 11, 2026. Full reference guides at:
`06-REFERENCE_GUIDES/Active_Directory_Enumeration_and_Attacks/`

### Attack Techniques Covered

| Technique | Tool(s) | Section |
|-----------|---------|---------|
| LLMNR/NBT-NS Poisoning | Responder, Inveigh | 06, 07 |
| Password Spraying | kerbrute, CrackMapExec | 11, 12 |
| Kerberoasting | GetUserSPNs.py, Rubeus | 17, 18 |
| AS-REP Roasting | GetNPUsers.py, Rubeus | 26 |
| ACL Abuse (GenericAll/WriteDACL) | PowerView, ldap3 | 19, 20, 21 |
| DCSync | secretsdump.py, Mimikatz | 22 |
| Pass-the-Hash | evil-winrm, psexec.py, wmiexec.py | 23 |
| SeImpersonatePrivilege | PrintSpoofer, JuicyPotato | 35 |
| NoPac | noPac.py | 25 |
| PrintNightmare | CVE-2021-1675 | 25 |
| PetitPotam + ADCS relay | ntlmrelayx.py | 25 |
| ExtraSids (Child→Parent) | ticketer.py, Mimikatz kerberos::golden | 28, 29 |
| Cross-Forest Kerberoasting | GetUserSPNs.py -target-domain | 30, 31 |
| BloodHound collection | bloodhound-python, SharpHound | 14, 15 |
| Targeted Kerberoasting | PowerView Set-DomainObject | 21 |
| Shadow Credentials | Certipy, pywhisker | 25 |
| MSSQL abuse | mssqlclient.py, xp_cmdshell | 23, 35 |

### Skills Assessment Results

**Part I** — External foothold → full domain compromise:
- Web shell (Antak ASPX) → SYSTEM on WEB-WIN01
- Kerberoasting `svc_sql` → cracked `lucky7`
- LSA Secrets (DefaultPassword) → `tpetty:Sup3rS3cur3D0m@inU2eR`
- DCSync as tpetty (DS-Replication rights) → Administrator hash
- Chisel SOCKS proxy → wmiexec.py PTH → DC01 flag

**Part II** — Internal Parrot Linux host → full domain compromise:
- Responder → `AB920:weasal`
- Password spray (kerbrute) → `BR086:Welcome1`
- Department Shares → web.config → `netdb:D@ta_bAse_adm1n!`
- MSSQL xp_cmdshell + PrintSpoofer (SeImpersonate) → SYSTEM on SQL01
- Mimikatz on SQL01 → `mssqlsvc` NTLM hash → Pwn3d on MS01
- BloodHound → CT059 has GenericAll on Domain Admins
- **Inveigh on MS01** → CT059:charlie1 (key insight: Inveigh on internal Windows host catches what Responder misses)
- GenericAll + LDAP → add CT059 to Domain Admins → DCSync → krbtgt hash

---

## Supplementary Box Practice

| Difficulty | Completed |
|------------|-----------|
| Very Easy | 19 |
| Easy | 3 |
| Medium | 0 |
| **Total** | **22** |

### Box Skills Index

| Skill | Box |
|-------|-----|
| Telnet default creds | MEOW |
| FTP anonymous | FAWN |
| SMB null session | DANCING |
| Redis enum | REDEEMER |
| RDP | EXPLOSION |
| Directory brute force | PREIGNITION |
| MongoDB | MONGOD |
| Rsync | SYNCED |
| SQLi auth bypass | APPOINTMENT |
| MySQL enum | SEQUEL |
| FTP + web login | CROCODILE |
| NTLM capture (Responder) | RESPONDER |
| AWS S3 | THREE |
| Web enum | IGNITION |
| SSTI | BIKE |
| SSH tunneling | FUNNEL |
| Jenkins RCE | PENNYWORTH |
| SMB + PSExec | TACTICS |
| MSSQL + xp_cmdshell + PSExec | ARCHETYPE |
| Web exploit + Linux privesc | NIBBLES |
| Theme injection + RCE | GETTING_STARTED |
| SMB CVE-2007-2447 | LAME |

---

## Certification Roadmap

| # | Cert | Focus | Status |
|---|------|-------|--------|
| 1 | Security+ | Foundations | ✅ Jan 2026 (768/900) |
| 2 | **CPTS** | Penetration Testing | 🔄 ~50% — exam June 21, 2026 |
| 3 | CRTO | Red Team Ops | ⬚ After CPTS |
| 4 | CRTE | Red Team Expert | ⬚ After CRTO |
| 5 | CARTP | Azure Red Team | ⬚ After CRTE |
