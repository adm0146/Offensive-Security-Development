# CPTS Box Progression — Skill Building Path

Ordered progression from Windows privesc fundamentals through full AD chains. Do these after finishing AEN guided walkthrough and before Zephyr.

---

## Phase 1 — Windows Privilege Escalation (Layer 3)

Goal: Get comfortable landing on Windows, recognizing SeImpersonate, dumping creds.

| # | Box | Difficulty | Primary Skills |
|---|-----|-----------|----------------|
| 1 | Jeeves | Medium | Jenkins RCE, SeImpersonate + JuicyPotato, KeePass credential hunting (.kdbx) |
| 2 | Bastard | Medium | Drupal RCE, SeImpersonate + JuicyPotato, Windows token abuse |

After these two: you should recognize `whoami /priv` output, pick the right Potato variant for the OS, and hunt for creds post-exploitation.

---

## Phase 2 — Active Directory Fundamentals (Layer 4 Basics)

Goal: Learn the core AD attack loop — enumerate, Kerberoast/AS-REP, BloodHound, DCSync.

| # | Box | Difficulty | Primary Skills |
|---|-----|-----------|----------------|
| 3 | Active | Easy | SMB enumeration, GPP cPassword decryption (Groups.xml), Kerberoasting |
| 4 | Forest | Easy | AS-REP Roasting, BloodHound path discovery, WriteDACL → DCSync |
| 5 | Sauna | Easy | AS-REP Roasting, BloodHound ACL abuse, DCSync, Mimikatz |
| 6 | Resolute | Medium | Password spraying (default creds), WinRM, DnsAdmins group privesc |
| 7 | Monteverde | Medium | LDAP user enumeration, SMB brute force, Azure AD Connect credential extraction |

After these five: Kerberoasting, AS-REP Roasting, BloodHound, and DCSync should be muscle memory.

---

## Phase 3 — Advanced AD (Layer 4 Depth)

Goal: Handle ADCS, delegation attacks, and Kerberos-only environments.

| # | Box | Difficulty | Primary Skills |
|---|-----|-----------|----------------|
| 8 | Escape | Medium | MSSQL credential leakage, ADCS ESC1 exploitation (certipy-ad) |
| 9 | Support | Easy | LDAP enumeration, Resource-Based Constrained Delegation (RBCD) |
| 10 | Scrambled | Medium | Kerberos-only auth (no NTLM), Kerberoasting, Silver Ticket forgery, MSSQL impersonation |

After these three: you can handle ADCS attacks, delegation abuse, and non-standard AD configurations.

---

## Phase 4 — Full Chain (Layers 1-5 Combined)

Goal: Practice the complete exam workflow — web exploit → privesc → pivot → AD → Domain Admin.

| # | Box | Difficulty | Primary Skills |
|---|-----|-----------|----------------|
| 11 | Blackfield | Hard | AS-REP Roasting, BloodHound ForceChangePassword, LSASS dump analysis, SeBackupPrivilege → NTDS.dit |
| 12 | Cerberus | Hard | CVE chaining, Linux privesc, Linux → Windows pivot, ADCS exploitation |

---

## Additional Resources

| Resource | Link / Notes |
|----------|-------------|
| HTB CPTS Preparation Track | 16 curated machines on HTB main platform — directly mapped to exam topics |
| IppSec CPTS Prep Playlist | youtube.com — unofficial walkthrough playlist mapped to CPTS curriculum |
| AD Box List (GitHub) | github.com/seriotonctf/HackTheBox-AD-Machines — every AD box on HTB |
| 0xdf Writeups | 0xdf.gitlab.io — detailed methodology writeups, read after completing each box |

## Pro Labs (After Boxes)

| Lab | Purpose |
|-----|---------|
| Zephyr | Multi-hop pivoting, segmentation, dead ends — mirrors exam experience |
| Dante | Beginner-friendly multi-host lab, good for pivoting confidence |
| Offshore | Real-world AD enterprise, multi-domain attacks — most recommended for CPTS |

---

## Recommended Order

```
1. Finish AEN guided walkthrough
2. Phase 1-2 boxes (Jeeves → Monteverde) — ~2-3 weeks
3. Buy Zephyr — full chain blind practice
4. Phase 3-4 boxes (Escape → Cerberus) — ~2 weeks
5. AEN blind attempt
6. Exam readiness gate check
```
