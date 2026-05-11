# Section 36 — Beyond This Module

> Final section — no labs, no flags. Resources for continuing AD security education.
> **Module complete.** All 36 sections finished.

---

## What Comes Next

The skills from this module feed directly into:
- **Cross-domain trust attacks** — abusing forest/external trusts to pivot between AD environments
- **Persistence techniques** — Golden Tickets, Silver Tickets, skeleton keys, AdminSDHolder abuse
- **C2 within a domain** — long-engagement assessments that need stealth and dwell time
- **Cloud pivoting** — AD foundations apply directly to Azure AD (Entra ID), hybrid environments, and SSO attacks

---

## Recommended HTB Modules (do these next)

| Module | Why It Matters |
|--------|---------------|
| **Active Directory BloodHound** | Deep dive into BloodHound graph queries, custom Cypher, and finding attack paths you'd miss manually |
| **Active Directory LDAP** | Understanding LDAP queries makes credentialed enumeration faster and more targeted |
| **Active Directory PowerView** | PowerView syntax and use cases — essential for Windows-side AD enumeration |
| **Cracking Passwords with Hashcat** | Improve speed and technique for cracking Kerberoast, AS-REP, NTLMv2, and NTLM hashes |
| **Introduction to Active Directory** | Go back to this if anything in this module was unclear — it explains the AD fundamentals in depth |

---

## HTB Boxes to Practice AD Skills

Work through these roughly in order of difficulty:

| Box | Key Skills |
|-----|-----------|
| **Forest** | AS-REP Roasting, DCSync, Exchange group abuse |
| **Active** | GPP password decryption, Kerberoasting |
| **Reel** | Phishing, ACL abuse, PowerView |
| **Mantis** | MSSQL, Kerberos delegation, Silver Ticket |
| **Blackfield** | AS-REP Roasting, Backup Operators → NTDS dump |
| **Monteverde** | Azure AD Connect, MSSQL, password reuse |

**Tip:** If you're stuck on any box, watch the IppSec video for it first. IppSec's site (ippsec.rocks) lets you search by technique — search "kerberoast" or "BloodHound" and get a list of relevant boxes.

---

## Pro Labs and Endgames

| Lab | Level | AD Focus |
|-----|-------|----------|
| **Dante Pro Lab** | Beginner/Intermediate | Good variety, introduces AD concepts |
| **Offshore Pro Lab** | Advanced | Full AD environment, heavy trust abuse and lateral movement |
| **Ascension Endgame** | Expert | Two AD domains, extreme challenge, mirrors real enterprise |

---

## Must-Watch Videos

| Video | Why Watch It |
|-------|-------------|
| **Six Degrees of Domain Admin** — Andy Robbins, BloodHound team (DEFCON 24) | How BloodHound was built and the graph-theory thinking behind AD attack paths |
| **Designing AD DACL Backdoors** — Will Schroeder & Andy Robbins | ACL abuse in depth — the theory behind GenericAll, WriteDACL, and persistence |
| **Kicking The Guard Dog of Hades** — Tim Medin | The original Kerberoasting talk — explains why it works and how defenders can detect it |
| **Kerberoasting 101** — Tim Medin | Practical breakdown of Kerberoasting mechanics |

---

## Blogs and Authors to Follow

| Author / Blog | Topics |
|---------------|--------|
| **0xdf** (0xdf.gitlab.io) | HTB box walkthroughs — best write-ups for seeing real AD attack paths step by step |
| **SpecterOps** (blog.specterops.io) | BloodHound, C2, AD research — the team that built BloodHound |
| **harmj0y** (harmj0y.net/blog) | PowerView author — deep AD offense research, ACL abuse, Kerberos attacks |
| **AD Security** — Sean Metcalf (adsecurity.org) | Comprehensive AD security reference — Mimikatz internals, Golden Tickets, detection |
| **Shenaniganslabs** | New vulnerabilities, Threat Actor TTPs, AD research |
| **Dirk-jan Mollema** (dirkjanm.io) | Azure AD, protocol attacks, Python tools (mitm6, ldapdomaindump) |
| **The DFIR Report** (thedfirreport.com) | Real intrusion analyses — shows what AD attacks look like from the defender side with forensic artifacts |

---

## MITRE ATT&CK Reference

For any technique learned in this module, look it up in MITRE ATT&CK:
- `TA0006` = Credential Access (Kerberoasting, AS-REP Roasting, DCSync, LSASS dump)
- `T1558` = Steal or Forge Kerberos Tickets
- `T1558.003` = Kerberoasting
- `T1558.004` = AS-REP Roasting
- `T1003.006` = DCSync
- `T1110.003` = Password Spraying
- `T1557.001` = LLMNR/NBT-NS Poisoning
- `T1134.002` = Token Impersonation (SeImpersonatePrivilege / PrintSpoofer)

Each entry includes: how defenders detect it, what logs it generates, and which tools are commonly used.

---

## Module Complete — Skills Summary

After completing this module you can:

| Skill | Technique |
|-------|-----------|
| Get initial foothold with zero creds | LLMNR/NBT-NS poisoning (Responder/Inveigh) |
| Identify weak passwords at scale | Password spraying (kerbrute, crackmapexec) |
| Map the entire AD attack surface | BloodHound + credentialed enumeration |
| Crack Kerberos service ticket hashes | Kerberoasting (GetUserSPNs.py, Rubeus) |
| Escalate via misconfigured ACLs | GenericAll/GenericWrite/WriteDACL abuse |
| Dump every hash in the domain | DCSync (secretsdump.py, Mimikatz) |
| Move between child and parent domains | ExtraSids Golden Ticket attack |
| Move between forests | Cross-forest Kerberoasting, foreign group membership |
| Escalate from SQL service to SYSTEM | SeImpersonatePrivilege + PrintSpoofer |
| Pivot using captured hashes | Pass-the-Hash (evil-winrm, psexec.py, wmiexec.py) |

Keep practicing. AD security is one of the highest-value skills in the industry.
