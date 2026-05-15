# Section 32 — Hardening Active Directory

> Defensive section — no lab questions. Covers the hardening measures that counter the TTPs used throughout this module.
> Understanding defenses makes you a better attacker: you know which controls to probe for and where gaps likely remain.

---

## QUICK REFERENCE

```powershell
# View Protected Users group membership
Get-ADGroup -Identity "Protected Users" -Properties Name,Description,Members

# Check ms-DS-MachineAccountQuota (should be 0)
Get-ADDomain | select ms-DS-MachineAccountQuota

# Audit accounts with no password required (PASSWD_NOTREQD flag)
Get-ADUser -Filter {PasswordNotRequired -eq $true} -Properties PasswordNotRequired | select SamAccountName

# Find accounts that don't require pre-auth (ASREPRoastable)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth | select SamAccountName

# Audit Kerberoastable accounts (SPN set, not gMSA)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | select SamAccountName,ServicePrincipalName

# Find accounts with unconstrained delegation enabled
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | select Name
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | select SamAccountName

# Check if print spooler is running (should be disabled on DCs)
Get-Service -Name Spooler | select Name,Status

# Find stale computer accounts (not logged in for 90+ days) — defender audit
Search-ADAccount -ComputersOnly -AccountInactive -TimeSpan 90.00:00:00 | select Name,LastLogonDate
```
> AD hardening audit commands. Run these from a Domain Admin session to identify misconfigured accounts and risky settings. Each result is a potential finding or attack path: AS-REP Roastable accounts, Kerberoastable SPNs, unconstrained delegation, and stale accounts are common pentest wins.

---

## The Attacker Perspective

Hardening directly counters the attack paths in Sections 1–31. As a pentester, you need to understand each control for three reasons:
1. Identify when it IS in place — and pivot to a different technique.
2. Report when it is NOT in place — that is a high-value finding for the client.
3. Explain to defenders exactly what each control prevents.

---

## Step One: Document and Audit

**Why this matters:** You cannot protect what you do not know you have. Most breaches succeed because defenders had no inventory of privileged accounts, orphaned service accounts, or legacy systems.

### Things to Document and Track

| Item | Why It Matters to an Attacker |
|------|-------------------------------|
| Naming conventions (OUs, computers, users, groups) | Naming patterns reveal structure — `SVC_`, `ADM_`, `LEGACY_` prefix conventions tell us which accounts to target |
| DNS, network, DHCP configurations | Network layout reveals pivot paths, internal hostnames, subnets |
| All GPOs and what they're applied to | GPOs often push scripts with credentials to SYSVOL — discoverable without admin rights |
| FSMO roles | Tells us which DCs are highest-value targets |
| Full application inventory | Third-party apps introduce attack surface (Exchange, SharePoint, SQL) |
| Enterprise hosts and locations | Helps identify stale/unpatched systems that are easier to exploit |
| Trust relationships | Cross-domain/forest trusts = Section 27–31 attack paths |
| Users with elevated permissions | Most targeted group — if not documented, defenders can't detect anomalous use |

---

## People, Processes, and Technology Framework

### People

The human layer is the weakest link. The controls below prevent "easy wins" that cover most of the Tactics, Techniques, and Procedures (TTPs) in this module.

**Password controls:**
- Strong password policy with a filter that blocks `welcome`, `password`, months, seasons, company name
- Periodic rotation of ALL service account passwords
  - Why: Kerberoastable service accounts with never-rotated passwords are cracked in minutes with rockyou
- Enterprise password manager to prevent weak/reused passwords

**Privilege controls:**
- Disable local admin access on user workstations (no business need = no access)
  - Why: local admin = easy privilege escalation from a foothold, SAM hash dumping
- Disable the default `RID-500 local administrator` account; create a new admin account under LAPS
  - Why: RID-500 cannot be locked out — spray-resistant for attackers
- Implement tiered administration (separate accounts for: workstation admin, server admin, DC admin)
  - Why: Compromise of a Tier 2 account should never yield Domain Admin — tiering breaks this chain
- Keep privileged group membership minimal (DA/EA should have fewer than 10 members in most orgs)
  - Why: Every extra DA is another Kerberoastable/DCSync-able account we can target
- Place high-value accounts in the **Protected Users** group

**Protected Users Group:**
```powershell
Get-ADGroup -Identity "Protected Users" -Properties Name,Description,Members
# Built-in security group introduced in Windows Server 2012 R2
# Members receive hardened Kerberos and authentication behavior automatically
# Adding an account here requires NO other configuration changes
```
> Lists current members of the Protected Users group. Membership blocks NTLM, RC4 Kerberos, delegation, Digest auth, and caps TGT lifetime at 4 hours. As an attacker, note which privileged accounts are NOT in this group — those are easier targets.

What Protected Users enforces for members:
| Protection | What It Blocks |
|-----------|---------------|
| No constrained or unconstrained delegation | Prevents delegation abuse (Section 19/20 attacks) |
| CredSSP does not cache plaintext credentials | Blocks credential harvesting from memory via CredSSP |
| Windows Digest disabled — no plaintext password cache | Blocks `sekurlsa::wdigest` in Mimikatz |
| No NTLM authentication | Blocks pass-the-hash attacks for this account |
| No DES or RC4 Kerberos keys | Forces AES — RC4 TGTs required for certain Golden Ticket attacks become unavailable |
| Long-term keys/plaintext not cached after TGT acquisition | Limits what can be harvested from LSASS |
| TGT renewal capped at 4 hours (not the default 10 hours) | Limits the window an attacker has with a stolen TGT |

> **Warning:** Protected Users can cause auth failures for service accounts. Test in staging before applying broadly — never add ALL privileged users at once.

- Disable Kerberos delegation for administrative accounts explicitly (Protected Users may not cover all cases)

---

### Processes

Policies and procedures close gaps that technology alone cannot close.

**Asset management:**
- Periodic AD host audits with asset tags
  - Why: Untracked hosts are never patched and become low-hanging pivot points
- Defined provisioning and decommissioning workflows with baseline hardening gold images
  - Why: Hosts built without a hardening baseline ship with legacy settings attackers rely on

**Access control:**
- Formal user account provisioning/de-provisioning process with MFA enforcement
  - Why: Orphaned accounts from former employees are frequently valid and never rotated
- Defined schedule for auditing users, groups, and hosts
  - Why: AD accumulates stale objects — stale accounts often retain high permissions from old roles

**Cleanup policies:**
- Process for removing stale AD records (not just disabling — actively purging)
- Formal process for decommissioning legacy OS and services (e.g., removing Exchange when migrating to M365)
  - Why: Print Nightmare, MS-RPRN abuse, and Exchange misconfigurations remain exploitable when services linger after migration

---

### Technology

Periodic review of AD with security tooling catches misconfigurations before attackers do.

**Periodic scanning:**
```
BloodHound   — graph-based AD attack path analysis
PingCastle   — automated AD risk score and misconfiguration report
Grouper      — GPO misconfiguration scanner (checks for cred exposure in SYSVOL)
```
Run these as part of quarterly security assessments. These are the same tools attackers use. Defenders should find the misconfigs first.

**Specific hardening controls and what they block:**

| Control | What It Blocks |
|---------|---------------|
| No passwords in AD account Description field | Quick-win credential harvest (Section 5 enumeration) |
| SYSVOL scripts audited for embedded credentials | GPP password abuse, legacy script creds |
| Use gMSA/MSA instead of standard service accounts | Kerberoasting — gMSA passwords auto-rotate and are 120+ char random, uncrackable |
| Disable unconstrained delegation wherever possible | Unconstrained delegation attacks (printer bug, Section 20) |
| Hardened jump hosts to access DCs — no direct DC RDP | Limits the blast radius if a sysadmin workstation is compromised |
| ms-DS-MachineAccountQuota = 0 | Prevents non-admin users from adding machine accounts → blocks noPac, RBCD attacks |
| Disable Print Spooler service on DCs and servers | Blocks PrinterBug (SpoolSample), PrintNightmare (CVE-2021-34527) |
| Disable NTLM authentication on DCs if possible | Blocks pass-the-hash, NTLM relay attacks entirely |
| Extended Protection for Authentication + SSL only on ADCS web enrollment | Blocks ESC8 (NTLM relay to ADCS), PetitPotam |
| Enable SMB signing | Blocks SMB relay attacks — poisoned LLMNR/NBT-NS responses can't be replayed |
| Enable LDAP signing and channel binding | Blocks LDAP relay attacks |
| RestrictNullSessAccess registry key = 1 | Blocks null session enumeration (unauthenticated SAMR, MSRPC enumeration) |

**RestrictNullSessAccess registry location:**
```
HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RestrictNullSessAccess = 1
```

---

## TTP-to-MITRE Hardening Map

| TTP | MITRE Tag | Key Defense |
|-----|-----------|-------------|
| External Reconnaissance | T1589 | Scrub document metadata before publishing; limit job posting detail about internal tools/versions |
| Internal Reconnaissance | T1595 | NIDS/firewall to detect scanning bursts; Windows Firewall tuned to not respond to ICMP; SIEM alerting on sweep patterns |
| LLMNR/NBT-NS Poisoning (Responder) | T1557 | Enable SMB signing; disable LLMNR and NBT-NS via GPO — eliminates the poisoning opportunity entirely |
| Password Spraying | T1110/003 | Monitor Event IDs 4624 (logon success) and 4648 (explicit credential logon) for spray patterns; strong lockout policy; MFA |
| Credentialed Enumeration | TA0006 | No complete prevention — detect via anomaly monitoring (CLI use by non-IT users, bulk LDAP queries, unusual RDP movement) |
| Living off the Land (LOTL) | N/A | Baseline normal traffic/behavior; AppLocker policy to restrict LOLBins; PowerShell Constrained Language Mode |
| Kerberoasting | T1558/003 | Use gMSA for service accounts; enforce AES encryption (disable RC4); strong service account passwords; audit SPN assignments |
| AS-REP Roasting | T1558/004 | Never set DONT_REQ_PREAUTH unless required; audit monthly; enforce pre-auth on all accounts |
| Pass-the-Hash | T1550/002 | Protected Users group for admins; disable NTLM; Credential Guard on Windows 10/11 |
| DCSync | T1003/006 | Audit Replicating Directory Changes permissions; only DCs and dedicated tools should have this right |
| Golden Ticket | T1558/001 | Rotate KRBTGT password twice (invalidates all existing tickets); monitor for TGTs with 10-year lifetimes |
| ExtraSids (Child→Parent) | T1134/005 | Rotate KRBTGT in child domain; enable SID filtering on intraforest trusts if child domains are untrusted |
| Cross-Forest Kerberoasting | T1558/003 | Same as domestic — gMSA for SPNs in trusted forests; check what accounts are exposed across trust |
| BloodHound Enumeration | TA0007 | Run BloodHound yourself first and remediate attack paths; restrict LDAP query access; monitor for large LDAP sweeps |

---

## Exam Notes

- gMSA = best single control against Kerberoasting — 120-char auto-rotating passwords make offline cracking impossible
- Protected Users = membership blocks NTLM, RC4, delegation, Digest, and limits TGT lifetime — no code changes required
- ms-DS-MachineAccountQuota = 0 blocks noPac and RBCD attacks that require adding machine accounts
- SMB signing + LDAP signing = kills relay attacks (Responder becomes useless without a crackable hash path)
- DisableSpooler on DCs = blocks PrinterBug and PrintNightmare — these require the Spooler service to be running
- Tiered admin model = prevents lateral movement from workstation → server → DC using a single set of creds
- Rotating KRBTGT twice = invalidates all outstanding Golden Tickets (each rotation uses the previous hash as the old one)
- Event IDs to know: 4624 (logon), 4648 (explicit credential logon), 4769 (Kerberos service ticket request), 4771 (Kerberos pre-auth failure)
- MITRE format: TA#### = tactic (goal), T####.### = technique/sub-technique (method)
- Kerberoasting in MITRE: TA0006 (Credential Access) → T1558 (Steal or Forge Kerberos Tickets) → T1558.003 (Kerberoasting)
- BloodHound is both an attacker tool AND a defender tool — the same attack paths attackers find, defenders should remediate
- Defenders should run BloodHound, PingCastle, and Grouper quarterly — if you find the path first, you can close it
