# Section 1 — Introduction to Windows Privilege Escalation

> **No lab / no questions** — methodology & context section. Sets up the *why* behind every technique in the module.
> Companion: `../Foundation/Privilege_Escalation.md` (general decision tree / vector priority matrix) — this module = Windows-specific vectors in depth.

**Goal:** low-priv user → `Local Administrator` or `NT AUTHORITY\SYSTEM`. Sometimes escalating to *another user* (e.g., a service account with SeImpersonate, or a user with DB access) is enough to reach the objective.

**Rule #1: manual enumeration matters.** Automated tools (WinPEAS, Seatbelt, PowerUp) are excellent, but you'll hit environments where you can't load tools — no internet, USB ports blocked, AppLocker/WDAC in place. Know how to enumerate and escalate with built-in cmd.exe and PowerShell.

---

## Why privilege escalation happens

| Root cause | Example |
|------------|---------|
| Understaffed / under-budgeted IT | Patching, auditing, and hardening fall behind |
| Weak gold images | Default installs ship services/perms never reviewed |
| Credential sprawl | Scripts and configs with plaintext passwords on shares |
| Legacy compatibility | Old apps require elevated service accounts or weak ACLs |
| No internal assessments | Flaws go unnoticed until an attacker finds them |

---

## Common Windows privilege escalation vectors

| Vector | Key idea |
|--------|----------|
| Windows user privileges | SeImpersonate, SeBackup, SeTakeOwnership, SeDebug, SeLoadDriver |
| Windows group privileges | Backup Operators, DnsAdmins, Server Operators, Print Operators, Hyper-V Admins |
| Weak service permissions | Modify service binary path or DLL search order |
| Unquoted service paths | Inject a binary into a path gap |
| DLL hijacking | Place a malicious DLL where a service searches first |
| Credential theft | SAM/LSASS dump, registry secrets, saved creds, DPAPI |
| UAC bypass | Elevated execution without triggering the consent prompt |
| Kernel exploits | Unpatched OS → local root (last resort — noisy, may crash) |
| Scheduled tasks / Startup | Writable scripts executed by SYSTEM or another privileged user |
| Traffic capture | Sniff creds on the wire (LLMNR/NBT-NS, cleartext protocols) |
| Abusing installed software | Vulnerable third-party apps with local admin context |

---

## Real-world scenarios (from module)

### Scenario 1 — Overcoming network restrictions

Situation: client-provided workstation, no internet, USB blocked, NAC preventing direct attacker-machine connection.

```
Enumeration → found printer VLAN allows outbound 80/443/445
→ manual privesc via permissions flaw
→ manual LSASS memory dump
→ mounted SMB share on printer VLAN, exfiltrated DMP
→ offline Mimikatz → domain admin NTLM hash → cracked → DC access
```
> Takeaway: when you can't load tools, manual enumeration and creative network paths (printer VLANs, management interfaces) become critical.

### Scenario 2 — Pillaging open shares

Situation: locked-down environment, no obvious misconfigs or vulnerable services.

```
Found wide-open file share hosting VM backups (.VMDK/.VHDX)
→ mounted .VHDX as local drive on Windows VM
→ extracted SYSTEM, SAM, SECURITY registry hives
→ secretsdump.py → local admin hash
→ gold image = same hash everywhere → pass-the-hash across the network
```
> Takeaway: shares with VM backups are goldmines. Mount virtual disks offline to pull hashes without touching live systems.

### Scenario 3 — Hunting credentials & abusing account privileges

Situation: standard domain user on a laptop, tools allowed, goal = critical database servers.

```
Snaffler → hunted file shares → found .sql files with DB creds
→ mssqlclient.py → enabled xp_cmdshell → local command exec as service account
→ whoami /priv → SeImpersonatePrivilege confirmed
→ Juicy Potato → added local admin (reverse shell attempts failed)
→ RDP in as local admin → full DB access
```
> Takeaway: credential hunting (Snaffler, manual share browsing) feeds into service account abuse (SeImpersonate → Potato family). Always check `whoami /priv` on service accounts.

---

## Reasons you escalate

1. **Gold image / workstation breakout** — the assessment goal itself is to break out of a locked-down build
2. **Local resource access** — a database, file, or service only available to admins
3. **AD foothold** — SYSTEM on a domain-joined machine → extract machine account hash or LSASS creds → lateral movement
4. **Credential harvesting** — local admin → SAM dump / LSASS / DPAPI → reuse across the network

---

## Connecting to module labs

```bash
xfreerdp /v:<TARGET_IP> /u:htb-student /p:<PASSWORD> /cert:ignore /dynamic-resolution +clipboard
```
> Default creds throughout: `htb-student` (unless stated otherwise). Tools pre-staged in `C:\Tools` on targets.

---

## Key mindset points

- **Enumeration > exploitation.** Most Windows privesc is a misconfiguration you find, not an exploit you fire.
- **Manual first, tools second.** cmd.exe and PowerShell are always available. WinPEAS/Seatbelt are accelerators, not crutches.
- **Think laterally.** Escalating to a service account (not just admin) may be the path to your objective.
- **Chain small wins.** A readable share → creds → service account → SeImpersonate → SYSTEM. No single step looks dramatic; the chain is the exploit.
