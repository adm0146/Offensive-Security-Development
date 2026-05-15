# Section 13 — Enumerating Security Controls

> Run this immediately after gaining a foothold. These checks determine which tools you can safely use on this host.

---

## QUICK REFERENCE — Run After Foothold

```powershell
# 1. Defender
Get-MpComputerStatus | select RealTimeProtectionEnabled, AMServiceEnabled

# 2. AppLocker
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# 3. PowerShell language mode
$ExecutionContext.SessionState.LanguageMode

# 4. LAPS
Find-LAPSDelegatedGroups
Find-AdmPwdExtendedRights
Get-LAPSComputers
```
> Run this checklist immediately after gaining a foothold. These four checks tell you what tools you can safely use. `Get-MpComputerStatus` shows Defender status. `Get-AppLockerPolicy` shows application allow/deny rules. `LanguageMode` tells you if PowerShell is restricted. The LAPS (Local Administrator Password Solution) commands check if local admin passwords are managed and whether you can read them.

---

## Windows Defender

```powershell
Get-MpComputerStatus
# RealTimeProtectionEnabled : True  → Defender active, will block PowerView etc.
```
> Checks whether Windows Defender is running and actively scanning. `True` means Defender will likely block PowerView and similar tools. Switch to in-memory execution or C# binaries in that case.

**If enabled:** Run tools from memory, use obfuscation, or switch to C# binaries (SharpView, SharpHound).

---

## AppLocker

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
# Action: Deny on PowerShell = blocked at default path
```
> Returns the active AppLocker rules. Look for `Deny` actions on PowerShell or executable paths. If PowerShell is blocked at the default path, try the bypass paths listed below.

**Common bypass paths AppLocker misses:**
```
%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
PowerShell_ISE.exe
```

Admins group (`S-1-5-32-544`) typically has Allow All → if local admin, you're fine.

---

## PowerShell Language Mode

```powershell
$ExecutionContext.SessionState.LanguageMode
# FullLanguage      → no restrictions
# ConstrainedLanguage → blocks COM objects, limits .NET — breaks PowerView etc.
```
> A single-line check. `FullLanguage` means PowerShell runs normally. `ConstrainedLanguage` blocks many advanced features that PowerView relies on. In that case, switch to C# tools.

**If ConstrainedLanguage:** Switch to C# tools (SharpView, SharpHound, etc.)

---

## LAPS

LAPS randomizes local admin passwords — prevents lateral movement via password reuse.

```powershell
# Who can read LAPS passwords per OU
Find-LAPSDelegatedGroups

# Users with All Extended Rights (can read LAPS passwords)
Find-AdmPwdExtendedRights

# List computers + LAPS passwords (if you have access)
Get-LAPSComputers
```
> `Find-LAPSDelegatedGroups` shows which groups can read LAPS passwords per Organizational Unit (OU). `Find-AdmPwdExtendedRights` finds any user or group with the "All Extended Rights" permission on a computer object — that permission lets them read the LAPS-managed password. `Get-LAPSComputers` lists computers and their current passwords if you have read access.

**Key:** "All Extended Rights" on a computer object = can read LAPS password. Accounts that joined the computer to the domain get this automatically — check for non-obvious read access.

If `Get-LAPSComputers` shows cleartext passwords → you have local admin on those machines.

---

## What to Do Based on Results

| Finding | Action |
|---------|--------|
| Defender enabled | Use in-memory execution, C# tools, obfuscation |
| AppLocker blocks PS | Try `SysWOW64\powershell.exe` or PowerShell_ISE |
| ConstrainedLanguage | Switch to SharpView, SharpHound, etc. |
| LAPS present | Check extended rights — may expose local admin passwords |
| No LAPS | Local admin password reuse spray is viable |

---

## Exam Notes

- Run security controls check right after foothold — informs all tool choices
- No LAPS + local admin creds = spray subnet with `--local-auth`
- LAPS present → Find-AdmPwdExtendedRights → may find a user who can read passwords
- Constrained Language Mode → C# tools only
