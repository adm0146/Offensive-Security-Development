# Section 13 — Enumerating Security Controls

> Run this immediately after gaining a foothold — determines what tools you can use.

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

---

## Windows Defender

```powershell
Get-MpComputerStatus
# RealTimeProtectionEnabled : True  → Defender active, will block PowerView etc.
```

**If enabled:** Run tools from memory, use obfuscation, or switch to C# binaries (SharpView, SharpHound).

---

## AppLocker

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
# Action: Deny on PowerShell = blocked at default path
```

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
