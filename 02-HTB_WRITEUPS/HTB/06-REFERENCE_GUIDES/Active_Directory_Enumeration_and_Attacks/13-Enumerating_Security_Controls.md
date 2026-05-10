# Section 13 — Enumerating Security Controls

## Why This Matters

Security controls affect what tools you can use and how. Enumerate them early after gaining a foothold so you can plan your approach — avoid blocked tools, use LOLBins, or find bypasses.

---

## Windows Defender

```powershell
Get-MpComputerStatus

# Key field to check:
# RealTimeProtectionEnabled : True  → Defender is active, will block PowerView etc.
```

If enabled — tools like PowerView will be caught. Look for bypass techniques or run from memory.

---

## AppLocker

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

**What to look for:**
- `Action: Deny` on PowerShell → blocked at default path
- Common bypass: AppLocker blocks `%SYSTEM32%\WindowsPowerShell\v1.0\powershell.exe` but forgets:
  - `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`
  - `PowerShell_ISE.exe`
- Admins group (`S-1-5-32-544`) typically has `Allow All` → if you're local admin you're fine

---

## PowerShell Constrained Language Mode

```powershell
$ExecutionContext.SessionState.LanguageMode

# FullLanguage     → no restrictions
# ConstrainedLanguage → blocks COM objects, limits .NET types, breaks many PS tools
```

If `ConstrainedLanguage` — PowerView and many other tools won't work as expected. Need to find a bypass or use C# tools instead.

---

## LAPS (Local Administrator Password Solution)

LAPS randomizes and rotates local admin passwords — prevents lateral movement via local admin hash reuse.

### Enumerate with LAPSToolkit

```powershell
# Who can read LAPS passwords (delegated groups per OU)
Find-LAPSDelegatedGroups

# Users/groups with All Extended Rights (can read LAPS passwords)
Find-AdmPwdExtendedRights

# List computers with LAPS — shows cleartext password if you have access
Get-LAPSComputers
```

**Key insight:** "All Extended Rights" on a computer object = can read LAPS password. Accounts that joined a computer to the domain get this right automatically — worth checking for non-obvious read access.

If `Get-LAPSComputers` returns passwords in cleartext → you have local admin access to those machines.

---

## Quick Security Posture Checklist (run after foothold)

```powershell
# 1. Defender status
Get-MpComputerStatus | select RealTimeProtectionEnabled, AMServiceEnabled

# 2. AppLocker rules
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# 3. PowerShell language mode
$ExecutionContext.SessionState.LanguageMode

# 4. LAPS presence and read access
Find-LAPSDelegatedGroups
Find-AdmPwdExtendedRights
Get-LAPSComputers
```

---

## Exam Notes

- Always enumerate security controls right after gaining a foothold — informs all subsequent tool choices
- Defender on → use in-memory execution, obfuscation, or C# alternatives to PowerShell tools
- AppLocker blocking PS → try alternate PS paths or ISE
- Constrained Language Mode → switch to C# tools (SharpView, SharpHound, etc.)
- LAPS = look for accounts with extended rights → may expose local admin passwords in cleartext
- No interactive component in this section — reference only
