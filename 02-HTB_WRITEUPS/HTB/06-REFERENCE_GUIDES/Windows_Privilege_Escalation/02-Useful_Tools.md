# Section 2 — Useful Tools

> **No lab / no questions** — reference section. Bookmark this and come back when you need to pick the right tool for a situation.

---

## Tool reference table

| Tool | Language | What it does | Where to get it |
|------|----------|--------------|-----------------|
| **Seatbelt** | C# | Wide-ranging local privesc checks (services, tokens, creds, registry, etc.) | `~/tools/SharpCollection/NetFramework_4.7_x64/Seatbelt.exe` |
| **WinPEAS** | C#/Batch | Automated enumeration — searches for all known privesc paths | `~/Downloads/winPEASx64.exe` |
| **PowerUp** | PowerShell | Finds misconfigs (services, unquoted paths, DLL hijack, AlwaysInstallElevated, etc.) and can auto-exploit some | `/usr/share/powersploit/Privesc/PowerUp.ps1` |
| **SharpUp** | C# | C# port of PowerUp — no PowerShell needed, evades some detections | `~/tools/SharpCollection/NetFramework_4.7_x64/SharpUp.exe` |
| **JAWS** | PowerShell 2.0 | Lightweight privesc enumeration — works on older systems where newer PS isn't available | GitHub |
| **SessionGopher** | PowerShell | Finds & decrypts saved sessions for PuTTY, WinSCP, SuperPuTTY, FileZilla, RDP | GitHub |
| **Watson** | C# (.NET) | Enumerates missing KBs, suggests kernel/OS exploits | GitHub |
| **LaZagne** | Python (compiled) | Extracts stored passwords from browsers, DBs, Git, email, sysadmin tools, WiFi, Windows vault | GitHub |
| **WES-NG** | Python | Parses `systeminfo` output → lists vulnerabilities + exploits (XP through Win10/Server) | Run on attacker box with `systeminfo` output |
| **Sysinternals Suite** | Native Windows | AccessChk (permissions), PipeList (named pipes), PsService (service info), Process Monitor, etc. | Microsoft / pre-staged in labs at `C:\Tools` |

---

## Tools on this Kali box (ready to transfer)

```bash
# Pre-compiled SharpCollection (.NET 4.7 x64)
ls ~/tools/SharpCollection/NetFramework_4.7_x64/
# Includes: Seatbelt.exe, SharpUp.exe, Rubeus.exe, SharpHound.exe, Certify.exe, etc.

# WinPEAS
ls ~/Downloads/winPEASx64.exe

# PowerUp (PowerSploit)
ls /usr/share/powersploit/Privesc/PowerUp.ps1

# Windows binaries (nc, wget, plink)
ls /usr/share/windows-resources/binaries/
```
> These are your transfer candidates. Host with `python3 -m http.server 8000` and pull from the target with `iwr` or `certutil`.

---

## Safe upload location on target

```powershell
C:\Windows\Temp
```
> `BUILTIN\Users` has write access here. Always a safe bet when you don't know what directories your user can write to.

---

## When to use tools vs. manual enumeration

| Situation | Approach |
|-----------|----------|
| Full tool access, time-constrained | Run WinPEAS/Seatbelt first, validate findings manually |
| Air-gapped / no tool upload | Manual cmd.exe + PowerShell only (this module teaches how) |
| AV/EDR active | Manual first; if tools needed, compile from source or obfuscate |
| Gold image audit (non-evasive) | Full tool suite — WinPEAS + Seatbelt + PowerUp for coverage |
| Validating a single vector | Targeted manual check — don't waste time on full enum |

---

## AV/EDR detection reality

Most privesc tools are **heavily signatured**:

- LaZagne v2.4.3 → **47/70** detections on VirusTotal
- Pre-compiled Seatbelt/SharpUp → flagged by most EDR products
- WinPEAS → detected by Defender, Cylance, Carbon Black, CrowdStrike

**Mitigations (out of scope for this module but relevant on exams):**
- Compile from source with modifications (rename functions, strip comments)
- Encrypt/pack the binary
- Use .NET reflection / in-memory execution to avoid dropping to disk
- Obfuscate PowerShell (AMSI bypass + encoded commands)

> For this module: assume Defender is disabled / exclusions set. The focus is on *finding and exploiting vectors*, not AV evasion.

---

## Key takeaways

- **Tools accelerate enumeration but don't replace understanding.** Know what each tool checks so you can replicate it manually when tools aren't an option.
- **False positives happen.** PowerUp may flag a service path issue that you can't actually exploit due to ACLs. Always validate.
- **False negatives happen too.** WinPEAS may miss a custom scheduled task or unusual registry permission. Manual checks catch what automation doesn't.
- **Information overload is real.** WinPEAS dumps thousands of lines. Learn to skim for the high-value sections (service permissions, stored creds, AlwaysInstallElevated, token privileges) and ignore the noise.
- **Compile your own for client work.** Pre-compiled binaries from GitHub are fine for labs but inappropriate for real engagements — you can't verify they're clean, and they're immediately flagged.
