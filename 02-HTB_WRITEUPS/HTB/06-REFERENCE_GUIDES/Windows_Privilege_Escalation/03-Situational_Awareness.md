# Section 3 — Situational Awareness

> **Lab: yes** — RDP to target, enumerate network info and AppLocker policies.

**Core principle:** Before escalating, orient yourself. Understand the network position (dual-homed? domain-joined?), what protections are active (AV/EDR/AppLocker), and what lateral movement opportunities exist. This informs which tools you can use and what paths are available.

---

## Network enumeration

### Interfaces, IPs, DNS

```cmd
ipconfig /all
```
> Look for: multiple NICs (dual-homed = pivot opportunity), DNS suffix (domain name), DNS servers (often the DC), DHCP vs static (static = server/infrastructure role).

**What to extract:**
| Field | Why it matters |
|-------|---------------|
| Multiple adapters | Host bridges two networks — pivot candidate |
| DNS Suffix Search List | Reveals AD domain name |
| DNS Server IPs | Often points to Domain Controller |
| Default Gateway | Network segmentation clues |
| DHCP vs Static | Static = likely a server, higher value target |

### ARP cache

```cmd
arp -a
```
> Shows hosts this machine has recently communicated with. Look for other live hosts, especially ones admins may RDP/WinRM into. Cross-reference with lateral movement targets after obtaining creds.

### Routing table

```cmd
route print
```
> Reveals all networks the host can reach. Multiple routes = access to segmented networks (management VLANs, database subnets, etc.) that your attack machine can't reach directly.

**Reading the output:**
- `0.0.0.0` destination = default route (internet-bound traffic)
- Specific subnets with `On-link` = directly connected networks
- Multiple default routes with different interfaces = dual-homed

---

## Enumerating protections

### Windows Defender status

```powershell
Get-MpComputerStatus
```
> Key fields to check:
> - `RealTimeProtectionEnabled` — if True, tools will get caught on disk
> - `AntivirusEnabled` — overall AV status
> - `BehaviorMonitorEnabled` — behavioral detection (catches in-memory attacks)
> - `IoavProtectionEnabled` — scans downloaded files
> - `OnAccessProtectionEnabled` — scans files when accessed

If Defender is active, you'll need to work around it (AMSI bypass, obfuscation, manual techniques) or use living-off-the-land binaries (LOLBins).

### AppLocker rules

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
> Enumerates what's allowed and blocked. Default rules typically:
> - Allow everything in `%PROGRAMFILES%\*` and `%WINDIR%\*` for Everyone
> - Allow all files for local Administrators (`S-1-5-32-544`)
> - May block specific executables or scripts for non-admin users

### Test a specific binary against AppLocker

```powershell
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
```
> Returns `Allowed` or `Denied`. Test your tools before uploading — saves time if they'd just get blocked.

**Common AppLocker bypasses (when you can't run blocked binaries):**
- Execute from `C:\Windows\Temp` (sometimes not covered by rules)
- Use alternate scripting hosts: `mshta.exe`, `cscript.exe`, `wscript.exe`
- DLL-based execution if DLL rules aren't enforced
- `MSBuild.exe` or `InstallUtil.exe` for C# payload execution

---

## Situational awareness checklist (run on every new Windows host)

```cmd
:: Network position
ipconfig /all
arp -a
route print
netstat -ano

:: Domain context
systeminfo | findstr /B /C:"Domain"
nltest /dclist:%USERDOMAIN% 2>nul
nslookup %LOGONSERVER:~2%.%USERDNSDOMAIN% 2>nul
```
> `systeminfo | findstr Domain` tells you if it's domain-joined. `nltest /dclist` finds DCs. `nslookup` on the logon server confirms DC IP.

```powershell
# Protections
Get-MpComputerStatus | select RealTimeProtectionEnabled, AntivirusEnabled, BehaviorMonitorEnabled
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
Get-Service | where {$_.DisplayName -like "*defend*" -or $_.DisplayName -like "*endpoint*" -or $_.DisplayName -like "*crowd*" -or $_.DisplayName -like "*carbon*" -or $_.DisplayName -like "*sentinel*"}
```
> Check for third-party EDR services (CrowdStrike Falcon, Carbon Black, SentinelOne, Cylance) — they're harder to bypass than Defender.

---

## Lab walkthrough

**Target:** `10.129.43.43` (ACADEMY-WINLPE-SRV01)
**Creds:** `htb-student` / `HTB_@cademy_stdnt!`

```bash
xfreerdp /v:10.129.43.43 /u:htb-student /p:'HTB_@cademy_stdnt!' /cert:ignore /dynamic-resolution +clipboard
```

### Question 1 — What is the IP address of the other NIC attached to the target host?

```cmd
ipconfig /all
```
> Look for a second Ethernet adapter with a different subnet. The host is dual-homed — one NIC on the HTB lab network (10.129.x.x), and another on an internal network.

### Question 2 — What executable other than cmd.exe is blocked by AppLocker?

```powershell
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -User Everyone
```
> Alternatively, enumerate all deny rules:
```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections | where {$_.Action -eq "Deny"}
```
> Or test common targets:
```powershell
"cmd.exe","powershell.exe","powershell_ise.exe","wscript.exe","cscript.exe","mshta.exe" | % { Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path "C:\Windows\System32\$_" -User Everyone }
```

---

## Lab observations & attack chain (WINLPE-SRV01)

**What we found:**
- **Dual-homed:** Ethernet1 on `172.16.20.0/23` (internal), Ethernet0 on `10.129.x.x` (lab/VPN). This host bridges two networks.
- **Windscribe VPN adapter** present (disconnected) — indicates VPN software installed, potential named pipe attack vector (see Section 5).
- **AppLocker:** `cmd.exe` and `powershell_ise.exe` blocked for Everyone. Regular `powershell.exe` is allowed. Admins can run anything.
- **No effective Deny rules from domain** (only Local policy has the blocks).

**Attack chain implications:**
```
Situational Awareness findings:
├── Dual-homed (172.16.20.0/23) → after privesc, pivot to internal network
├── AppLocker blocks cmd.exe → use PowerShell for all enumeration
├── Windscribe VPN installed → check named pipe permissions (Section 5)
└── Server 2016 Build 14393 → check for kernel exploits, potato attacks
```

**What you'd do next on a real engagement:**
1. Since cmd.exe is blocked, operate entirely in PowerShell
2. Note the 172.16.20.0/23 network for post-privesc pivoting
3. Check if Windscribe's named pipe is exploitable (CVE-2020-12749)
4. Continue to initial enumeration (Section 4) to understand user context

---

## Key takeaways

- **Dual-homed hosts are pivot goldmines.** A second NIC means access to a network segment your attacker machine can't reach. Escalate here → pivot there.
- **ARP cache reveals relationships.** Recent entries show who connects to this host — likely admin workstations or other servers worth targeting.
- **Know protections before acting.** Running WinPEAS into active Defender = instant detection. Check first, adapt second.
- **AppLocker != security.** Default rules are often weak. If `%WINDIR%\*` is allowed for Everyone, your tools can run from `C:\Windows\Temp`. Test before assuming you're blocked.
