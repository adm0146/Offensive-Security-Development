# Section 21 — Credential Hunting

> **Lab: yes** — Two questions: (1) Find a password in a file on the filesystem, (2) RDP as bob and decrypt PowerShell credentials from pass.xml.

**Core principle:** Credentials are scattered across Windows systems in plaintext config files, PowerShell history, unattended install files, browser data, and encrypted PowerShell credential objects. Always search for these during enumeration — a single password can skip hours of exploitation.

---

## Where to find credentials

| Location | What to look for |
|----------|-----------------|
| Config files (.txt, .ini, .cfg, .config, .xml) | Plaintext passwords in app configs |
| web.config (IIS) | Database connection strings, app credentials |
| Unattend.xml / sysprep files | Auto-logon passwords (plaintext or base64) |
| PowerShell history | Commands with credentials passed as arguments |
| PowerShell credential files (.xml) | DPAPI-encrypted credentials (decryptable as same user) |
| Chrome/browser custom dictionaries | Passwords added to dictionary to avoid red underline |
| Sticky Notes | Users store passwords in Sticky Notes app |
| Saved browser credentials | Chrome, Firefox, Edge saved passwords |
| Registry (autologon) | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` |
| WiFi profiles | `netsh wlan show profile name="X" key=clear` |
| Scheduled tasks | May reference scripts containing credentials |

---

## Search commands

### Broad file content search

```powershell
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
```
> `/S` = recurse subdirectories. `/I` = case-insensitive. `/M` = print only filenames (not matching lines). Searches all common config file types for the word "password."

### Search specific file types

```powershell
findstr /SIM /C:"password" C:\*.txt C:\*.xml C:\*.config
```
> Search from C:\ root for broader coverage. Can be slow on large filesystems.

```powershell
Get-ChildItem -Path C:\ -Recurse -Include *.txt,*.ini,*.cfg,*.config,*.xml -ErrorAction SilentlyContinue | Select-String -Pattern "password" -CaseSensitive:$false
```
> PowerShell equivalent — more flexible filtering and output formatting.

### Unattended install files

```cmd
dir /s /b C:\unattend.xml C:\sysprep.xml C:\sysprep.inf C:\unattended.xml 2>nul
```
> Common locations: `C:\Windows\Panther\`, `C:\Windows\System32\Sysprep\`, `C:\Windows\Panther\Unattend\`. Passwords may be plaintext or base64.

### IIS web.config

```cmd
dir /s /b C:\inetpub\web.config 2>nul
dir /s /b C:\inetpub\wwwroot\web.config 2>nul
```
> Default IIS location, but may exist in subdirectories for virtual applications.

---

## PowerShell history

### Default history file path

```
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### Read current user's history

```powershell
gc (Get-PSReadLineOption).HistorySavePath
```
> Shows every PowerShell command the user has run. Look for commands with `-p`, `-Password`, `/p:`, credential parameters.

### Read ALL users' history (needs file access)

```powershell
foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
```
> Iterates all user profiles. As a standard user, you can only read profiles you have access to. Re-run after getting admin — you'll see more.

### What to grep for in history

```
password, -p, /p:, -Password, ConvertTo-SecureString,
Export-Clixml, Import-Clixml, Get-Credential, net use,
runas, cmdkey, -Credential, PSCredential
```

---

## Chrome custom dictionary

```powershell
gc 'C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
```
> Users sometimes type passwords in browser fields. Chrome underlines unknown words — users add them to dictionary. The password ends up in this plaintext file.

---

## PowerShell credential files (DPAPI)

### How they work

```powershell
# Admin creates encrypted credential file:
Get-Credential | Export-Clixml -Path 'C:\scripts\pass.xml'
```
> Saves username + password encrypted with DPAPI. **Only decryptable by the same user on the same machine.**

### Decrypt (must be running as the user who created it)

```powershell
$credential = Import-Clixml -Path 'C:\scripts\pass.xml'
$credential.GetNetworkCredential().username
$credential.GetNetworkCredential().password
```
> If you can run commands as the user who created the file (or abuse DPAPI), this gives plaintext credentials.

---

## Other credential locations

### Registry autologon

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
```
> Systems configured for auto-logon store credentials in the registry in plaintext.

### Saved Windows credentials

```cmd
cmdkey /list
```
> Shows saved credentials in Windows Credential Manager. If entries exist, `runas /savecred /user:<USER> cmd.exe` may work without a password.

### WiFi passwords

```cmd
netsh wlan show profiles
netsh wlan show profile name="<SSID>" key=clear
```
> Displays saved WiFi passwords in plaintext.

---

## Lab walkthrough

**Target:** `<TARGET_IP>` (ACADEMY-WINLPE-WS01)
**Access:** RDP

### Attack chain (editable)

```
┌─────────────────────────────────────────────────────────┐
│ VARIABLES — edit these for your instance                │
├─────────────────────────────────────────────────────────┤
│ TARGET_IP    = <TARGET_IP>                              │
│ USER_1       = htb-student                              │
│ PASS_1       = HTB_@cademy_stdnt!                       │
│ USER_2       = bob                                      │
│ PASS_2       = Str0ng3ncryptedP@ss!                     │
└─────────────────────────────────────────────────────────┘

QUESTION 1: Find a password in a file
──────────────────────────────────────
1. RDP as htb-student
   xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:<TARGET_IP> /u:htb-student /p:'HTB_@cademy_stdnt!'

2. Search the filesystem for passwords
   findstr /SIM /C:"password" C:\Users\*.txt C:\Users\*.ini C:\Users\*.cfg C:\Users\*.config C:\Users\*.xml

3. Check PowerShell history
   foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}

4. Check Chrome dictionary
   gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt'

5. Check unattended files
   dir /s /b C:\Windows\Panther\unattend.xml 2>nul
   dir /s /b C:\unattend.xml 2>nul

QUESTION 2: Decrypt PowerShell credentials as bob
──────────────────────────────────────────────────
6. RDP as bob
   xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:<TARGET_IP> /u:bob /p:'Str0ng3ncryptedP@ss!'

7. Decrypt pass.xml
   $credential = Import-Clixml -Path 'C:\scripts\pass.xml'
   $credential.GetNetworkCredential().username
   $credential.GetNetworkCredential().password

8. Read the flag
   type C:\Users\bob\Desktop\flag.txt
```

---

## Key takeaways

- **Credential hunting should be one of your FIRST steps** after gaining access. A found password can save hours of exploitation.
- **PowerShell history is a goldmine.** Admins constantly pass credentials on the command line — `wevtutil`, `net use`, `runas`, scripts.
- **Read ALL users' history after escalating.** Standard user access limits what profiles you can read. Re-check after admin.
- **DPAPI credential files require the creating user's context.** If you can run as that user (or dump DPAPI keys), you get plaintext.
- **Chrome custom dictionary is an overlooked source.** Users unknowingly save passwords there.
- **Search broadly:** `findstr /SIM /C:"password"` across all config file types. Also search for `secret`, `credential`, `apikey`, `connectionstring`.
- **Unattend.xml files should be deleted after install** but often aren't. Check `C:\Windows\Panther\` and Sysprep directories.
