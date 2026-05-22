# Section 22 — Other Files

> **Lab: yes** — Same target. Find cleartext password for bob_adm user by searching the filesystem.

**Core principle:** Credentials hide everywhere on Windows systems — Sticky Notes databases, pagefile, IIS logs, backup SAM files, user documents, RDP files, and more. Manual search skills are essential because automated tools don't catch everything.

---

## Manual search commands

### Search file contents for "password"

```cmd
findstr /SI /M "password" *.xml *.ini *.txt *.config
```
> `/S` = recurse, `/I` = case-insensitive, `/M` = filenames only. Fast broad search.

```cmd
findstr /si password *.xml *.ini *.txt *.config
```
> Same but shows matching lines (not just filenames).

```cmd
findstr /spin "password" *.*
```
> `/P` = skip binary files, `/N` = show line numbers. Searches ALL file types.

### PowerShell content search

```powershell
select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password
```

### Search for interesting file extensions

```cmd
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
```

```cmd
where /R C:\ *.config
```

```powershell
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
```

---

## Sticky Notes

Users store passwords in Sticky Notes — it's actually a SQLite database.

**Location:**
```
C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
```

### Check if Sticky Notes DB exists

```powershell
ls C:\Users\*\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
```

### Query with PSSQLite (on target)

```powershell
Import-Module .\PSSQLite.psd1
$db = 'C:\Users\<USER>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
```

### Extract with strings (on attacker box after transfer)

```bash
strings plum.sqlite-wal | grep -i password
```
> The `-wal` (Write-Ahead Log) file often contains the most recent data, including notes not yet committed to the main DB.

---

## Other credential locations

| File / Location | What to look for |
|----------------|-----------------|
| `%WINDIR%\repair\sam` | Backup SAM hive |
| `%WINDIR%\repair\system` | Backup SYSTEM hive |
| `%WINDIR%\repair\security` | Backup SECURITY hive |
| `%WINDIR%\debug\NetSetup.log` | Domain join credentials |
| `%WINDIR%\iis6.log` | IIS credentials |
| `%WINDIR%\system32\config\*.sav` | Saved registry hives |
| `%USERPROFILE%\ntuser.dat` | User registry hive |
| `%WINDIR%\System32\drivers\etc\hosts` | Internal hostnames |
| `C:\ProgramData\Configs\*` | Application configs |
| `%WINDIR%\system32\CCM\logs\*.log` | SCCM logs |
| `%SYSTEMDRIVE%\pagefile.sys` | Memory dump — may contain plaintext creds |
| `.kdbx` files | KeePass databases |
| `.vmdk`, `.vhdx` files | Virtual disks — mount and extract SAM |
| `.ppk` files | PuTTY private keys |
| `.rdp` files | May contain saved credentials |

---

## Network share hunting (AD environments)

```bash
# From Linux with Snaffler or manspider
snaffler -s -o snaffler_output.txt
manspider <TARGET> -u <USER> -p <PASS> -e kdbx vmdk vhdx ppk rdp
```
> Snaffler crawls accessible shares for high-value file types. Common finds: KeePass DBs, SSH keys, config files with credentials, password documents.

---

## Lab walkthrough

**Target:** `<TARGET_IP>` (ACADEMY-WINLPE-WS01)
**Creds:** `htb-student` / `HTB_@cademy_stdnt!`
**Goal:** Find cleartext password for `bob_adm`

### Attack chain (editable)

```
┌─────────────────────────────────────────────────────────┐
│ VARIABLES — edit these for your instance                │
├─────────────────────────────────────────────────────────┤
│ TARGET_IP    = <TARGET_IP>                              │
│ USERNAME     = htb-student                              │
│ PASSWORD     = HTB_@cademy_stdnt!                       │
│ TARGET_USER  = bob_adm                                  │
└─────────────────────────────────────────────────────────┘

1. RDP as htb-student

2. Search for bob_adm in files
   findstr /spin "bob_adm" C:\Users\*.txt C:\Users\*.xml C:\Users\*.ini C:\Users\*.config

3. Check Sticky Notes DB
   ls C:\Users\*\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite

4. If found, query it
   cd C:\Tools\PSSQLite
   Import-Module .\PSSQLite.psd1
   $db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
   Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap

5. Check PowerShell history for all users
   foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}

6. Search broadly
   findstr /spin "password" C:\Users\htb-student\Documents\*.*
   findstr /spin "bob_adm" C:\*.*
```

---

## Key takeaways

- **Sticky Notes is a SQLite database.** Always check for `plum.sqlite` — users store passwords there constantly.
- **The `-wal` file is often more valuable than the main `.sqlite`.** It contains uncommitted writes.
- **Search for the target username, not just "password."** `findstr /spin "bob_adm"` may find credentials in unexpected files.
- **Network shares in AD environments are goldmines.** Use Snaffler or manspider to crawl them.
- **Check ALL user profiles' PowerShell history** after escalating. Re-run the foreach loop as admin.
- **Virtual disk files (.vmdk, .vhdx) can contain entire OS images.** Mount offline → extract SAM → crack hashes.
- **Automated tools miss things.** Manual search with `findstr` and `Get-ChildItem` catches files in non-standard locations.
