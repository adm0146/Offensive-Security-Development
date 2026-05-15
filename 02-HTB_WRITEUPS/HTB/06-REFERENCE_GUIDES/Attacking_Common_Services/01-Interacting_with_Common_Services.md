# 01 — Interacting with Common Services

## Overview

Attacking a service requires understanding its purpose, how to interact with it, and what tools are available. This section covers the most common services encountered in enterprise environments — SMB, Email, and Databases — and how to interact with them from both Windows and Linux attack hosts.

---

## File Sharing Services

| Service | Protocol | Common Use |
|---------|----------|------------|
| **SMB** | TCP 445 | Windows network file shares |
| **NFS** | TCP/UDP 2049 | Linux/Unix network file shares |
| **FTP** | TCP 21 | File transfer (unauthenticated or authenticated) |
| **TFTP** | UDP 69 | Trivial file transfer (no auth) |
| **SFTP** | TCP 22 | Secure file transfer over SSH |
| **Cloud (OneDrive, S3, etc.)** | HTTPS | Third-party cloud storage |

> Focus for this module is **internal services**, though cloud services synced locally also apply.

---

## SMB — Windows Interaction

### GUI Access
Press `[WINKEY] + [R]` and enter the UNC path:
```
\\192.168.220.129\Finance\
```
- Anonymous auth → content displays directly
- Restricted share → Windows Security credential prompt appears

---

### CMD — Key Commands

#### List share contents
```cmd
dir \\192.168.220.129\Finance\
```
> Lists files in the remote SMB share using a UNC path. Replace the IP and share name with your target.

#### Map share to drive letter
```cmd
net use n: \\192.168.220.129\Finance
```
> Maps the share to drive letter `N:` for easier browsing. Change `n:` to any free drive letter.

#### Map share with credentials
```cmd
net use n: \\192.168.220.129\Finance /user:plaintext Password123
```
> `/user:` specifies the username, followed by the password. Replace with valid credentials. After mapping, use `n:` like a local drive.

#### Count all files in share
```cmd
dir n: /a-d /s /b | find /c ":\"
```
> `/a-d` lists files only (no directories), `/s` recurses subdirectories, `/b` outputs bare filenames. `find /c` counts matching lines. Useful to know the scope before searching.

| Flag | Meaning |
|------|---------|
| `/a-d` | Attributes — exclude directories (files only) |
| `/s` | Search recursively through subdirectories |
| `/b` | Bare format (no headers or summary) |
| `find /c ":\\"` | Count lines matching the pattern |

#### Search for credential-related filenames
```cmd
dir n:\*cred* /s /b
dir n:\*secret* /s /b
dir n:\*password* /s /b
dir n:\*users* /s /b
dir n:\*key* /s /b
```
> Wildcards (`*cred*`) match any filename containing the keyword. `/s` recurses all subdirectories. Run all of these — credential files may have unexpected names.

#### Search file extensions (source code hunting)
```cmd
dir n:\*.cs /s /b
dir n:\*.php /s /b
dir n:\*.config /s /b
```
> Searches for source code files by extension. Config files often contain hardcoded credentials. Add more extensions as needed (`.xml`, `.ini`, `.yaml`).

#### Search file contents with findstr
```cmd
findstr /s /i cred n:\*.*
findstr /s /i password n:\*.*
```
> `/s` recurses subdirectories, `/i` is case-insensitive. Searches inside all files for credential strings. Slower than filename search but finds embedded passwords.

| `findstr` Flag | Meaning |
|----------------|---------|
| `/s` | Search subdirectories |
| `/i` | Case-insensitive |

---

### PowerShell — Key Commands

#### List share contents
```powershell
Get-ChildItem \\192.168.220.129\Finance\
```
> PowerShell equivalent of `dir`. Use a UNC path directly. Alias `gci` works too.

#### Map share to drive (no creds)
```powershell
New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"
```
> Creates a mapped drive `N:` accessible in the current PowerShell session. Replace the IP and share name with your target.

#### Map share with credentials (PSCredential object)
```powershell
$username = 'plaintext'
$password = 'Password123'
$secpassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred
```
> PowerShell requires credentials as a `PSCredential` object — you can't just pass plaintext. `ConvertTo-SecureString -AsPlainText -Force` converts a plain string to the required type.

#### Count all files
```powershell
N:
(Get-ChildItem -File -Recurse | Measure-Object).Count
```
> Change to the `N:` drive first, then run the count. `-File` filters out directories, `-Recurse` searches all subdirectories. `.Count` extracts the number from the `Measure-Object` output.

#### Search filenames containing pattern
```powershell
Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
Get-ChildItem -Recurse -Path N:\ -Include *password* -File
```
> `-Include` filters by filename pattern. Change the wildcard to target different keywords.

#### Search file contents (like grep)
```powershell
Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
Get-ChildItem -Recurse -Path N:\ | Select-String "password" -List
```
> Pipes all files to `Select-String` which searches inside each file. `-List` shows only the first match per file (faster). Equivalent to Linux `grep -r`.

| PowerShell Cmdlet | CMD Equivalent |
|-------------------|----------------|
| `Get-ChildItem` / `gci` | `dir` |
| `New-PSDrive` | `net use` |
| `Select-String` | `findstr` |

---

## SMB — Linux Interaction

### Install required package
```bash
sudo apt install cifs-utils
```
> Required to mount SMB/CIFS shares on Linux. Only needs to be installed once.

### Mount SMB share (inline credentials)
```bash
sudo mkdir /mnt/Finance
sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
```
> `-t cifs` specifies the SMB filesystem type. `-o` passes mount options including credentials. Replace the IP, share name, username, and password with your target's values. `domain=.` means local authentication (no domain).

### Mount SMB share (credential file)
```bash
mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
```
> Avoids putting credentials on the command line (visible in `ps`). Create the credential file with `username=`, `password=`, and `domain=` lines. Replace the path with the actual credential file location.

**Credential file format:**
```
username=plaintext
password=Password123
domain=.
```
> Each field goes on its own line. Set `domain=.` for local accounts or enter the domain name for domain accounts. Pass the file path to `-o credentials=`.

### Search once mounted

#### Find files by name
```bash
find /mnt/Finance/ -name *cred*
find /mnt/Finance/ -name *password*
```
> Searches for files whose names contain the keyword. Replace `/mnt/Finance/` with your mount point and adjust the pattern as needed.

#### Search file contents
```bash
grep -rn /mnt/Finance/ -ie cred
grep -rn /mnt/Finance/ -ie password
```
> `-r` recurses directories, `-n` shows line numbers, `-i` is case-insensitive, `-e` specifies the search pattern. Searches inside every file under the mount point.

| `grep` Flag | Meaning |
|-------------|---------|
| `-r` | Recursive |
| `-n` | Show line numbers |
| `-i` | Case-insensitive |
| `-e` | Pattern to match |

---

## Email Services

| Protocol | Purpose | Default Ports |
|----------|---------|---------------|
| **SMTP** | Send mail | TCP 25, 587 (STARTTLS), 465 (SMTPS) |
| **IMAP** | Receive mail (sync/server-side) | TCP 143, 993 (IMAPS) |
| **POP3** | Receive mail (download/local) | TCP 110, 995 (POP3S) |

### Linux Mail Client — Evolution
```bash
sudo apt-get install evolution
# If sandbox error on launch:
export WEBKIT_FORCE_SANDBOX=0 && evolution
```
> Install Evolution once, then launch it. If it crashes with a sandbox error, set `WEBKIT_FORCE_SANDBOX=0` first. Configure it to connect to the target SMTP/IMAP/POP3 server for email enumeration.

**Connection tips:**
- Use domain name or IP for mail server
- SMTPS/IMAPS → use TLS on dedicated port
- SMTP/IMAP → use STARTTLS after connecting
- Use "Check for Supported Types" to confirm auth methods

---

## Databases

### Types Relevant to This Module

| Type | Examples |
|------|---------|
| **SQL (Relational)** | MySQL, MSSQL, PostgreSQL |
| **NoSQL** | MongoDB, Redis, Cassandra |

### Three Interaction Methods

| Method | Examples |
|--------|---------|
| **Command-line utilities** | `mysql`, `sqsh`, `sqlcmd` |
| **Programming languages** | Python, PHP, C# |
| **GUI applications** | HeidiSQL, MySQL Workbench, SSMS, dbeaver |

---

### MSSQL Interaction

#### Linux (sqsh)
```bash
sqsh -S 10.129.20.13 -U username -P Password123
```
> `-S` is the server address, `-U` is username, `-P` is password. After connecting, type SQL queries and end with `go` to execute. Replace the IP and credentials with your target's.

#### Windows (sqlcmd)
```cmd
sqlcmd -S 10.129.20.13 -U username -P Password123
```
> Windows-native MSSQL client. Same flags as `sqsh`. Run queries and use `GO` to execute. Replace the server IP and credentials with your target's.

---

### MySQL Interaction

#### Linux
```bash
mysql -u username -pPassword123 -h 10.129.20.13
```
> `-u` is the username, `-p` followed directly by the password (no space), `-h` is the remote host. Replace all three values with your target's. Omit the password after `-p` to be prompted securely.

#### Windows
```cmd
mysql.exe -u username -pPassword123 -h 10.129.20.13
```
> Same syntax as Linux. No space between `-p` and the password. Run from a Windows host with MySQL client tools installed.

> Note: No space between `-p` and the password.

---

### GUI — dbeaver (Multi-platform)

Supports: MSSQL, MySQL, PostgreSQL, and many others. Works on Linux, macOS, Windows.

```bash
# Install from .deb package
sudo dpkg -i dbeaver-<version>.deb

# Launch
dbeaver &
```
> Replace `<version>` with the actual version number from the downloaded `.deb` file. `&` launches it in the background so the terminal stays free.

Download: [https://github.com/dbeaver/dbeaver/releases](https://github.com/dbeaver/dbeaver/releases)

> SSMS (SQL Server Management Studio) is Windows-only. Use dbeaver as the cross-platform alternative.

---

## Tools Reference Table

| Category | Tool | Notes |
|----------|------|-------|
| **SMB** | `smbclient` | CLI SMB client |
| **SMB** | `CrackMapExec` | SMB enumeration & exploitation |
| **SMB** | `SMBMap` | Share enumeration |
| **SMB** | `Impacket` | Suite including `psexec.py`, `smbexec.py` |
| **FTP** | `ftp`, `lftp`, `ncftp` | CLI FTP clients |
| **FTP** | `filezilla`, `crossftp` | GUI FTP clients |
| **Email** | `Thunderbird`, `Evolution`, `Geary` | GUI mail clients |
| **Email** | `mutt`, `mailutils`, `sendmail` | CLI mail tools |
| **Email** | `swaks`, `sendEmail` | SMTP testing/exploitation |
| **Databases** | `mssql-cli`, `sqsh`, `sqlcmd` | MSSQL CLI tools |
| **Databases** | `mycli`, `mysql` | MySQL CLI tools |
| **Databases** | `mssqlclient.py` | Impacket MSSQL tool |
| **Databases** | `dbeaver`, `MySQL Workbench`, `SSMS` | GUI database tools |

---

## General Troubleshooting

Common reasons for failed service connections:

| Reason | What to Check |
|--------|---------------|
| **Authentication** | Credentials valid? Account locked? |
| **Privileges** | Does the account have access to that share/DB? |
| **Network Connection** | Can you reach the host? (`ping`, `traceroute`) |
| **Firewall Rules** | Is the port open? (`nmap`, `nc`) |
| **Protocol Support** | Does the server support the version/method you're using? |

> Use error codes to search official docs or community forums for targeted solutions.

---

## Key Takeaways

| Concept | Takeaway |
|---------|----------|
| SMB shares | Mountable on both Windows (`net use`) and Linux (`mount -t cifs`) |
| Credential hunting | Use `dir`/`findstr` (CMD), `Get-ChildItem`/`Select-String` (PS), `find`/`grep` (Linux) |
| Email interaction | SMTP sends, IMAP/POP3 receives; Evolution works on Linux |
| Database access | CLI (`mysql`, `sqsh`) or GUI (`dbeaver`) — both are valid attack paths |
| Tool awareness | Know both OS-native tools and community tools for each service type |
