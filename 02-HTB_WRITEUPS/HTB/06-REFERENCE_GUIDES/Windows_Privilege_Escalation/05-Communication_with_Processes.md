# Section 5 — Communication with Processes

> **Lab: yes** — 2 questions on same target (ACADEMY-WINLPE-SRV01).

**Core principle:** Processes communicate via network sockets and named pipes. Both are attack surfaces — services listening on localhost bypass network-level security assumptions, and named pipes with weak DACLs can be abused for privilege escalation.

---

## Access tokens (quick context)

Every process/thread has an access token describing the security context (user identity + privileges). When you exploit a service, you inherit its token — which is why targeting services running as SYSTEM or with SeImpersonate matters.

---

## Network services — localhost listeners

### Enumerate listening ports

```cmd
netstat -ano
```

**What to look for:**
| Indicator | Why it matters |
|-----------|---------------|
| `127.0.0.1:<port>` or `[::1]:<port>` | Only accessible locally — often no auth because devs assumed "it's not on the network" |
| Non-standard ports (8080, 14147, 25672, etc.) | Custom apps, admin interfaces, dev tools |
| Services running as SYSTEM on these ports | Exploit → instant SYSTEM |

### Cross-reference PID to service

```cmd
tasklist /svc /fi "PID eq <PID>"
```

### Common localhost privesc targets

| Service | Port | Attack |
|---------|------|--------|
| FileZilla Admin Interface | 14147 | Connect → extract FTP creds, create share at C:\ |
| Splunk Universal Forwarder | 8089 | No default auth → deploy malicious app → code exec as SYSTEM |
| Erlang Port (RabbitMQ, CouchDB, SolarWinds) | 25672 | Weak/default cookie (`rabbit`) → join cluster → RCE |
| MSSQL | 1433 | xp_cmdshell if you have creds |
| Tomcat Manager | 8080 | Default creds → deploy WAR shell |

---

## Named pipes

Named pipes are in-memory IPC (inter-process communication) files at `\\.\pipe\<name>`. They allow processes to communicate — if a pipe's DACL is misconfigured (writable by low-priv users), it can be exploited for privilege escalation.

### Enumerate named pipes

```cmd
pipelist.exe /accepteula
```
```powershell
gci \\.\pipe\
```

### Check permissions on a specific pipe

```cmd
accesschk.exe /accepteula \\.\Pipe\<pipename> -v
```

### Find all writable pipes (key command)

```cmd
accesschk.exe -w \pipe\* -v /accepteula
```
> This finds pipes where your user/group has write access. Any pipe writable by `Everyone`, `BUILTIN\Users`, or `Authenticated Users` that belongs to a privileged service = potential privesc.

### Reading DACL output

| Permission | Meaning |
|------------|---------|
| `FILE_ALL_ACCESS` | Full control — read, write, execute |
| `FILE_WRITE_DATA` | Can write to the pipe |
| `WRITE_DAC` | Can modify the pipe's own permissions (very dangerous) |
| `FILE_READ_DATA` | Can read from the pipe |

### Named pipe attack flow

```
1. Find pipe owned by privileged service (SYSTEM/admin)
2. Check DACL → Everyone or Users has write access
3. Connect to pipe → inject commands or impersonate the service's token
4. Result: code execution as the service's user (often SYSTEM)
```

### Real-world example — WindscribeService

```cmd
accesschk.exe -accepteula -w \pipe\WindscribeService -v
```
> Output showed `Everyone` has `FILE_ALL_ACCESS` → exploit the pipe → escalate to SYSTEM.

### Cobalt Strike context

Cobalt Strike uses named pipes (`\\.\pipe\msagent_XX`) for command output. Operators often rename to `mojo` (Chrome's pipe name) for evasion. Finding named pipes that look like browser pipes on a machine without that browser = indicator of compromise.

---

## Lab walkthrough

**Target:** `10.129.43.43` (ACADEMY-WINLPE-SRV01)
**Creds:** `htb-student` / `HTB_@cademy_stdnt!`

### Question 1 — What service is listening on 0.0.0.0:21? (two words)

```cmd
netstat -ano | findstr ":21 "
```
> Get the PID, then:
```cmd
tasklist /svc /fi "PID eq <PID>"
```
> The service name (two words) is the answer — likely something like `FileZilla Server`.

### Question 2 — Which account has WRITE_DAC privileges over \pipe\SQLLocal\SQLEXPRESS01?

```cmd
accesschk.exe /accepteula \\.\Pipe\SQLLocal\SQLEXPRESS01 -v
```
> Or if accesschk is in C:\Tools:
```cmd
C:\Tools\accesschk.exe /accepteula \\.\Pipe\SQLLocal\SQLEXPRESS01 -v
```
> Look for the account that has `WRITE_DAC` in its permission list.

---

## Lab observations & attack chain (WINLPE-SRV01)

**What we found:**

| Finding | Value | Significance |
|---------|-------|--------------|
| Service on port 21 (PID 2100) | `FileZilla Server` | FTP server — check for anonymous access, stored creds, admin interface on 14147 (localhost) |
| WRITE_DAC on SQLExpress pipe | `NT SERVICE\MSSQL$SQLEXPRESS01` | This service account can modify the pipe's DACL — if compromised, can grant any user full pipe access |
| Everyone has RW on SQL pipe | `FILE_WRITE_DATA`, `FILE_READ_DATA`, etc. | Any authenticated user can read/write to the SQL pipe — potential for command injection or credential interception |

**Lab note:** `accesschk64.exe` initially failed with "All pipe instances are busy" — workaround was using the wildcard `\pipe\*` with grep instead of targeting the specific pipe directly.

**Attack chain — exploiting process communication:**

```
Process Communication findings:
│
├── Path 1: FileZilla (port 21 + admin port 14147)
│   └── Connect to 127.0.0.1:14147 (admin interface, localhost only)
│       └── Extract stored FTP credentials from FileZilla config
│       └── OR create FTP share mapped to C:\ as FileZilla service user
│           └── If FileZilla runs as admin/SYSTEM → full filesystem read/write
│
├── Path 2: SQL Express named pipe (Everyone has RW!)
│   ├── Everyone can read/write to \\.\Pipe\SQLLocal\SQLEXPRESS01
│   │   └── Connect to SQL Express via pipe → xp_cmdshell if enabled
│   │       └── Command exec as MSSQL$SQLEXPRESS01 service account
│   │           └── Check whoami /priv → likely SeImpersonate → Potato → SYSTEM
│   └── NT SERVICE\MSSQL$SQLEXPRESS01 has WRITE_DAC
│       └── If we get this account → can lock others out or grant full access
│
├── Path 3: Windscribe VPN pipe (from Section 3)
│   └── Check: accesschk64.exe -w \pipe\WindscribeService -v
│       └── If Everyone has write → CVE-2020-12749
│           └── Escalate to SYSTEM via pipe impersonation
│
└── Practical notes:
    ├── accesschk on specific busy pipes fails → use wildcard: \pipe\* with grep
    └── Tools location: C:\Tools\accesschk64.exe (not accesschk.exe for 64-bit OS)
```

**Connecting the dots with earlier sections:**
- FileZilla on port 21 was visible in `netstat -ano` (Section 4) — now we know the admin interface is the real target (port 14147, localhost only)
- The `sccm_svc` account (Section 4) likely owns some of these named pipes — after privesc, its token is valuable
- SQL Express service account probably has SeImpersonate → feeds into Potato attacks later in the module

---

## Key takeaways

- **Localhost listeners are prime targets.** They exist because someone assumed local = safe. FileZilla admin (14147), Splunk (8089), and Erlang (25672) are the classics.
- **Named pipes with weak DACLs = token impersonation.** If Everyone can write to a pipe owned by SYSTEM, you can escalate.
- **`accesschk.exe -w \pipe\* -v`** is your go-to command for finding writable pipes.
- **WRITE_DAC is as dangerous as FILE_ALL_ACCESS.** If you can change the DACL, you can grant yourself full control.
- **Cross-reference ports to services with `tasklist /svc`.** The PID from netstat maps directly to the service name.
