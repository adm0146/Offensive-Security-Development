# Section 01 — Introduction

> No lab questions. Context + lab setup.

---

## QUICK REFERENCE — Lab Connection

```bash
# SSH to Linux attack host
ssh htb-student@ATTACK01_IP
# password: HTB_@cademy_stdnt!

# RDP to Windows attack host
xfreerdp /v:MS01_IP /u:htb-student /p:'Academy_student_AD!' /cert:ignore /dynamic-resolution

# xfreerdp to Linux attack host (for BloodHound GUI)
xfreerdp /v:ATTACK01_IP /u:htb-student /p:'HTB_@cademy_stdnt!' /cert:ignore /dynamic-resolution
```

**Tool locations:** Windows = `C:\Tools\` | Linux = `/opt/` or PATH

---

## Lab Hosts

| Host | Role | User | Password | Access |
|------|------|------|----------|--------|
| MS01 | Windows attack host | htb-student | `Academy_student_AD!` | RDP |
| ATTACK01 | Parrot Linux attack host | htb-student | `HTB_@cademy_stdnt!` | SSH / xfreerdp |

> Spawn the lab first — it takes 3-5 min to fully boot. Read while you wait.

---

## Key Concepts

- **Primary attack surface:** Misconfigurations, not just CVEs
- **Minimum access needed:** Any valid domain user unlocks the majority of AD enumeration
- **Both platforms:** Must be comfortable attacking from Linux and Windows
- **Iterative:** You'll loop back to enumeration every time you gain new access

---

## Attack Chain Patterns

### Chain 1 — Kerberoast → Share Files → Responder → DA
```
SYSTEM on host → enumerate SPNs → Kerberoast → crack →
write access to shares → drop SCF file → Responder captures NTLMv2 → victim = DA
```

### Chain 2 — NULL Session → Spray → BloodHound → Pass-the-Ticket
```
NULL SMB session → dump users + policy → careful spray →
local admin on box → active DA session → Rubeus extracts TGT → pass-the-ticket → DA
```

### Chain 3 — Kerbrute → Spray → ACL Abuse → DCSync
```
No creds → Kerbrute + LinkedIn → valid users → spray →
RDP access → spray again → ACL chain → Shadow Credentials → DCSync → all hashes
```

---

## Scope (INLANEFREIGHT Lab)

| Target | Description |
|--------|-------------|
| `INLANEFREIGHT.LOCAL` | Primary domain |
| `LOGISTICS.INLANEFREIGHT.LOCAL` | Child domain |
| `FREIGHTLOGISTICS.LOCAL` | External forest (bidirectional trust) |
| `172.16.5.0/23` | In-scope subnet |
