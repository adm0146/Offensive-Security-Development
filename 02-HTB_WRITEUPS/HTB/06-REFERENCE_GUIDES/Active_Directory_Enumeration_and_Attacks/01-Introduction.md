# 01 — Introduction to Active Directory Enumeration & Attacks

> No lab questions. Context section — key concepts, lab setup, and connection info.

---

## Why AD Matters

- ~43% market share for enterprise IAM
- 2000+ CVEs in the last two years against Microsoft products
- Misconfigurations, not just vulnerabilities — the primary attack surface
- Goal: escalate privileges laterally or vertically until domain compromise

---

## Lab Setup

| Host | Role | Credentials | Access |
|------|------|-------------|--------|
| MS01 | Windows attack host | `htb-student / Academy_student_AD!` | RDP |
| ATTACK01 | Parrot Linux attack host | `htb-student / HTB_@cademy_stdnt!` | SSH + xfreerdp |

```bash
# RDP to MS01
xfreerdp /v:MS01_IP /u:htb-student /p:'Academy_student_AD!' /cert:ignore /dynamic-resolution

# SSH to ATTACK01
ssh htb-student@ATTACK01_IP

# xfreerdp to ATTACK01 (BloodHound GUI)
xfreerdp /v:ATTACK01_IP /u:htb-student /p:'HTB_@cademy_stdnt!' /cert:ignore /dynamic-resolution
```

**Tool locations:**
- Windows: `C:\Tools\`
- Linux: `/opt/` or in PATH

> Spawn the lab at the bottom of each section FIRST, then read — labs take 3–5 min to fully boot.

---

## Key Concepts Introduced

- **Iterative enumeration** — keep going back, try different angles
- **Living off the land** — use built-in Windows tools (WMI, DNS, Sysinternals) when custom tools are blocked
- **Both platforms** — must be comfortable attacking from Windows and Linux
- **The "why"** — understanding misconfigurations makes recommendations actionable

---

## Attack Chain Patterns (Real-World Scenarios)

### Chain 1 — Kerberoast → Responder → DA
SYSTEM on host → enumerate SPNs → Kerberoast → crack overnight → write access to shares → drop SCF files → Responder captures NetNTLMv2 → victim is DA

### Chain 2 — NULL Session → Spray → BloodHound → Pass-the-Ticket
NULL SMB session → dump users + password policy → spray carefully → local admin on a box → active DA session on that box → Rubeus extracts TGT → pass-the-ticket → DA

### Chain 3 — Kerbrute → Spray → ACL Abuse → DCSync
No creds → Kerbrute + LinkedIn usernames → enumerate valid users → spray → RDP access → spray again from inside → ACL chain (GenericAll → Enterprise Key Admins → DC) → Shadow Credentials → DCSync → all hashes

---

## References

- Next: [02-Tools_of_the_Trade.md](02-Tools_of_the_Trade.md)
- Prerequisite: Introduction to Active Directory module
