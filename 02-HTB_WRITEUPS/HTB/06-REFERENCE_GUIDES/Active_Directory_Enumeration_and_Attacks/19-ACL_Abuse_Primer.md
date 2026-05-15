# Section 19 — ACL Abuse Primer

> No lab questions. Concepts + attack reference for sections 20+.

---

## QUICK REFERENCE — Abusable ACE Permissions

| Permission | Abuse Method | PowerView Command |
|------------|-------------|-------------------|
| `ForceChangePassword` | Reset user's password without knowing current | `Set-DomainUserPassword` |
| `GenericAll` (user) | Force password change OR **targeted Kerberoast** (assign SPN) — primary ACE for this | `Set-DomainUserPassword` |
| `GenericAll` (group) | Add yourself to group | `Add-DomainGroupMember` |
| `GenericAll` (computer) | Read LAPS password (if LAPS enabled) | `Get-DomainObject` |
| `GenericWrite` (user) | Assign SPN → Kerberoast | `Set-DomainObject` |
| `GenericWrite` (group) | Add member to group | `Add-DomainGroupMember` |
| `GenericWrite` (computer) | Resource-Based Constrained Delegation attack | `Set-DomainObject` |
| `WriteOwner` | Change object owner → grant yourself full control | `Set-DomainObjectOwner` |
| `WriteDACL` | Add ACE to object → grant yourself any right | `Add-DomainObjectACL` |
| `AllExtendedRights` | Force password change OR add to group | `Set-DomainUserPassword` / `Add-DomainGroupMember` |
| `AddSelf` | Add yourself to a security group | `Add-DomainGroupMember` |
| `Add Members` | Add any user to a group | `Add-DomainGroupMember` |

---

## ACL Concepts

**ACL (Access Control List)** — defines who has access to an AD object and at what level. Every user, group, and computer object has one.

**DACL (Discretionary ACL)** — controls who is allowed or denied access. Made up of Access Control Entries (ACEs).
- No DACL on object = everyone has full rights
- DACL with no ACEs = everyone denied

**SACL (System ACL)** — controls audit logging for access attempts. Not used for attacks — just logging.

**ACE (Access Control Entry)** — a single entry inside a DACL. Each ACE contains:
- Security Identifier (SID) of the principal (user/group)
- ACE type (allow, deny, audit)
- Inheritance flags
- Access mask (32-bit value — defines which specific rights are granted)

**ACEs are checked top to bottom — first match wins. Deny beats allow if both exist.**

---

## ACE Types

| Type | Location | Purpose |
|------|----------|---------|
| Access Denied ACE | DACL | Explicitly deny a principal |
| Access Allowed ACE | DACL | Explicitly grant a principal |
| System Audit ACE | SACL | Log access attempts |

---

## Why ACL Attacks Matter

- **Not detected by vulnerability scanners** — ACL misconfigurations are invisible to Nessus and OpenVAS.
- **Often unchecked for years** — especially in complex environments where no one does regular reviews.
- **Software installs create them** — Exchange, SCCM, and other products add broad ACEs at install time without warning.
- **Hard to spot** — even experienced admins do not audit ACLs regularly.
- **BloodHound visualizes them** — edges like `ForceChangePassword`, `GenericAll`, and `WriteDACL` show exact attack paths.

---

## Common Attack Scenarios

| Scenario | Path |
|----------|------|
| Help Desk account has `ForceChangePassword` on DA | Compromise Help Desk → reset DA password → DA |
| IT account has `Add Members` on privileged group | Compromise IT account → add self to group → elevated access |
| User has `GenericWrite` on high-value account | Assign SPN → Kerberoast → crack → privileged access |
| User has `WriteDACL` on Domain Admins group | Grant self `Add Members` → add self → DA |
| User has `WriteOwner` on any object | Take ownership → grant self full control → any abuse |

---

## Attack Flow (General Pattern)

```
1. BloodHound — identify ACE paths to high-value targets
2. PowerView — enumerate and confirm the specific ACE
3. PowerView — abuse the ACE (change password, add member, modify object)
4. Use the new access to move laterally or escalate
5. CLEAN UP — revert all changes, document in report
```

---

## Enumeration Tools

```powershell
# BloodHound — visual attack path (best for finding ACL chains)
# Look for edges: ForceChangePassword, GenericAll, GenericWrite, WriteDACL, WriteOwner

# PowerView — enumerate specific ACEs
Find-InterestingDomainAcl                          # broad scan for interesting ACEs
Get-DomainObjectAcl -Identity USER -ResolveGUIDs   # ACEs on a specific object
```
> Start with BloodHound to find ACL edges visually. Then use PowerView to confirm the exact ACE and plan the abuse. `Find-InterestingDomainAcl` scans the whole domain for non-default ACEs. `Get-DomainObjectAcl -ResolveGUIDs` translates the raw GUID values in ACEs into human-readable right names.

---

## Exam Notes

- ACL abuse = invisible to scanners, overlooked for years — high value finding
- BloodHound edges are your roadmap — learn what each one means
- **GenericAll** = full control — most powerful, most dangerous — the ACE for targeted Kerberoasting (not GenericWrite)
- **WriteDACL** = can grant yourself any right → chained escalation
- **WriteOwner** → take ownership → then WriteDACL → then anything
- Always get client approval before ForceChangePassword — it's destructive
- Document every change and revert after — include in report
- Sections 20+ cover the hands-on exploitation of these ACEs
