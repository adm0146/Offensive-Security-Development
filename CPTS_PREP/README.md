# CPTS Exam Prep — Live Tracker

**Target:** early July 2026 — **readiness-gated, not date-gated.** The exam is self-scheduled; you start the 10-day window when the signals below are green. Don't burn the voucher early.

**Last updated:** 2026-06-18

---

## 🚦 Readiness gate (the only thing that decides "go")

You're ready when you can do these **solo, no notes, no hand-holding:**

- [ ] Solo an easy AD box end-to-end (enum → foothold → roast/ACL → DA) — **Active, Forest, Sauna**
- [ ] Build a double pivot into a segmented network unaided (SOCKS + portproxy / ligolo)
- [ ] Chain web → local privesc → AD → DA on a multi-host box
- [ ] Take clean, report-ready notes the whole way

> Honest baseline (2026-06-08): you can do **enum, file transfer, common vectors** solo. AD attacks + pivoting were **teacher-scaffolded** on AEN/Active — not yet solo. That gap is the whole game.

---

## 📅 5-Week Plan (aligned with CPTS → CRTO Ops Plan)

Scaffolding fades each week: Week 1 ADCS gap-killers, Week 2 RBCD/Kerberos, Week 3+ fully blind.

| Week | Boxes | Focus | Done? |
|------|-------|-------|-------|
| **1** | **Certified** ✅ · **Escape** ✅ · **Authority** ✅ | ADCS ESC1/ESC9, Shadow Credentials, PassTheCert | ✅ |
| **2** | **Vintage** ✅ · **Blackfield** ✅ | RBCD, Kerberos-only ops, gMSA, DPAPI, SeBackup → NTDS | ✅ |
| **3** | **Cascade** ✅ · Support · Intelligence · Monteverde · Tabby | Blind reps + report template lock | ☐ |
| **4** | **Zephyr** (Pro Lab) — blind run | Multi-host enterprise chain, pivoting under load | ☐ |
| **5** | Taper — no new material | Field manual review, logistics check, rest | ☐ |

**Pre-work (complete):** Active ✅ · Forest ✅ · Sauna ✅ (Kerberoast, AS-REP, GPP, DCSync, ACL abuse, PtH)

Full ops plan: [CPTS CRTO Roadmap 2026.html](../CPTS_CRTO_Roadmap_2026.html)

---

## 📦 Box Tracker

| Box | Difficulty | Date | Solo? | Key techniques | Writeup |
|-----|-----------|------|-------|----------------|---------|
| Active | Easy | 2026-06-08 | ❌ taught | GPP cpassword, Kerberoast, psexec | [ACTIVE_Easy.md](../02-HTB_WRITEUPS/HTB/02-EASY/ACTIVE_Easy.md) |
| Forest | Easy | 2026-06-09 | 🟡 hints+taught | AS-REP roast, BloodHound ACL chain → DCSync, PtH | [FOREST_Easy.md](../02-HTB_WRITEUPS/HTB/02-EASY/FOREST_Easy.md) |
| Sauna | Easy | 2026-06-09 | 🟡 hints | AS-REP roast, autologon registry, DCSync, PtH | [SAUNA_Easy.md](../02-HTB_WRITEUPS/HTB/02-EASY/SAUNA_Easy.md) |
| Cascade | Medium | 2026-06-10 | 🟡 hints | LDAP enum, TightVNC decrypt, .NET reversing, AD Recycle Bin | [CASCADE_Medium.md](../02-HTB_WRITEUPS/HTB/03-MEDIUM/CASCADE_Medium.md) |
| Certified | Medium | 2026-06-10 | 🟡 syntax refs | ACL chaining, Shadow Credentials, ADCS ESC9, PtH | [CERTIFIED_Medium.md](../02-HTB_WRITEUPS/HTB/03-MEDIUM/CERTIFIED_Medium.md) |
| Escape | Medium | 2026-06-11 | 🟡 infra issues | MSSQL xp_dirtree coercion, Responder, ADCS ESC1, PtH | [ESCAPE_Medium.md](../02-HTB_WRITEUPS/HTB/03-MEDIUM/ESCAPE_Medium.md) |
| Cicada | Easy | 2026-06-11 | ✅ unaided | LDAP enum, password spray | *(no writeup)* |
| Support | Easy | 2026-06-11 | ✅ unaided | .NET reversing, RBCD | *(no writeup)* |
| Manager | Easy | 2026-06-12 | ✅ unaided | MSSQL, ADCS ESC7 | *(no writeup)* |
| Authority | Medium | 2026-06-18 | 🟡 infra issues | Ansible vault, PWM config redirect, ADCS ESC1, PassTheCert | [AUTHORITY_Medium.md](../02-HTB_WRITEUPS/HTB/03-MEDIUM/AUTHORITY_Medium.md) |
| Blackfield | Hard | 2026-06-18 | 🟡 BH UI help | AS-REP roast, ForceChangePassword, LSASS dump, SeBackupPrivilege → ntds.dit | [BLACKFIELD_Hard.md](../02-HTB_WRITEUPS/HTB/04-HARD/BLACKFIELD_Hard.md) |
| Vintage | Hard | 2026-06-18 | 🟡 syntax refs + infra | Kerberos-only, Pre-Win2000, gMSA, targeted Kerberoast, DPAPI, RBCD S4U | [VINTAGE_Hard.md](../02-HTB_WRITEUPS/HTB/04-HARD/VINTAGE_Hard.md) |

*(Solo? = ❌ taught / 🟡 hints / ✅ unaided. The goal is turning ❌→✅.)*

---

## 🧠 Concept-Review List (techniques I've seen but can't yet do solo)

Close these by **doing**, not reading. Each box below drills one.

- [ ] **GPP cpassword** decrypt (openssl one-liner / `gpp-decrypt`) — *Active ✅ seen*
- [ ] **Kerberoasting** — `GetUserSPNs -request` → `hashcat -m 13100` — *Active ✅ seen*
- [x] **AS-REP roasting** — `GetNPUsers` → `-m 18200` — *Forest ✅ (solo-confirm on Sauna)*
- [x] **BloodHound** — collect (CE collector!), mark owned, pathfind, read ACL edges — *Forest ✅*
- [x] **ACL abuse w/ bloodyAD** — `add groupMember`, `add dcsync`, WriteDacl chain — *Forest ✅*
- [x] **DCSync** — `secretsdump -just-dc-ntlm` — *Forest ✅*
- [x] **Pass-the-Hash** — `nxc -H` / `evil-winrm -H` — *Forest ✅*
- [x] **ACL chaining** — WriteOwner → dacledit → group add, multi-hop chains — *Certified ✅*
- [x] **Shadow Credentials** — `certipy shadow auto`, msDS-KeyCredentialLink + PKINIT → hash — *Certified ✅*
- [x] **ADCS ESC9** — CT_FLAG_NO_SECURITY_EXTENSION + weak binding → UPN swap → impersonate — *Certified ✅*
- [x] **ADCS ESC1** — ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU → request cert as any user — *Escape ✅*
- [x] **MSSQL hash coercion** — xp_dirtree UNC path → Responder captures NTLMv2 → crack -m 5600 — *Escape ✅*
- [x] **Credential hunting in logs** — check ERRORLOG, config files, scripts, history after every shell — *Escape ✅*
- [ ] **Double pivot** — SOCKS + `netsh portproxy`, then `ligolo-ng` — *Dante/Zephyr*
- [x] **ForceChangePassword** — rpcclient `setuserinfo2 <user> 23 "<pass>"` — *Blackfield ✅*
- [x] **LSASS dump analysis** — `pypykatz lsa minidump lsass.DMP` — *Blackfield ✅*
- [x] **SeBackupPrivilege → ntds.dit** — diskshadow + robocopy /B + secretsdump LOCAL — *Blackfield ✅*
- [ ] **NTLMv2 capture** — Inveigh/Responder → `-m 5600` — *later*
- [x] **LDAP anonymous enum** — `ldapsearch -x` for custom attributes (cascadeLegacyPwd) — *Cascade ✅*
- [x] **Published-key decryption** — TightVNC DES, GPP AES — recognize format, Google key, decrypt — *Active + Cascade ✅*
- [ ] **.NET reversing** — extract UTF-16LE strings / monodis for hardcoded keys — *Cascade ✅ seen*
- [x] **AD Recycle Bin** — `Get-ADObject -Filter {isDeleted -eq $true} -IncludeDeletedObjects` — *Cascade ✅*

---

## ⚙️ Workflow (locked in)

- **opsbox** = network ops only (VPN, SOCKS pivot, nxc/impacket/bloodyAD). No GPU.
- **Mac** = offline cracking (hashcat GPU) + BloodHound-CE GUI. OPSEC-safe (cracking touches no target).
- Capture hashes on opsbox → `scp` to Mac → crack. Wordlist: `~/wordlists/rockyou.txt`.
- Hashcat modes: `13100` kerberoast · `18200` AS-REP · `5600` NTLMv2 · `1000` NTLM.

---

## 🔁 Per-box ritual (build the habit)

1. Drive it yourself; I only spot/ask.
2. After rooting: write the chain from **memory** — blanks = study list.
3. Read the 0xdf writeup; log where their path differed from yours.
4. Update this tracker (Solo? column, concept checkboxes).

---

## 🔗 Reference (built, don't add more — go *do*)

- AEN reference guides: [../02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Attacking_Enterprise_Networks/](../02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/Attacking_Enterprise_Networks/)
- Box progression: [../CPTS_BOX_PROGRESSION.md](../CPTS_BOX_PROGRESSION.md)

**Next action:** Week 3 blind reps: Cascade, Support, Intelligence, Monteverde, Tabby.
