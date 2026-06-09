# CPTS Exam Prep — Live Tracker

**Target:** early July 2026 — **readiness-gated, not date-gated.** The exam is self-scheduled; you start the 10-day window when the signals below are green. Don't burn the voucher early.

**Last updated:** 2026-06-08

---

## 🚦 Readiness gate (the only thing that decides "go")

You're ready when you can do these **solo, no notes, no hand-holding:**

- [ ] Solo an easy AD box end-to-end (enum → foothold → roast/ACL → DA) — **Active, Forest, Sauna**
- [ ] Build a double pivot into a segmented network unaided (SOCKS + portproxy / ligolo)
- [ ] Chain web → local privesc → AD → DA on a multi-host box
- [ ] Take clean, report-ready notes the whole way

> Honest baseline (2026-06-08): you can do **enum, file transfer, common vectors** solo. AD attacks + pivoting were **teacher-scaffolded** on AEN/Active — not yet solo. That gap is the whole game.

---

## 📅 4-Week Plan (boxes, you driving)

Scaffolding fades each week: Week 1 I teach, Week 2 I ask, Week 3+ you drive blind.

| Week | Boxes | Focus | Done? |
|------|-------|-------|-------|
| **1** | **Active** ✅ · Forest · Sauna | GPP, Kerberoast, AS-REP, BloodHound ACL → DCSync | ☐ |
| **2** | Cascade · Resolute · Monteverde | spraying, WinRM, AD Connect creds, more ACL | ☐ |
| **3** | Escape · Support · Blackfield + **Dante** (lab) | ADCS/ESC1, RBCD, SeBackup, multi-host pivoting | ☐ |
| **4** | **Zephyr** (Pro Lab) + 1 practice report | exam dress rehearsal end-to-end | ☐ |

Full curriculum + ordering: [../CPTS_BOX_PROGRESSION.md](../CPTS_BOX_PROGRESSION.md)

---

## 📦 Box Tracker

| Box | Difficulty | Date | Solo? | Key techniques | Writeup |
|-----|-----------|------|-------|----------------|---------|
| Active | Easy | 2026-06-08 | ❌ taught | GPP cpassword, Kerberoast, psexec | [ACTIVE_Easy.md](../02-HTB_WRITEUPS/HTB/02-EASY/ACTIVE_Easy.md) |
| Forest | Easy | 2026-06-09 | 🟡 hints+taught | AS-REP roast, BloodHound ACL chain → DCSync, PtH | [FOREST_Easy.md](../02-HTB_WRITEUPS/HTB/02-EASY/FOREST_Easy.md) |
| Sauna | Easy | — | — | AS-REP roast, ACL abuse, DCSync | **← next, drive it** |

*(Solo? = ❌ taught / 🟡 hints / ✅ unaided. The goal is turning ❌→✅.)*

---

## 🧠 Concept-Review List (techniques I've seen but can't yet do solo)

Close these by **doing**, not reading. Each box below drills one.

- [ ] **GPP cpassword** decrypt (openssl one-liner / `gpp-decrypt`) — *Active ✅ seen*
- [ ] **Kerberoasting** — `GetUserSPNs -request` → `hashcat -m 13100` — *Active ✅ seen*
- [x] **AS-REP roasting** — `GetNPUsers` → `-m 18200` — *Forest ✅ (solo-confirm on Sauna)*
- [x] **BloodHound** — collect (CE collector!), mark owned, pathfind, read ACL edges — *Forest ✅*
- [x] **ACL abuse w/ bloodyAD** — `add groupMember`, `add dcsync`, WriteDacl chain — *Forest ✅ (solo-confirm on Sauna)*
- [x] **DCSync** — `secretsdump -just-dc-ntlm` — *Forest ✅*
- [x] **Pass-the-Hash** — `nxc -H` / `evil-winrm -H` — *Forest ✅*
- [ ] **Double pivot** — SOCKS + `netsh portproxy`, then `ligolo-ng` — *Dante/Zephyr*
- [ ] **NTLMv2 capture** — Inveigh/Responder → `-m 5600` — *later*

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

**Next action:** spawn **Forest** — AS-REP roast + BloodHound ACL → DCSync, training wheels off.
