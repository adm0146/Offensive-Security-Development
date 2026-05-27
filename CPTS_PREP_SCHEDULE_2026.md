# CPTS Prep Schedule — Great-Prep Version

**Approach:** Readiness-gated, not date-pinned. Exam is scheduled **when the gates pass**, not on a fixed calendar.
**Working assumption:** ~5 hrs/weekday + ~6 hrs/weekend ≈ 37 hrs/week.
**Estimated duration if executed cleanly:** ~10–12 weeks of focused prep (~300–400 hands-on hours).
**Schedule v2 created:** 2026-05-27.

---

## State entering this plan

- 27/28 HTB Academy CPTS modules documented with reference guides + exam cheatsheets.
- **AEN module: ~24% complete, in progress** on native Kali (primary workspace). Guided walkthrough with assistant — not blind, not spoonfed.
- Missing cheatsheet: `Using_Web_Proxies/00-EXAM_CHEATSHEET.md` (only module without one).
- HTB box practice: 22 boxes, all Very Easy / Easy. Zero Medium+.
- Pivoting: only practiced on FUNNEL.
- Reporting: complete module, no end-to-end mock report artifact exists.
- Pro Labs: **buying Zephyr first**, then **Dante** after.
- Primary workspace: native Kali Linux desktop. This Mac repo is for planning + reference docs.

---

## Why this is the great-prep schedule, not the good-prep schedule

The earlier draft was 46 days, ~180 hrs, fixed July 12 exam. Honest assessment of that plan: 70–80% chance of first-attempt pass, no buffer, AEN done guided not blind, only 2 mock reports, 5–8 Medium boxes. Bottom of the passing distribution.

This version raises the floor to ~90% likely pass by adding: AEN blind second pass, Dante (in addition to Zephyr), 4 mock reports (last one rubric-scored), 15+ Medium boxes, higher daily hours, IppSec walkthroughs as standard practice, and explicit readiness gates before sitting the exam.

---

## Phase 1 — AEN Guided Walkthrough

**Status:** In progress, ~24% complete.

Continue AEN on Kali with assistant in collaboration mode (reasoning help, not exploit handouts). Take exam-style notes from minute one. Capture screenshots as you go — you can't redo them after a box resets.

**Estimated remaining:** ~10 days.

**Gate to Phase 2:**
- [ ] All AEN sections complete
- [ ] Mock report #1 written end-to-end (exec summary → findings → remediation)
- [ ] AEN folder pushed to GitHub from Kali

---

## Phase 2 — AEN Blind Second Pass

**Goal:** Diagnostic. Re-do AEN hosts from scratch without notes. This is the closest in-Academy exam simulation — reviewers consistently call it the single best gauge of readiness.

If you struggle on a host you "knew" how to solve, that technique is recognized, not internalized. Drill it before moving on.

**Estimated duration:** 5–7 days.

**Gate to Phase 3:**
- [ ] All AEN hosts solved blind (notes from Phase 1 closed)
- [ ] List of struggling-points captured for targeted drill in Phase 6

---

## Phase 3 — Zephyr Pro Lab

**Goal:** Complete Zephyr 100%. Zephyr is AD-heavy, chained, 14 hosts — closest single external thing to the CPTS exam.

- Buy Zephyr cubes on HTB (3 cubes, ~$45 student / ~$90 standard). Verify VPN from Kali.
- Treat Zephyr like a real engagement: full enum, document every host, write findings as you go (this becomes mock report #2).
- **Stuck-rule:** 6 hours without progress on a host → IppSec walkthrough for an equivalent retired box, then return.

**Parallel:** Begin Medium HTB boxes (see Phase 5).

**Estimated duration:** 15–20 days.

**Gate to Phase 4:**
- [ ] Zephyr 100% complete (or 90%+ with documented blocker)
- [ ] Mock report #2 written on Zephyr engagement
- [ ] ≥ 5 Medium AD HTB boxes solved (own work; IppSec assist counts only if redone solo after)

---

## Phase 4 — Dante Pro Lab

**Goal:** Fill the non-AD gaps Zephyr doesn't hit. Dante is mixed Linux + Windows, 14 hosts, 27 flags, broader skillset.

- Buy Dante cubes after Zephyr finishes.
- Don't aim for 100% — aim for ≥ 75% with a focus on the chains/techniques you're weakest on.
- Concurrent report writing as before.

**Parallel:** Continue Medium HTB boxes.

**Estimated duration:** 20–30 days.

**Gate to Phase 5:**
- [ ] Dante ≥ 75% complete
- [ ] Mock report #3 written on a Dante chain
- [ ] Total ≥ 15 Medium HTB boxes solved

---

## Phase 5 — Medium HTB Box Volume (parallel track, ongoing Phases 3–6)

Not a sequential phase — a constant background track that runs alongside Pro Labs.

**Target progression:**
1. FOREST (AS-REP roast, DCSync via ACL abuse) — canonical
2. ACTIVE (Kerberoasting, GPP cpassword)
3. SAUNA (AS-REP roast + WinRM)
4. MONTEVERDE (Azure ADConnect creds)
5. RESOLUTE (DnsAdmins → DLL → SYSTEM)
6. CASCADE (LDAP, AD recycle bin)
7. INTELLIGENCE (constrained delegation, gMSA)
8. MULTIMASTER (SQLi → AD → constrained delegation chain)
9. REEL (phishing-style email → AD)
10. WORKER (Azure DevOps pivot)
... plus 5+ more biased toward your weakest areas

**Rule:** IppSec walkthrough after every solve (to refine methodology) and after every skip (to learn the technique).

---

## Phase 6 — 96-Hour Capstone Simulation

**Goal:** Full dress rehearsal. Self-imposed exam under strict conditions.

- Pick a chained scenario: unfinished Zephyr/Dante section, or 3 fresh Medium AD boxes chained.
- Hard time cap: 96 hours total, no extensions.
- Concurrent report writing — this becomes **mock report #4**, the one you score against the HTB CPTS official rubric.
- No hints, no IppSec, no notes from Pro Lab solutions.

**Estimated duration:** 5 days.

**Gate to Phase 7:**
- [ ] Simulation objectives completed within 96 hrs
- [ ] Mock report #4 submitted and self-scored against rubric
- [ ] Honest list of mistakes / time sinks captured

---

## Phase 7 — Targeted Review + Taper

**Goal:** Plug gaps from Phase 6, polish, rest. No new content.

| Step | Activity |
|---|---|
| 1 | Re-read all 28 `00-EXAM_CHEATSHEET.md` files. Flag rusty areas. |
| 2 | Targeted reps on rusty areas (likely: BloodHound queries, mimikatz / Rubeus, evil-winrm flags, msfvenom one-liners) |
| 3 | AD attack-path speed drill: Kerberoast → AS-REP → DCSync on a known box, < 90 min |
| 4 | Report-writing drill: exec summary + one finding writeup, 90 min cap |
| 5 | Tool sanity check: VPN, BloodHound, msfvenom, screenshot tooling, report template |
| 6 | **Taper, 2 days minimum.** Light review only. Sleep 8+ hrs. No screens past 6pm on the last day. |
| 7 | **Schedule the exam** — only after gates below all pass. |

**Estimated duration:** 7 days.

---

## Exam Readiness Gates

**Do not schedule the CPTS exam until ALL of these are true.** This is the whole point of going great-prep over good-prep — readiness, not calendar.

- [ ] AEN guided complete + mock report #1 written
- [ ] AEN blind second pass — all hosts solved without notes
- [ ] Zephyr ≥ 90% + mock report #2 written
- [ ] Dante ≥ 75% + mock report #3 written
- [ ] ≥ 15 Medium HTB boxes solved (own work)
- [ ] 96-hr simulation passed + mock report #4 scored against rubric
- [ ] Cheatsheet review complete, no module feels rusty
- [ ] Tool sanity check passed
- [ ] 2-day taper completed

If you can check every box, you are not in the bottom 20% of the exam distribution. Schedule the exam.

---

## Failure modes to watch for

- **Skipping the AEN blind second pass because "I just did it."** That's the test — recognition vs. internalization. Don't skip.
- **Treating Pro Lab as a learning exercise.** It's a calibration exercise. Concurrent report writing is non-negotiable.
- **Spending 12+ hours on a Medium box out of pride.** Cap at 6, then IppSec.
- **Letting the schedule drift right indefinitely.** Push the exam back for readiness gaps, not for procrastination. Track which gate is blocking each week.
- **Skipping IppSec walkthroughs after solves.** You learn methodology this way that you don't get from just solving.
- **Phase 7 becoming a new-content phase.** No. Review only.

---

## Reference reviewers consulted (May 2026)

- Charles-Thibault Sanchez, "HTB CPTS Review 2026"
- Radiant Sec, "How I Passed HTB CPTS"
- UberZachAttack, "CPTS Review (with Pro Labs)"
- Yash, "My CPTS experience"
- whYMiR, "Review: HTB Dante Pro Lab"

Consensus takeaways applied here:
- AEN blind = closest in-Academy exam simulation (Phase 2)
- Pro Labs (Zephyr + Dante) = most exam-like external practice (Phases 3, 4)
- CPTS-track HTB boxes are essential supplements (Phase 5)
- Concurrent report writing is non-negotiable (Phases 1, 3, 4, 6)
- IppSec walkthroughs build methodology, not just commands (Phase 5)
