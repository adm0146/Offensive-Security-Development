# CPTS Prep Schedule — May 27 → July 12, 2026

**Exam date:** 2026-07-12 (10-day exam window)
**Schedule created:** 2026-05-27 (46 days out)
**Time budget assumption:** ~3.5 hrs/day weekday + ~6 hrs/day weekend ≈ 30 hrs/week, ~180 hrs total

---

## State entering this plan

- 27/28 HTB Academy CPTS modules documented with reference guides + exam cheatsheets
- Missing module: **Attacking Enterprise Networks** (capstone — folder does not exist)
- Missing cheatsheet: `Using_Web_Proxies/00-EXAM_CHEATSHEET.md` (only module without one)
- HTB box practice: 22 boxes, all Very Easy / Easy tier. **Zero Medium or above.**
- Pivoting: only practiced on FUNNEL (Very Easy SSH tunnel)
- Reporting: complete module, no end-to-end mock report artifact exists
- Pro Lab: **buying Zephyr** (AD-heavy, most CPTS-exam-aligned)

---

## Phase 1 — AEN Blind Run (May 27 – June 5, 10 days)

**Goal:** Complete Attacking Enterprise Networks module without reading sections ahead. First mock exam.

| Day | Date | Focus |
|---|---|---|
| Wed | 5/27 | Scaffold `06-REFERENCE_GUIDES/Attacking_Enterprise_Networks/` folder. Set up Kali, OpenVPN, fresh note template. Begin AEN engagement blind. |
| Thu–Mon | 5/28 – 6/1 | Work AEN sections. Take exam-style notes from minute one. Optimize for the report, not the reference guide. |
| Tue–Wed | 6/2 – 6/3 | Finish remaining hosts / objectives. |
| Thu–Fri | 6/4 – 6/5 | Write a full end-to-end pentest report: executive summary, methodology, findings, screenshots, remediation. Half of CPTS grading is the report. |

**Deliverables:**
- AEN module folder + section guides + `00-EXAM_CHEATSHEET.md`
- First end-to-end mock report (.md or .docx)

---

## Phase 2 — Zephyr + AD Box Reps (June 6 – June 17, 12 days)

**Goal:** Calibrate to Medium difficulty. Most exam-aligned external practice.

| Day | Date | Focus |
|---|---|---|
| Sat–Sun | 6/6 – 6/7 | Buy Zephyr cubes, VPN setup, start first 25% of Zephyr (5–6 hosts) |
| Mon–Wed | 6/8 – 6/10 | Continue Zephyr OR retired CPTS-track AD boxes: **FOREST**, **ACTIVE** + IppSec walkthrough |
| Thu–Sat | 6/11 – 6/13 | **SAUNA** (AS-REP roasting), **MONTEVERDE** (Azure ADConnect) |
| Sun–Tue | 6/14 – 6/16 | **RESOLUTE** (DnsAdmins), one Linux-heavy box (CAP / KNIFE) |
| Wed | 6/17 | Catch-up day. Write mini-report on hardest box from this phase. |

**Rule:** If a box takes > 6 hours without progress, watch IppSec walkthrough for that point. Methodology > pride.

---

## Phase 3 — Pivoting + Web Depth (June 18 – June 26, 9 days)

**Goal:** Build pivoting muscle memory, shore up missing cheatsheet, drill weak web areas.

| Day | Date | Focus |
|---|---|---|
| Thu | 6/18 | Add `00-EXAM_CHEATSHEET.md` to `Using_Web_Proxies/`. Re-read Pivoting_Tunneling guide. |
| Fri–Sun | 6/19 – 6/21 | Two pivoting-required boxes (Zephyr hosts requiring chisel/proxychains, or REEL / MULTIMASTER). Drill: `ssh -L/-D/-R`, chisel client/server, proxychains4, socat relay. |
| Mon–Wed | 6/22 – 6/24 | One web-heavy box per day. Bias toward modules you trust least: SQLi, file upload, deserialization. |
| Thu–Fri | 6/25 – 6/26 | **Mock report #2** on a chained-pivot box. "Report as you go" workflow under time pressure: 24 hrs foothold → report. |

---

## Phase 4 — Capstone Simulation (June 27 – July 4, 8 days)

**Goal:** Full exam dress rehearsal.

| Day | Date | Focus |
|---|---|---|
| Sat–Sun | 6/27 – 6/28 | Push toward Zephyr completion (or 2 fresh Medium AD boxes) |
| Mon–Thu | 6/29 – 7/2 | **96-hour simulated exam.** Chained scenario: remaining Zephyr, or self-imposed 3-box chain. Strict hours. Concurrent report. |
| Fri–Sat | 7/3 – 7/4 | Finalize simulation report. Compare against Phase 1 AEN report — what improved, what's still rough. |

---

## Phase 5 — Targeted Review (July 5 – July 9, 5 days)

**Goal:** Plug gaps surfaced in Phases 2–4. No new content.

| Day | Date | Focus |
|---|---|---|
| Sun | 7/5 | Re-read all 28 `00-EXAM_CHEATSHEET.md` files. Flag rusty areas. |
| Mon | 7/6 | Targeted reps on rustiest 2–3 areas (likely candidates: BloodHound queries, mimikatz/Rubeus syntax, evil-winrm flags, msfvenom one-liners) |
| Tue | 7/7 | AD attack-path speed drill: Kerberoast → AS-REP → DCSync on a known box. Target < 90 min. |
| Wed | 7/8 | Report-writing drill: executive summary + one full finding writeup against a solved box. 90 min cap. |
| Thu | 7/9 | Tool sanity check: VPN, BloodHound, msfvenom encoding, screenshot tooling, report template. Patch Kali. |

---

## Phase 6 — Taper (July 10 – July 11, 2 days)

| Day | Date | Focus |
|---|---|---|
| Fri | 7/10 | Light review only. Cheatsheets, no new boxes. Sleep 8+ hrs. |
| Sat | 7/11 | Full rest. No screens past 6pm. Lay out exam-day setup. |
| **Sun** | **7/12** | **Exam starts. 10-day window.** |

---

## Acceptance criteria (per phase)

| Phase | Done when |
|---|---|
| 1 | AEN folder populated, blind run complete, mock report written |
| 2 | Zephyr ≥ 50%, ≥ 4 Medium AD boxes solved (own work or with IppSec assist) |
| 3 | 2+ pivoting boxes solved, Web_Proxies cheatsheet added, mock report #2 written |
| 4 | 96-hr simulation completed with concurrent report |
| 5 | All 28 cheatsheets re-read, weak areas drilled |
| 6 | Rested, environment verified |

---

## Failure modes to watch for

- **Sinking 12+ hours into a single Medium box out of pride.** Cap at 6, then IppSec.
- **Treating AEN as a learning exercise instead of a mock exam.** Read-ahead defeats the point.
- **Skipping the concurrent report.** This is the most common reason CPTS candidates fail the exam despite solid technical execution.
- **Phase 5 becoming a new-content phase.** No. Review only.
- **Skipping Phase 6 taper.** Sleep deprivation on Day 1 of a 10-day exam compounds.

---

## Reference reviewers consulted (May 2026)

- Charles-Thibault Sanchez, "HTB CPTS Review 2026"
- Radiant Sec, "How I Passed HTB CPTS"
- UberZachAttack, "CPTS Review (with Pro Labs)"
- Yash, "My CPTS experience"

Consensus takeaways applied here:
- AEN done blind = closest in-Academy exam simulation
- Pro Lab (Zephyr preferred) = most exam-like external practice
- CPTS-track HTB boxes are essential, not optional — but not random boxes
- Concurrent report writing is non-negotiable
