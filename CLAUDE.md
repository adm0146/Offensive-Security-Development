# Cybersecurity Workspace — Context for Claude

## Workspace setup

- **Primary workspace:** native **Kali Linux desktop**. All hands-on lab work (AEN, Pro Labs, HTB boxes) happens there.
- **Mac mirror at** `/Users/andym/Desktop/Cybersecurity_Professional_Development/` — used for planning, reading reference guides, and pushing/pulling.
- **This folder is its own git repo** (separate from the home directory's git repo on the Mac). Remote: `https://github.com/adm0146/Offensive-Security-Development.git`. Active branch: `main`. Always `cd` here before any git command.

## User profile

CPTS candidate. Passed Security+ Jan 2026 (768/900). Cert pathway: **CPTS → CRTO → CRTE → CARTP** (offensive security focus).

## CPTS state (last updated 2026-05-27)

- 27/28 HTB Academy CPTS modules documented with reference guides + exam cheatsheets at `02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/`.
- **AEN module: in progress, ~24% complete.** Being done on Kali as a guided walkthrough.
- HTB box reps: 22 boxes, all Very Easy / Easy tier. Zero Medium+ as of late May 2026.
- Pro Labs: **buying Zephyr first, then Dante.**
- Exam: **readiness-gated, no fixed date.** Earlier dates (June, July) pushed back. User decided to prioritize internalization over calendar.

## Active schedule

Lives at `CPTS_PREP_SCHEDULE_2026.md` in this repo root. Great-prep version, readiness-gated, ~300–400 hrs total estimated, 9 explicit gates before sitting the exam.

## Collaboration mode (AEN + future labs)

User wants **reasoning help, not exploit handouts.** When working through a host/section:

- Ask "what does enum show, what does the privilege/permission imply, what have you tried?" before suggesting the next move.
- Explain *why* a technique works, not just the command.
- Push back if user reaches for a tool before they've justified it.
- For pure CTF / box solving: same rule — methodology coaching, not walkthrough.

This shifts looser in Phase 2+ (Zephyr / Dante / Medium boxes) where user should drive more independently — assistant is a stuck-rule fallback, not a co-pilot.

## Honest-assessment preference

User explicitly wants blunt critique, not encouragement. When asked about prep quality, readiness, gaps, or current state:

- Lead with the gap or weakness.
- Reserve praise for things genuinely strong.
- Don't pad with "great job" before delivering critique.
- Specific verdict (% pass probability, percentile positioning) is welcome.

Validated 2026-05-27 when user accepted "you're 70% ready, not 97%" framing without pushback.

## Reference docs in this repo

- `README.md` — top-level project overview
- `CPTS_PREP_SCHEDULE_2026.md` — active prep schedule (great-prep v2)
- `02-HTB_WRITEUPS/HTB/06-REFERENCE_GUIDES/` — 26 module folders, each with section MDs + `00-EXAM_CHEATSHEET.md`
- `02-HTB_WRITEUPS/HTB/Enumeration_Checklist.md` — methodology checklist
- `00-archived/00-roadmap/COMPREHENSIVE_CERTIFICATION_PATHWAY_2026.md` — **currently corrupted with merge residue, do not trust until cleaned up**
- `00-private/` — personal files, do not touch unless explicitly asked

## Out of scope

- Don't proactively edit files in `00-private/`.
- Don't push to GitHub without explicit confirmation from the user — only push when asked.
- Don't add modules / content to AEN or Pro Lab folders from this Mac — the user writes those on Kali and pushes from there.
