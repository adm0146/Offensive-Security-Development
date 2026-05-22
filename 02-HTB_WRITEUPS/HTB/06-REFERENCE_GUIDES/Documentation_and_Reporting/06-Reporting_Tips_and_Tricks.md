# Section 06 — Reporting Tips and Tricks

> **Lab: no** — Reading-only section covering MS Word efficiency, automation, QA processes, and client communication.

**Core principle:** Write the report as you test — not after. Use templates, automation, and a QA process to produce consistent, professional deliverables. The report is your highlight reel; treat it with the same intensity as the exploitation itself.

---

## Core workflow rule: Write as you go

- Fill in templated sections (contact info, scope, dates) during long scans
- Write up findings with evidence immediately after exploitation
- Build the attack chain incrementally as you progress
- Don't leave reporting until the last day — rushed reports get kicked back from QA

---

## Templates

- Maintain blank templates for every assessment type (internal, external, web app, physical, etc.)
- **Never modify a previous client's report** — risk leaving their name/data in the new report
- Use placeholders and macros for commonly repeated fields
- Save templates as `.dotm` files for macro support

---

## MS Word tips & tricks

### Essentials

| Feature | Why It Matters |
|---------|----------------|
| **Font styles** | Update one style → updates all instances globally. Eliminates manual formatting |
| **Table styles** | Same concept — global consistency for all tables |
| **Captions** | Right-click → Insert Caption. Auto-renumbers when you add/remove figures |
| **Page numbers** | Required for client collaboration ("What does page 12 mean?") |
| **Table of Contents** | Standard professional component — auto-generates from heading styles |
| **Bookmarks** | Hyperlink targets for appendices; section markers for macro automation |
| **Custom dictionary** | Auto-correct common typos ("pubic" → "public") |
| **Language settings** | Set code/terminal font style to "Do not check spelling" — stops spell-checker noise |
| **Custom numbering** | Auto-number findings, appendices, and other sequential elements |

### Useful hotkeys

| Hotkey | Action |
|--------|--------|
| `F4` | Repeat last action (apply same style to new selection) |
| `Ctrl+A` then `F9` | Update all fields (ToC, figure lists) |
| `Ctrl+S` | Save (do this constantly) |
| `Ctrl+Alt+S` | Split window into two panes (view two areas simultaneously) |
| `Shift+F5` | Jump cursor to last edit location |

### Quick Access Toolbar additions

- **Back** — return to previous position after clicking a hyperlink
- **Undo/Redo** — if you don't use keyboard shortcuts
- Browse "Commands Not in the Ribbon" for hidden gems

---

## Automation with macros

| Use Case | How |
|----------|-----|
| Auto-fill client info | Pop-up prompts insert client name, dates, scope into placeholder variables |
| Combine templates | Merge multiple assessment-type templates; macro removes irrelevant sections via bookmarks |
| QA automation | Correct common errors programmatically |

> Requires Windows Word (Mac VB Editor is useless). Save as `.dotm` for macro support.

---

## Reporting tools / findings database

Maintain a sanitized findings database to avoid rewriting the same content repeatedly. Customize per client but start from templates.

| Free | Paid |
|------|------|
| Ghostwriter | AttackForge |
| Dradis | PlexTrac |
| VECTR (Security Risk Advisors) | Rootshell Prism |
| WriteHat | |

---

## Miscellaneous tips

### Evidence presentation
- Tell a story — connect findings to business impact
- Show enough evidence to reproduce, but don't paste 50 pages of console output
- Use Greenshot for arrows/boxes on screenshots (solid shapes, never blur)
- Redact credentials, hashes, and crude tool output (e.g., CrackMapExec's "Pwn3d!")
- Check Hashcat output for offensive candidate passwords — sanitize if present
- Include URL bar or `ipconfig` to prove target identity in screenshots

### Professionalism
- Keep hostname/username professional (not `azzkicker@clientsmasher`)
- Solid black terminal background, white/green text — no crazy themes
- Consider light backgrounds for clients who print reports
- Disable bookmarks bar and unprofessional browser extensions
- Spell out acronyms on first use

### Quality
- Grammar, spelling, formatting — check all three
- Use Grammarly/LanguageTool (with approval — they may ship data to cloud)
- Consistent fonts and sizes throughout
- Autosave everything — notetaking tool AND Word
- Back up evidence to secondary location daily (VMs can fail)

---

## QA process

### Why it matters
> A sloppy report calls into question your entire assessment. The report IS what the client is paying for.

### Process

```
Author completes report
→ Self-review (sleep on it, come back fresh)
→ QA Round 1: Technical accuracy (findings, evidence, reproduction steps)
→ QA Round 2: Style, grammar, formatting (optional separate reviewer)
→ Author addresses feedback (Track Changes ON)
→ Draft issued to client
→ Client review meeting (1 week later)
→ Final report issued (with any client-requested changes)
```

### QA rules
- Author should NOT be the only reviewer
- QA reviewer fixes minor typos directly; sends back for major issues
- Include a QA checklist in your template (remove before finalizing)
- Track common mistakes → add to checklist to prevent recurrence
- Online grammar tools may send data to cloud — verify compliance first

---

## Client communication

### Start notification (beginning of each day/engagement)

Include:
- Tester name
- Assessment type and scope description
- Source IP address(es) for testing
- Expected testing dates
- Primary and secondary contact info (email + phone)

### Stop notification (end of each day)

- Signal end of testing window
- High-level summary of findings (prevents report blindsiding)
- Reiterate report delivery timeline

### During testing

| Situation | Action |
|-----------|--------|
| Found additional subnet/subdomain | Ask client if they want to add to scope |
| Critical external RCE / SQLi | Stop testing, formally notify client |
| Host seems down from scanning | Be upfront immediately |
| Achieved DA/EA | Notify client, ask about additional focus areas |
| Client asks about specific host activity | Produce timestamped evidence from logs |

---

## Report delivery lifecycle

```
Draft Report → Client (1 week to review)
→ Report Review Meeting (walk through findings, answer questions)
→ Address any client feedback/changes
→ Change "DRAFT" to "FINAL"
→ Deliver Final Report
→ Archive all testing data per retention policy
```

---

## Key takeaways

- **Write as you test.** The report should be 80% done when testing ends — not 0%.
- **Use templates, never modify old client reports.** One leftover client name destroys credibility.
- **Font styles and table styles save hours.** One change updates the entire document globally.
- **Maintain a findings database.** Same findings appear across clients — don't rewrite from scratch every time.
- **QA is non-negotiable.** Someone other than the author must review. Sleep on it if you're solo.
- **Communicate proactively.** Start/stop notifications, critical finding alerts, and scope questions build trust and win repeat business.
- **The report is your highlight reel.** The coolest attack chain ever means nothing if it can't be understood on paper.
