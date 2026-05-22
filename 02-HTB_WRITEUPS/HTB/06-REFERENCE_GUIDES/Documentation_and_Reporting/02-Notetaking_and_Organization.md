# Section 02 — Notetaking & Organization

> **Lab: optional** — RDP to Parrot VM, explore Obsidian notebook and Tmux logging. Questions are knowledge-based.

**Core principle:** Structured notetaking and organized evidence storage are the foundation of professional reporting. Develop a repeatable process: consistent folder structure, centralized credentials tracking, per-finding evidence folders, and full terminal logging via Tmux.

---

## Notetaking structure (recommended categories)

| Category | Purpose |
|----------|---------|
| Attack Path | Outline of full compromise chain with screenshots and command output |
| Credentials | Centralized list of all compromised creds/secrets |
| Findings | Subfolder per finding — narrative + evidence together |
| Vulnerability Scan Research | What you investigated from scan results (avoid re-doing work) |
| Service Enumeration Research | Services investigated, failed attempts, promising leads |
| Web Application Research | Interesting apps, default creds tried, subdomain results |
| AD Enumeration Research | Step-by-step AD enum performed, areas to revisit |
| OSINT | Collected OSINT data if applicable |
| Administrative Information | POC contacts, RoE flags, to-do list |
| Scoping Information | In-scope IPs/CIDRs, URLs, provided creds |
| Activity Log | High-level log of all testing activities with timestamps |
| Payload Log | Payloads used, file hashes, upload locations, cleanup status |

---

## Notetaking tools

| Local | Cloud | Either |
|-------|-------|--------|
| Obsidian | Notion | GitBook |
| CherryTree | Evernote | Outline (self-hosted option) |
| VS Code | Cryptpad | Standard Notes |
| Sublime Text | | Notepad++ |

> **For real engagements:** Use local storage tools (Obsidian, CherryTree) or company-approved solutions. Cloud tools may violate client data handling policies. Both Obsidian and Outline export to Markdown for portability.

---

## Tmux logging setup

### Install Tmux Plugin Manager

```bash
git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
```

### Create ~/.tmux.conf

```bash
# List of plugins
set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'

# Increase scrollback buffer
set -g history-limit 50000

# Initialize TMUX plugin manager (keep at bottom)
run '~/.tmux/plugins/tpm/tpm'
```

### Activate

```bash
tmux source ~/.tmux.conf
tmux new -s setup
```
> In the session: `[Ctrl]+[B]` then `[Shift]+[I]` to install plugins.

### Key bindings

| Action | Keys |
|--------|------|
| Start/stop logging | `[Ctrl]+[B]` then `[Shift]+[P]` |
| Retroactive capture (save entire pane history) | `[Ctrl]+[B]` then `[Alt]+[Shift]+[P]` |
| Screen capture (single pane snapshot) | `[Ctrl]+[B]` then `[Alt]+[P]` |
| Clear pane history | `[Ctrl]+[B]` then `[Alt]+[C]` |
| Split pane vertically | `[Ctrl]+[B]` then `[Shift]+[%]` |
| Split pane horizontally | `[Ctrl]+[B]` then `[Shift]+["]` |
| Switch panes | `[Ctrl]+[B]` then `[O]` |

### Useful Tmux plugins

| Plugin | Purpose |
|--------|---------|
| tmux-sessionist | Manipulate sessions from within a session |
| tmux-pain-control | Intuitive pane keybindings |
| tmux-resurrect | Restore Tmux environment after host restart |

---

## Folder structure for assessments

```bash
mkdir -p ACME-IPT/{Admin,Deliverables,Evidence/{Findings,Scans/{Vuln,Service,Web,'AD Enumeration'},Notes,OSINT,Wireless,'Logging output','Misc Files'},Retest}
```

```
ACME-IPT/
├── Admin/              ← SoW, kickoff notes, status reports, vuln notifications
├── Deliverables/       ← Report drafts, supplemental spreadsheets, slide decks
├── Evidence/
│   ├── Findings/       ← Subfolder per finding (narrative + evidence)
│   ├── Scans/
│   │   ├── Vuln/      ← Nessus/OpenVAS exports
│   │   ├── Service/   ← Nmap, Masscan output
│   │   ├── Web/       ← Burp state, EyeWitness, Aquatone
│   │   └── AD Enumeration/ ← BloodHound JSON, PowerView CSV, Snaffler logs
│   ├── Notes/          ← Obsidian/markdown notes
│   ├── OSINT/          ← Intelx, Maltego output
│   ├── Wireless/       ← If in scope
│   ├── Logging output/ ← Tmux logs, MSF logs
│   └── Misc Files/     ← Web shells, payloads, custom scripts
└── Retest/             ← Replicate structure for retest evidence
```

---

## Artifacts and tracking

### Payload log (must track)

| Field | Example |
|-------|---------|
| Timestamp | 2026-01-08 14:32 EST |
| Target host | 172.16.5.20 (WEB01) |
| File path on target | C:\inetpub\wwwroot\cmd.aspx |
| File hash (MD5/SHA256) | a3f2... |
| Cleanup status | Removed / Needs client cleanup |

### Account creation / system modifications

Track: IP/hostname, timestamp, description of change, location, app/service affected, account name/password if created. Always get **written approval** before making system modifications.

---

## Evidence best practices

### What to capture

- Terminal output for all significant commands (prefer text over screenshots)
- Screenshots for GUI-based findings (web apps, RDP sessions)
- Successful AND unsuccessful exploitation attempts (shows thoroughness)

### Formatting rules

| Do | Don't |
|----|-------|
| Use text-based terminal output in reports | Screenshot terminal when text is available |
| Redact creds with `<REDACTED>` or solid black bars | Blur/pixelate (reversible with tools like Unredacter) |
| Color-highlight commands (blue) and key output (red) | Alter original command output |
| Crop screenshots to relevant area | Include full desktop screenshots |
| Include URL bar / hostname for context | Leave reader guessing which host |
| Strip formatting before pasting into Word | Paste with embedded formatting (breaks Unicode) |
| Mark removed output with `<SNIP>` | Delete output without indicating removal |

### What NOT to archive

- Unredacted PII (screenshot filenames, not file contents)
- Potentially criminal content
- Legally "discoverable" materials
- Actual sensitive data extracted from target (compliance risk: GDPR, etc.)

> If you find a share full of sensitive data, screenshot the directory listing — don't open and screenshot individual files.

---

## Answers

| Question | Answer |
|----------|--------|
| Q1: Tool that makes logging a session easier | `Tmux` |
| Q2: Split panes vertically keybinding | `[Ctrl] + [B] + [Shift] + [%]` |

---

## Key takeaways

- **Tmux logging captures everything.** Set it up once, never lose terminal evidence again. The `history-limit 50000` setting prevents buffer loss on retroactive captures.
- **One folder per finding** keeps evidence organized and makes report assembly trivial — just walk through each folder.
- **Activity and payload logs are non-negotiable.** If a client asks "did you scan X on day Y?" you must be able to answer immediately.
- **Text over screenshots** — easier to redact, format, and reproduce. Use `<SNIP>` for truncation, never alter output.
- **Never blur/pixelate** — use solid black bars. Pixelation is reversible.
- **Obsidian + folder structure = single source of truth.** Markdown is portable, version-controllable, and tool-agnostic.
