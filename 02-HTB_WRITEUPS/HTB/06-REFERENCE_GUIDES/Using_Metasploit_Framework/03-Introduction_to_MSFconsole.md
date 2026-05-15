# 03 — Introduction to MSFconsole

## Overview

`msfconsole` is the primary command-line interface for interacting with the Metasploit Framework. This section covers launching it, keeping it updated, and understanding the engagement structure that guides how MSF is used during assessments.

---

## Launching MSFconsole

### Standard Launch (with banner)

```bash
msfconsole
```
> Launches with the full banner showing exploit/payload/module counts. On slow machines give it 10–15 seconds to start the Java VM.

### Quiet Launch (no banner)

```bash
msfconsole -q
```
> Skips the banner and drops straight to the `msf6 >` prompt. Use this on the exam to save time.

### View All Available Commands

```bash
msf6 > help
```
> Lists every available command with brief descriptions. Pipe through `grep` to find specific commands.

---

## Keeping Metasploit Updated

| Method | Command | Notes |
|--------|---------|-------|
| **Current method (apt)** | `sudo apt update && sudo apt install metasploit-framework` | Handles module and feature updates |
| **Old method (deprecated)** | `msfupdate` | No longer the preferred approach |

---

## MSF Engagement Structure

The framework divides an engagement into five main categories:

```
┌──────────────────────────────────────────────────────────────┐
│  1. ENUMERATION                                              │
│     ├── Service Validation                                   │
│     └── Vulnerability Research                               │
├──────────────────────────────────────────────────────────────┤
│  2. PREPARATION                                              │
│     └── Code Auditing                                        │
├──────────────────────────────────────────────────────────────┤
│  3. EXPLOITATION                                             │
│     └── Module Execution                                     │
├──────────────────────────────────────────────────────────────┤
│  4. PRIVILEGE ESCALATION                                     │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│  5. POST-EXPLOITATION                                        │
│     ├── Pivoting                                             │
│     └── Data Exfiltration                                    │
└──────────────────────────────────────────────────────────────┘
```

### Category Breakdown

| Phase | Purpose | Key Actions |
|-------|---------|-------------|
| **Enumeration** | Identify what's running on the target | Scan target IPs, identify services and versions, validate vulnerabilities |
| **Preparation** | Get the right tools ready | Audit exploit code, select modules, configure payloads |
| **Exploitation** | Gain initial access | Execute the selected module against the target |
| **Privilege Escalation** | Elevate access | Move from low-privilege user to admin/root/SYSTEM |
| **Post-Exploitation** | Achieve objectives | Pivot to other hosts, exfiltrate data, establish persistence |

---

## The Role of Enumeration

Before any exploitation attempt, thorough enumeration is required:

| Question | Why It Matters |
|----------|----------------|
| What public-facing services are running? | Determines which modules to search for |
| What versions are installed? | **Versions are the key component** — unpatched versions are your entry point |
| Is it HTTP, FTP, SQL, SMB? | Different services have completely different attack vectors |

> **Versions are everything.** Unpatched versions of previously vulnerable services or outdated code in publicly accessible platforms will often be the entry point into the target system.

---

## MSFconsole Launch Summary

| Option | Command | Result |
|--------|---------|--------|
| Standard | `msfconsole` | Full banner + stats (exploits, auxiliary, post, payloads, etc.) |
| Quiet | `msfconsole -q` | Straight to `msf6 >` prompt |
| Help | `help` | Lists all available commands |
| Update | `sudo apt update && sudo apt install metasploit-framework` | Updates to latest version |

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **msfconsole is THE interface** | Only fully supported way to access most MSF features |
| **Update via apt** | `msfupdate` is deprecated — use `sudo apt update && sudo apt install metasploit-framework` |
| **5-phase structure** | Enumeration → Preparation → Exploitation → Privilege Escalation → Post-Exploitation |
| **Versions are the key** | During enumeration, identifying service versions determines if the target is vulnerable |
| **Enumerate before exploiting** | Never attempt exploitation without detailed target reconnaissance first |
| **Experiment freely** | Try out every function — hands-on experimentation is how you learn MSF |
