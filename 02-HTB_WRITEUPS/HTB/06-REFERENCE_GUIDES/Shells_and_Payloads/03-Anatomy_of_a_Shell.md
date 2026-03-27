# 03 — Anatomy of a Shell

## Overview

A shell has three layers: the **OS**, the **terminal emulator** (the window), and the **command language interpreter** (the program that understands your commands). Understanding which interpreter is running tells you what commands and scripts will work.

---

## The Three Layers

```
┌─────────────────────────┐
│   Terminal Emulator      │  ← The window you type in (MATE, iTerm2, Windows Terminal)
│  ┌───────────────────┐  │
│  │ Command Language   │  │  ← The interpreter (Bash, PowerShell, Zsh, cmd)
│  │ Interpreter        │  │
│  │  ┌─────────────┐  │  │
│  │  │ Operating    │  │  │  ← The OS processing your commands
│  │  │ System       │  │  │
│  │  └─────────────┘  │  │
│  └───────────────────┘  │
└─────────────────────────┘
```

---

## Common Terminal Emulators

| Terminal | OS |
|----------|-----|
| Windows Terminal | Windows |
| cmder | Windows |
| PuTTY | Windows |
| kitty | Windows, Linux, macOS |
| Alacritty | Windows, Linux, macOS |
| xterm | Linux |
| GNOME Terminal | Linux |
| MATE Terminal | Linux |
| Konsole | Linux |
| Terminal.app | macOS |
| iTerm2 | macOS |

> Terminal emulator choice is personal preference. What matters for pentesting is knowing **which interpreter is running on the target**.

---

## Command Language Interpreters

The interpreter is the program that **parses and executes** your commands. Different interpreters recognize different commands.

| Interpreter | Platform | Prompt Symbol |
|-------------|----------|---------------|
| Bash | Linux/macOS | `$` |
| Zsh | Linux/macOS | `$` or `%` |
| sh (POSIX) | Linux/macOS | `$` |
| cmd.exe | Windows | `C:\>` |
| PowerShell | Windows/Linux | `PS >` |
| fish | Linux/macOS | `>` |

> The `$` prompt = Bash/Zsh/POSIX shell. `PS` prompt = PowerShell. `C:\>` = cmd.exe. This tells you what commands will work.

---

## Identifying the Active Shell

### Method 1: Check Running Processes

```bash
ps
```

```
  PID TTY          TIME CMD
 4232 pts/1    00:00:00 bash
11435 pts/1    00:00:00 ps
```

> The `CMD` column shows `bash` — that's your interpreter.

### Method 2: Check Environment Variables

```bash
env | grep SHELL
```

```
SHELL=/bin/bash
```

> `SHELL` variable tells you the default shell for the user.

### Method 3: Just Look at the Prompt

- `$` → Bash, Zsh, sh
- `PS C:\>` or `PS />` → PowerShell
- `C:\Users\>` → cmd.exe
- `#` → Root shell (Bash/Zsh as root)

---

## Key Concept: One Terminal, Multiple Interpreters

A terminal emulator is **not locked to one interpreter**. The same MATE Terminal window can run:

- Bash (default on most Linux)
- PowerShell (`pwsh` command)
- Python (`python3` for a Python REPL)
- sh, zsh, fish, etc.

> This matters during engagements — if Bash is restricted, you might switch to `sh` or `python3` for a shell. Same terminal, different interpreter.

---

## Why This Matters for Pentesting

| Situation | Implication |
|-----------|-------------|
| Target runs Bash | Use Linux commands, Bash one-liners, shell scripts |
| Target runs PowerShell | Use PowerShell cmdlets, .NET methods |
| Target runs cmd.exe | Use Windows built-in commands, batch scripts |
| Shell is restricted | Try switching interpreters (`python3`, `sh`, `perl`) |
| Need to identify the shell | `ps`, `env`, or read the prompt symbol |

> Knowing the interpreter = knowing what tools and syntax are available to you on the target.
