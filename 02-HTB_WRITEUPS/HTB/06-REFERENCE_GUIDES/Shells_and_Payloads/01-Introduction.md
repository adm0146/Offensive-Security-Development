# 01 — Introduction: Shells & Payloads

## Overview

**Shells** give us interactive access to a target's operating system. **Payloads** are the code we deliver to get those shells. This entire module is about what happens **after** enumeration — turning a discovered vulnerability into actual system access.

---

## What Is a Shell?

A program that provides a user interface to input commands and view output.

| Context | Meaning |
|---------|---------|
| **Computing** | Text-based environment for administering tasks — Bash, Zsh, cmd, PowerShell |
| **Exploitation** | The result of exploiting a vulnerability to gain remote interactive access (e.g., triggering EternalBlue to get a cmd prompt) |
| **Web** | A script uploaded to a web server that lets you issue commands through a browser |

> When someone says "I popped a shell" — they exploited a vulnerability and now have remote command-line access to the target.

---

## Why Get a Shell?

A shell is the **gateway to everything else** in a pentest:

| Capability | Why It Matters |
|------------|---------------|
| **System enumeration** | Discover privesc vectors, users, configs |
| **Privilege escalation** | Elevate from user to root/admin |
| **Pivoting** | Move laterally to other systems on the network |
| **File transfers** | Upload tools, download loot |
| **Persistence** | Maintain access over time |
| **Data exfiltration** | Gather and extract target data |
| **Documentation** | Capture evidence for your report |

> Without a shell, you're limited to whatever the initial vulnerability gives you. With a shell, you own the system.

---

## CLI vs GUI Access

| Factor | CLI Shell (Bash/cmd) | GUI Shell (RDP/VNC) |
|--------|---------------------|---------------------|
| **Stealth** | ✅ Harder to detect | ❌ Visible to logged-in users |
| **Speed** | ✅ Faster navigation | ❌ Slower, mouse-dependent |
| **Automation** | ✅ Easy to script | ❌ Difficult to automate |
| **Bandwidth** | ✅ Minimal | ❌ Heavy (streaming video) |

> CLI shells are preferred in almost every scenario — faster, stealthier, scriptable.

---

## What Is a Payload?

The term "payload" means different things depending on context:

| Context | Definition |
|---------|-----------|
| **Networking** | The data portion of a packet (minus headers) |
| **Computing** | The part of an instruction that defines the action |
| **Programming** | The data carried by a programming instruction |
| **Exploitation** | Code crafted to exploit a vulnerability — reverse shells, web shells, ransomware, etc. |

> In this module: **payload = the code we use to get a shell on the target.**

---

## Module Focus

This module covers:

1. Different **types of shells** (bind, reverse, web)
2. **Payload creation** and delivery methods
3. **Establishing remote sessions** with vulnerable systems
4. Everything that comes **after enumeration** — turning findings into access

> 💡 Enumeration finds the door. Payloads open it. Shells let you walk through.
