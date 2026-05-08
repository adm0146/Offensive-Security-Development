# 05 — Targets

## Overview

Targets are unique operating system identifiers that adapt a selected exploit module to run on a specific version of the operating system. Choosing the correct target ensures the exploit uses the right return addresses and parameters for the victim's environment.

---

## Viewing Targets

### From Root Menu (no module selected)

```bash
msf6 > show targets
[-] No exploit module selected.
```

> You must select an exploit module first before viewing targets.

### From Within a Module

```bash
msf6 exploit(windows/smb/ms17_010_psexec) > show targets

Exploit targets:
   Id  Name
   --  ----
   0   Automatic
```

Some exploits have only one target (Automatic). Others have many:

```bash
msf6 exploit(windows/browser/ie_execcommand_uaf) > show targets

Exploit targets:
   Id  Name
   --  ----
   0   Automatic
   1   IE 7 on Windows XP SP3
   2   IE 8 on Windows XP SP3
   3   IE 7 on Windows Vista
   4   IE 8 on Windows Vista
   5   IE 8 on Windows 7
   6   IE 9 on Windows 7
```

---

## Setting a Target

| Command | Effect |
|---------|--------|
| `set target 0` | **Automatic** — MSF performs service detection before exploiting |
| `set target 6` | Manually select a specific target (e.g., IE 9 on Windows 7) |

```bash
msf6 exploit(windows/browser/ie_execcommand_uaf) > set target 6
target => 6
```

### When to Use Automatic vs Manual

| Scenario | Choice |
|----------|--------|
| You don't know exact OS/service versions | Use `Automatic` — MSF detects before exploiting |
| You've confirmed the exact version via enumeration | Set the specific target for reliability |
| Automatic fails but you know the target | Try setting it manually |

---

## What Makes Targets Different

Targets vary based on several factors:

| Factor | Description |
|--------|-------------|
| **Service Pack** | Different SPs change memory addresses |
| **OS Version** | Each version has different binary layouts |
| **Language Version** | Language packs shift addresses |
| **Software Version** | Different versions of the vulnerable software |
| **Return Address** | The core differentiator — varies by all of the above |

### Return Address Types

| Type | Description |
|------|-------------|
| `jmp esp` | Jump to the stack pointer |
| Register jump | Jump to a specific register that identifies the target |
| `pop/pop/ret` | Stack manipulation to reach shellcode |

> Comments in the exploit module's code help determine what defines each target. Use `info` to understand target dependencies.

---

## Identifying Targets Correctly

To correctly identify a target, you need to:

1. **Obtain a copy of the target binaries** — know exactly what's running
2. **Use `msfpescan`** — locate a suitable return address in the binary
3. **Check exploit comments** — module code comments explain target definitions

---

## Best Practice: Always Use `info` First

```bash
msf6 exploit(windows/browser/ie_execcommand_uaf) > info
```

This reveals:
- **Available targets** with OS/version combinations
- **Description** explaining vulnerability mechanics
- **Dependencies** (e.g., "JRE 1.6.x or below must be installed")
- **References** (CVEs, Microsoft bulletins)

> **Audit your code.** Always check `info` before running a new module — understand what it does, what artifacts it generates, and what conditions must exist on the target.

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **`show targets`** | Only works inside a selected exploit module |
| **`set target <id>`** | Manually select a target when you know the version |
| **Automatic** | MSF auto-detects — useful when unsure, but less reliable |
| **Targets differ by return address** | Service packs, language packs, and software versions shift memory addresses |
| **`info` first** | Always check module info before running — understand dependencies and target requirements |
| **`msfpescan`** | Tool for locating return addresses in target binaries |
| **Manual > Automatic when possible** | If enumeration confirms the exact version, set it manually for reliability |
