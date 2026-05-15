# 08 — Latest SMB Vulnerabilities

## Overview

Beyond credentialed attacks (spraying, relay, PtH), the SMB protocol has been hit by several **pre-auth RCE vulnerabilities** in the protocol/driver layer itself. The flagship example is **SMBGhost (CVE-2020-0796)** — an unauthenticated RCE in SMB v3.1.1's compression mechanism affecting Windows 10 builds **1903** and **1909**.

This section covers the **conceptual framework** of these attacks (Source → Process → Privileges → Destination) rather than the exploit-dev internals.

---

## SMBGhost — CVE-2020-0796

| Property | Detail |
|----------|--------|
| **CVE** | CVE-2020-0796 |
| **Aliases** | SMBGhost, CoronaBlue |
| **Class** | Pre-auth Remote Code Execution (Integer Overflow) |
| **Protocol** | SMB v3.1.1 |
| **Vector** | Compression in SMB session negotiation |
| **Affected** | Windows 10 v1903 & v1909, Windows Server 1903/1909 |
| **Impact** | Full SYSTEM-level RCE, no authentication required |
| **Patch** | KB4551762 (March 2020) |

### Root Cause

An **integer overflow** in an SMB driver function that lacked bounds checks while processing the size of compressed data during SMB session negotiation. Because the function trusts an attacker-controlled length field, a crafted compressed message can write past the allocated buffer and overwrite **subsequent CPU instructions** in kernel memory — replacing the planned execution flow with attacker-supplied instructions.

> **Integer overflow:** when an arithmetic operation produces a value larger than the variable can hold (or wraps a positive into a negative), bypassing assumed bounds. Common when developers don't validate ranges or signedness.

### Why It's Dangerous
- **Pre-auth** — no credentials needed; only an open TCP/445.
- **Wormable** — like EternalBlue, it can spread node-to-node automatically.
- **Kernel-level** — code executes as `NT AUTHORITY\SYSTEM`.

---

## The Concept of Attacks Framework

All exploitation, regardless of complexity, can be modeled with **four categories**:

| Category | Question it answers |
|----------|---------------------|
| **Source** | Where is the malicious input coming from? |
| **Process** | What component handles/parses the input? |
| **Privileges** | Under what security context does the process run? |
| **Destination** | Where does the attacker want execution/data to land? |

```
[Source] ──▶ [Process] ──▶ [Privileges] ──▶ [Destination]
   │             │                                │
attacker      vulnerable                     attacker-controlled
 input        parser/code                     code execution
```
> The categories are constant across all vulnerability types. Memorize this flow — it helps you understand any exploit write-up quickly.

Apply this to **any** vuln (SQLi, deserialization, BOF, format string) — the structure is constant.

---

## SMBGhost Mapped to the Framework

### Cycle 1 — Trigger the Overflow

| Step | SMBGhost Action | Category |
|------|-----------------|----------|
| 1 | Attacker-crafted SMB request sent to victim's SMB server | **Source** |
| 2 | Compressed packets processed per negotiated protocol responses | **Process** |
| 3 | SMB driver runs in kernel — SYSTEM/admin privileges | **Privileges** |
| 4 | Local SMB process is the buffer being corrupted | **Destination** |

After cycle 1, the buffer has been overflowed and CPU instructions in memory are now attacker-controlled.

### Cycle 2 — Convert Overflow to RCE

| Step | SMBGhost Action | Category |
|------|-----------------|----------|
| 5 | Output of cycle 1 (overwritten instructions) becomes new input | **Source** |
| 6 | CPU executes the attacker's instructions instead of the original | **Process** |
| 7 | Inherits SMB driver context — full SYSTEM | **Privileges** |
| 8 | Remote attacker host receives shell / agent callback | **Destination** |

The two-cycle model is generalizable: **memory-corruption exploits almost always have a "trigger" stage and a "payload" stage**, each independently fitting the four-category schema.

---

## Detection & Validation

### Quick check — is the host vulnerable?
```bash
# Public PoC scanner
nmap -p445 --script smb-protocols 10.10.10.10
nmap -p445 --script smb2-vuln-uptime,smb-vuln-ms17-010 10.10.10.10
```
> `smb-protocols` checks which SMB versions the target advertises. `smb2-vuln-uptime` and `smb-vuln-ms17-010` check for known SMB vulnerabilities. Replace the IP with your target.

For SMBGhost specifically:
```bash
# ZecOps scanner (PoC)
python3 SMBGhost_scanner.py 10.10.10.10
```
> Download the ZecOps scanner from GitHub. Replace the IP with your target. This only checks for vulnerability — it does not exploit.
Indicators:
- SMB 3.1.1 advertised in dialect negotiation.
- `SMB2_COMPRESSION_CAPABILITIES` present in negotiate response.
- Unpatched Windows 10 v1903 / v1909.

### Public Exploit (use only in authorized labs)
```bash
# chompie1337 RCE PoC
python3 SMBGhost_RCE_PoC.py -ip 10.10.10.10
# → SYSTEM shell on success; BSOD on failure
```
> `-ip` specifies the target. Replace with your target's IP. This PoC is unstable — take a VM snapshot before running. A failed attempt will BSOD the target machine.
> **Warning:** SMBGhost RCE PoCs are **highly unstable** — failed exploitation almost always BSODs the target. Snapshot before testing.

---

## Defensive Mitigations

| Layer | Mitigation |
|-------|------------|
| **Patch** | Apply KB4551762 (March 2020) immediately |
| **Compression** | Disable SMBv3 compression: `Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force` |
| **Network** | Block TCP/445 inbound at the perimeter; segment internal SMB |
| **Auth** | Enforce SMB signing + require SMBv3 minimum (kills downgrade tricks) |
| **Detection** | EDR rules for unexpected `srv2.sys`/`mrxsmb.sys` crashes; SMB compression negotiation alerts |

---

## Other Notable SMB Pre-Auth RCE History

| CVE | Name | Year | Protocol |
|-----|------|------|----------|
| MS08-067 | NetAPI | 2008 | SMBv1 |
| MS17-010 | EternalBlue | 2017 | SMBv1 |
| CVE-2020-0796 | SMBGhost | 2020 | SMBv3.1.1 (compression) |
| CVE-2020-1206 | SMBleed | 2020 | SMBv3.1.1 (info leak — chained with SMBGhost) |
| CVE-2022-37958 | "SMBGhost successor" / SPNEGO | 2022 | SMB authentication negotiation |

> Pattern: every few years, a parser/handler bug in the SMB stack yields pre-auth RCE. **Always inventory SMB versions and patch level** during engagements.

---

## Key Takeaways

| Concept | Takeaway |
|---------|----------|
| **Integer overflow** | Missing bounds checks on length fields → buffer overrun → instruction overwrite |
| **Source/Process/Privileges/Destination** | Universal model for analyzing any exploit |
| **Two-cycle exploitation** | Trigger (corrupt memory) → Payload (execute attacker code) |
| **SMB compression** | The SMBGhost attack surface — disable if you can't patch |
| **Pre-auth + kernel** | Highest-severity combo; treat unpatched SMB as critical finding |
| **Stability** | Memory-corruption RCE often BSODs targets — only run PoCs in approved scope |

---

## Further Reading

- **Stack-Based Buffer Overflows on Linux x86** — HTB module on classic BOF mechanics.
- **Stack-Based Buffer Overflows on Windows x86** — Windows-specific buffer corruption.
- ZecOps writeup on SMBGhost internals.
- chompie1337's `SMBGhost_RCE_PoC` — reference exploit code.
