# 15 — MSF6 Updates & Closing Thoughts

## Overview

The August 2020 update brought MSF6 with significant security, evasion, and payload improvements. **MSF5 payloads and sessions are incompatible with MSF6** — all payloads must be regenerated.

---

## MSF6 Key Changes

### Generation Features

| Feature | Detail |
|---------|--------|
| **End-to-end encrypted Meterpreter** | All 5 implementations: Windows, Python, Java, Mettle, PHP |
| **SMBv3 client support** | Modern exploitation workflows over SMB |
| **Polymorphic shellcode generation** | Randomized Windows shellcode — shuffles instructions each generation |

### Expanded Encryption

| Change | Impact |
|--------|--------|
| **AES encryption on all Meterpreter comms** | Defeats network-based IDS/IPS signature matching |
| **SMBv3 encryption integration** | Harder to signature-detect SMB-based operations |
| **Increased binary complexity** | Signature-based detection of MSF payload binaries is harder |

### Cleaner Payload Artifacts

| Before (MSF5) | After (MSF6) | Why It Matters |
|----------------|--------------|----------------|
| DLL functions resolved by name | Resolved by **ordinal** | No readable function names in binary |
| `ReflectiveLoader` export visible as text | **Removed** from binary text data | Eliminates a well-known signature |
| Meterpreter commands as strings | Encoded as **integers** | Harder to identify commands via static analysis |

### Plugin Changes

| Change | Detail |
|--------|--------|
| **Mimikatz extension removed** | Replaced by **Kiwi** |
| `load mimikatz` | Automatically loads Kiwi instead |

### Payload Changes

| Change | Detail |
|--------|--------|
| Static shellcode generation | Replaced with **polymorphic routine** |
| Instruction layout | **Shuffled** on each generation |
| Effect | Each payload is structurally unique |

---

## MSF5 → MSF6 Compatibility

| Item | Compatible? |
|------|-------------|
| MSF5 active sessions | **No** — all break on upgrade |
| MSF5-generated payloads | **No** — must regenerate with MSF6 |
| MSF5 modules | Yes — modules carry forward |
| `load mimikatz` command | Redirects to Kiwi |

---

## Module Closing Thoughts

Metasploit's strengths in a penetration testing workflow:

| Strength | Detail |
|----------|--------|
| **Extensibility** | Custom modules, plugins, scripts |
| **Data tracking** | Database integration for hosts, services, creds, loot |
| **Post-exploitation** | Meterpreter + post modules for thorough enumeration |
| **Pivoting** | Route, portfwd, autoroute for deep network access |
| **Practice** | HTB boxes, Academy targets, Dante Pro Lab |

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **MSF6 breaks MSF5 sessions/payloads** | Regenerate everything after upgrading |
| **All Meterpreter = AES encrypted now** | Built-in network evasion |
| **Polymorphic shellcode** | Each `msfvenom` run produces unique output |
| **ReflectiveLoader signature gone** | Major detection vector removed |
| **Mimikatz → Kiwi** | Same functionality, new name |
| **Use what works for you** | MSF is a tool, not a requirement |
