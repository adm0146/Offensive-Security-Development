# 03 — Introduction to John The Ripper

## Overview

John the Ripper (JtR) is an open-source password cracking tool released in 1996. The **jumbo** variant is recommended — it includes performance optimizations, multilingual wordlists, 64-bit support, and hundreds of hash format plugins. JtR also ships with `*2john` conversion tools for cracking password-protected files.

---

## Cracking Modes

### 1. Single Crack Mode

Generates candidates from the victim's **username, home directory, and GECOS fields** (full name, phone, etc.), then applies transformation rules.

```bash
john --single passwd
```
> Runs JtR's single crack mode on the file `passwd`. JtR reads username and GECOS fields from the file to generate and test candidates automatically.

**Example input file** (`passwd`):
```
r0lf:$6$ues25dIanlctrWxg$nZHVz2z4kCy1760Ee28M1xtHdGoy0C2cYzZ8l2sVa1kIa8K9gAcdBP.GI6ng/qA4oaMrgElZ1Cb9OeXO4Fvy3/:0:0:Rolf Sebastian:/home/r0lf:/bin/bash
```

| Source Data | Candidates Generated |
|-------------|---------------------|
| Username: `r0lf` | `r0lf`, `R0lf`, `r0lf1`, etc. |
| Real name: `Rolf Sebastian` | `Sebastian`, `RolfSebastian`, `SebastianRolf`, etc. |
| Home dir: `/home/r0lf` | Same as username variations |

| Attribute | Detail |
|-----------|--------|
| **Best for** | Linux credentials with rich GECOS data |
| **Speed** | Fast — limited candidate pool |
| **Rules** | Applied automatically from `john.conf` |

### 2. Wordlist Mode (Dictionary)

Attempts all passwords from a supplied wordlist against the hash.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash_file

# With rules applied
john --wordlist=rockyou.txt --rules hash_file

# Multiple wordlists
john --wordlist=list1.txt,list2.txt hash_file
```
> `--wordlist` feeds a password list to JtR one line at a time. `--rules` applies mangling rules (capitalize, append numbers, etc.) to each word. Comma-separate multiple wordlists to try them all in sequence.

| Attribute | Detail |
|-----------|--------|
| **Best for** | Time-constrained pentests |
| **Common wordlists** | `rockyou.txt` (14M+), SecLists |
| **Rules** | `--rules` applies transformations (append numbers, capitalize, etc.) |

### 3. Incremental Mode (Markov-Chain Brute Force)

Generates candidates using a **statistical model (Markov chains)** — smarter than pure brute-force.

```bash
# Default incremental
john --incremental hash_file
```
> Runs Markov-chain brute-force. JtR uses character frequency statistics to try probable combinations before unlikely ones. Slow for long passwords — use when wordlist mode fails.

| Attribute | Detail |
|-----------|--------|
| **Best for** | Exhaustive cracking when wordlists fail |
| **Character sets** | Defined in `john.conf` (ASCII, Latin1, UTF8, Custom) |
| **Smarter than brute-force** | Prioritizes statistically likely combinations |
| **Limitation** | Resource-intensive and slow for long passwords |

#### Built-in Incremental Modes (`john.conf`)

```bash
grep '# Incremental modes' -A 100 /etc/john/john.conf
```
> Shows all incremental mode definitions in JtR's config. `-A 100` prints 100 lines after the match. Use this to find available character sets and their names.

| Mode | Character Set | Max Length |
|------|--------------|------------|
| `ASCII` | 95 printable ASCII chars | 13 |
| `Latin1` | 203 CP1252 chars | Unlimited |
| `UTF8` | 196 UTF-8 chars | Unlimited |
| `Custom` | User-defined (`custom.chr`) | User-defined |

---

## Identifying Hash Formats

When the hash format is unknown, use **hashID** with the `-j` flag for JtR format names:

```bash
hashid -j 193069ceb0461e1d40d216e32c79c704
```
> Identifies hash type and prints the JtR format flag with `-j`. Replace the hash string with the target hash. The output tells you what to pass to `--format=`.

| Resource | Purpose |
|----------|---------|
| `hashid -j <hash>` | Auto-detect format + JtR format name |
| JtR sample hash docs | Reference examples per format |
| PentestMonkey hash list | Example hashes with format identifiers |

> **Tip**: Context matters — where the hash came from often narrows the format (e.g., SAM file → NT, `/etc/shadow` → sha512crypt, Active Directory → krb5).

### Specifying Format

```bash
john --format=raw-md5 hash_file
john --format=nt hash_file
john --format=sha512crypt hash_file
```
> Forces JtR to treat the hash as a specific format instead of guessing. Use `nt` for Windows NTLM hashes from SAM/NTDS, `sha512crypt` for Linux `/etc/shadow` `$6$` hashes.

### Common JtR Formats (Quick Reference)

| Format | Flag | Source |
|--------|------|--------|
| NTLM | `--format=nt` | Windows SAM / hashdump |
| LM | `--format=LM` | Legacy Windows |
| MD5 | `--format=raw-md5` | Web apps, databases |
| SHA1 | `--format=raw-sha1` | Web apps |
| SHA256 | `--format=raw-sha256` | Modern web apps |
| SHA512 crypt | `--format=sha512crypt` | Linux `/etc/shadow` ($6$) |
| NTLMv2 | `--format=netntlmv2` | Network capture |
| Kerberos 5 | `--format=krb5` | AD Kerberoasting |
| MS Cache 2 | `--format=mscach2` | Domain cached creds (DCC2) |
| MySQL SHA1 | `--format=mysql-sha1` | MySQL databases |
| Oracle 11 | `--format=oracle11` | Oracle databases |

---

## Cracking Files with `*2john` Tools

Convert password-protected files to JtR-compatible hashes, then crack normally.

```bash
# General workflow
<tool> <protected_file> > file.hash
john --wordlist=rockyou.txt file.hash
```
> Two-step pattern: run the `*2john` tool to extract a crackable hash from the protected file, redirect it to a `.hash` file, then crack that file with JtR normally.

### Common `*2john` Tools

| Tool | Converts |
|------|----------|
| `zip2john` | ZIP archives |
| `rar2john` | RAR archives |
| `pdf2john` | PDF documents |
| `ssh2john` | SSH private keys |
| `keepass2john` | KeePass databases |
| `office2john` | MS Office documents (docx, xlsx, pptx) |
| `putty2john` | PuTTY private keys |
| `bitlocker2john` | BitLocker volumes |
| `truecrypt_volume2john` | TrueCrypt volumes |
| `pfx2john` | PKCS#12 / PFX certificates |
| `keychain2john` | macOS keychain files |
| `hccap2john` / `wpa2john` | WPA/WPA2 handshakes |
| `gpg2john` | GPG private keys |
| `7z2john.pl` | 7-Zip archives |
| `1password2john.py` | 1Password vaults |

```bash
# Find all available *2john tools
locate *2john*
```
> Searches the file index for all `*2john` conversion scripts on the system. Run `updatedb` first if results seem outdated.

---

## Exercises

### Exercise 1: Single Crack Mode — r0lf's Password

**Hash file** (`passwd`):
```
r0lf:$6$ues25dIanlctrWxg$nZHVz2z4kCy1760Ee28M1xtHdGoy0C2cYzZ8l2sVa1kIa8K9gAcdBP.GI6ng/qA4oaMrgElZ1Cb9OeXO4Fvy3/:0:0:Rolf Sebastian:/home/r0lf:/bin/bash
```

```bash
# Save the hash to a file
echo 'r0lf:$6$ues25dIanlctrWxg$nZHVz2z4kCy1760Ee28M1xtHdGoy0C2cYzZ8l2sVa1kIa8K9gAcdBP.GI6ng/qA4oaMrgElZ1Cb9OeXO4Fvy3/:0:0:Rolf Sebastian:/home/r0lf:/bin/bash' > passwd

# Run single crack mode
john --single passwd
```
> Saves the full passwd-format line to a file, then runs single crack mode. JtR uses the username `r0lf` and real name `Rolf Sebastian` from the GECOS field to generate candidates.

**Answer: `NAITSABES`** — "SEBASTIAN" reversed. JtR derived it from the GECOS field `Rolf Sebastian` using string reversal rules.

### Exercise 2: Wordlist Mode — RIPEMD-128 Hash

**Hash**: `193069ceb0461e1d40d216e32c79c704` (format: RIPEMD-128)

```bash
# Save hash to file
echo '193069ceb0461e1d40d216e32c79c704' > ripemd_hash

# Crack with wordlist mode + explicit format
john --format=ripemd-128 --wordlist=/usr/share/wordlists/rockyou.txt ripemd_hash
```
> Saves a bare hash to a file and cracks it with an explicit format. Use `--format=` whenever JtR auto-detects the wrong type. Swap `ripemd-128` for any format from `john --list=formats`.

**Answer: `50cent`** — Found in rockyou.txt. Key lesson: use `--format=` when hashid returns ambiguous results and you know the format from context.

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **Use jumbo variant** | More formats, better performance, 64-bit |
| **Single mode first** | Fast — derives candidates from username/GECOS |
| **Wordlist mode is the workhorse** | `rockyou.txt` + `--rules` for most cracks |
| **Incremental = smart brute-force** | Markov chains, not random — still slow |
| **`hashid -j` for format detection** | Context of where hash came from is equally important |
| **`--format=` when auto-detect fails** | Specify explicitly to avoid wrong format |
| **`*2john` tools for files** | Convert first, then crack the extracted hash |
| **`--show` to display cracked** | `john --show hash_file` after cracking |
