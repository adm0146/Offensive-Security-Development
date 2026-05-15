# 04 — Introduction to Hashcat

## Overview

Hashcat is a GPU-accelerated password cracking tool (open-source since 2015) supporting hundreds of hash types and multiple attack modes. It is significantly faster than CPU-only tools for most hash types due to GPU parallelism.

---

## General Syntax

```bash
hashcat -a <attack_mode> -m <hash_type> <hashes> [wordlist, rule, mask, ...]
```
> Core hashcat syntax. `-a` sets the attack mode (0=dictionary, 3=mask), `-m` sets the hash type ID. The hash can be a single string or a file with one hash per line.

| Flag | Purpose |
|------|---------|
| `-a` | Attack mode |
| `-m` | Hash type ID |
| `<hashes>` | Hash string or file containing hashes |
| `-r` | Rule file for transformations |
| `-o` | Output file for cracked hashes |

---

## Identifying Hash Types

```bash
# List all supported hash modes
hashcat --help

# Auto-detect with hashID (-m for hashcat mode)
hashid -m '$1$FNr44XZC$wQxY6HHLrgrGX0e1195k.1'
```
> `hashcat --help` lists all `-m` mode IDs. `hashid -m` auto-identifies a hash and prints the hashcat `-m` value to use. Quote hashes with special characters like `$`.

### Common Hash Mode IDs

| ID | Hash Type | Source |
|----|-----------|--------|
| `0` | MD5 | Web apps, databases |
| `100` | SHA1 | Web apps |
| `500` | MD5 Crypt (`$1$`) | Linux `/etc/shadow` |
| `900` | MD4 | Legacy |
| `1000` | NTLM | Windows SAM / hashdump |
| `1300` | SHA2-224 | Modern apps |
| `1400` | SHA2-256 | Modern apps |
| `1700` | SHA2-512 | Modern apps |
| `1800` | SHA-512 Crypt (`$6$`) | Linux `/etc/shadow` |
| `3000` | LM | Legacy Windows |
| `5600` | NetNTLMv2 | Network capture |
| `6000` | RIPEMD-160 | Misc |
| `13100` | Kerberos 5 TGS-REP | Kerberoasting |

> Full list: `hashcat --help` or the [hashcat example hashes page](https://hashcat.net/wiki/doku.php?id=example_hashes)

---

## Attack Modes

### Dictionary Attack (`-a 0`)

Test every word in a wordlist against the hash.

```bash
# Basic dictionary attack
hashcat -a 0 -m 0 e3e3ec5831ad5e7288241960e5d4fdb8 /usr/share/wordlists/rockyou.txt

# With rules
hashcat -a 0 -m 0 1b0556a75770563578569ae21392630c /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule
```
> `-a 0` is dictionary mode. `-m 0` is MD5. Add `-r` with a rule file to apply mutations to every wordlist entry. Start with `best64.rule` before trying larger rulesets.

#### Common Rule Files (`/usr/share/hashcat/rules/`)

| Rule File | Description |
|-----------|-------------|
| `best64.rule` | 64 standard transformations — **start here** |
| `rockyou-30000.rule` | 30K rules derived from rockyou patterns |
| `d3ad0ne.rule` | Large ruleset (~200K) |
| `dive.rule` | Very large (~780K rules) |
| `leetspeak.rule` | Leet substitutions (a→@, e→3, etc.) |
| `toggles1-5.rule` | Toggle case at positions 1–5 |
| `combinator.rule` | Word combination rules |
| `generated.rule` / `generated2.rule` | Auto-generated comprehensive rules |

### Mask Attack (`-a 3`)

User-defined brute-force with explicit keyspace constraints.

```bash
# Uppercase + 4 lowercase + digit + symbol
hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'
```
> `-a 3` is mask mode. Each `?` placeholder defines one character position. Quote the mask to stop the shell from interpreting `?`. Adjust the pattern to match the known password policy.

#### Built-in Charsets

| Symbol | Characters |
|--------|------------|
| `?l` | `a-z` (lowercase) |
| `?u` | `A-Z` (uppercase) |
| `?d` | `0-9` (digits) |
| `?h` | `0-9a-f` (hex lowercase) |
| `?H` | `0-9A-F` (hex uppercase) |
| `?s` | Special characters (space, punctuation) |
| `?a` | All printable (`?l?u?d?s`) |
| `?b` | All bytes (`0x00-0xff`) |

#### Custom Charsets

```bash
# Define custom charset with -1, reference with ?1
hashcat -a 3 -m 0 <hash> -1 '?l?d' '?1?1?1?1?1?1'
#                         ↑ custom set    ↑ 6-char mask using it
```
> `-1` defines a custom character set (here: lowercase + digits). Reference it as `?1` in the mask. Supports up to four custom sets (`-1` through `-4`). Useful when the built-in charsets are too broad or too narrow.

| Flag | Reference |
|------|-----------|
| `-1 <chars>` | `?1` |
| `-2 <chars>` | `?2` |
| `-3 <chars>` | `?3` |
| `-4 <chars>` | `?4` |

#### Mask Examples

| Pattern | Mask | Keyspace |
|---------|------|----------|
| 8 lowercase | `?l?l?l?l?l?l?l?l` | 208B |
| 6 letters + 2 digits | `?l?l?l?l?l?l?d?d` | 30.8B |
| Upper + 4 lower + digit + symbol | `?u?l?l?l?l?d?s` | 3.9B |
| 4 digits (PIN) | `?d?d?d?d` | 10K |

---

## Attack Mode Summary

| Mode | Flag | Description | Best For |
|------|------|-------------|----------|
| **Dictionary** | `-a 0` | Wordlist ± rules | Most cracking scenarios |
| **Combination** | `-a 1` | Combine two wordlists | Compound passwords |
| **Mask** | `-a 3` | Defined keyspace brute-force | Known password structure |
| **Hybrid (WL+Mask)** | `-a 6` | Wordlist + mask appended | `password123` patterns |
| **Hybrid (Mask+WL)** | `-a 7` | Mask prepended + wordlist | `123password` patterns |
| **Association** | `-a 9` | Context-aware attack | Targeted cracking |

---

## Exercises

### Exercise 1: Dictionary Attack

**Hash (MD5)**: `e3e3ec5831ad5e7288241960e5d4fdb8`

```bash
hashcat -a 0 -m 0 e3e3ec5831ad5e7288241960e5d4fdb8 /usr/share/wordlists/rockyou.txt
```
> Straight dictionary attack against a single MD5 hash. Hashcat prints the cracked password after the hash separated by a colon. Add `--show` to display already-cracked results.

**Answer: `crazy!`** — Straight dictionary hit in rockyou.txt, no rules needed.

### Exercise 2: Dictionary Attack with Rules

**Hash (MD5)**: `1b0556a75770563578569ae21392630c`

```bash
hashcat -a 0 -m 0 1b0556a75770563578569ae21392630c /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best66.rule
```
> Applies `best66.rule` mutations to every rockyou.txt word. Catches leet-speak substitutions and common suffixes that a plain dictionary attack misses.

**Answer: `c0wb0ys1`** — Base word `cowboys` mutated with leet speak (`o→0`) + appended `1`. Wordlist alone missed it; rules caught the mutation.

> **Note**: On some systems the file is `best64.rule`, on others `best66.rule`. Check `/usr/share/hashcat/rules/` for available files.

### Exercise 3: Mask Attack

**Hash (MD5)**: `1e293d6912d074c0fd15844d803400dd`

Mask: uppercase + 4 lowercase + digit + symbol (`?u?l?l?l?l?d?s`)

```bash
hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'
```
> Mask attack with a specific 7-character pattern: one uppercase, four lowercase, one digit, one symbol. Use when you know the target password policy so you can constrain the keyspace.

**Answer: `Mouse5!`** — 7-char password matching the exact mask pattern. Keyspace was ~3.9B candidates, cracked in ~4 seconds.

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **`-a` = attack mode, `-m` = hash type** | Core flags for every hashcat command |
| **`hashid -m` for hash identification** | Returns hashcat mode ID directly |
| **Dictionary + rules is the go-to combo** | `-a 0` with `best64.rule` first, then `rockyou-30000.rule` |
| **Mask attacks replace naive brute-force** | Define exactly what you're searching for |
| **Custom charsets with `-1` through `-4`** | Mix and match character classes |
| **GPU acceleration is the advantage** | Hashcat on GPU >> JtR on CPU for most hashes |
| **Quote masks in the shell** | `'?u?l?l?d?s'` — prevent shell interpretation |
