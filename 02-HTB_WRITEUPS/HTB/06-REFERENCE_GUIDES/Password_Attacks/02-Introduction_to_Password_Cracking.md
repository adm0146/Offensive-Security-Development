# 02 — Introduction to Password Cracking

## Overview

Passwords are stored as **hashes** — one-way mathematical transformations that produce fixed-size outputs. Password cracking is the process of reversing this to recover the original password. Three primary techniques exist: rainbow tables, brute-force, and dictionary attacks.

---

## Hashing Basics

```bash
# Generate MD5 hash
echo -n Soccer06! | md5sum
# 40291c1d19ee11a7df8495c4cccefdfa

# Generate SHA-256 hash
echo -n Soccer06! | sha256sum
# a025dc6fabb09c2b8bfe23b5944635f9b68433ebd9a1a09453dd4fee00766d93
```
> Pipes a password string into `md5sum` or `sha256sum` to see its hash. Use `-n` to strip the trailing newline — without it the hash changes. Swap `md5sum` for `sha1sum`, `sha256sum`, or `sha512sum` for other algorithms.

| Property | Detail |
|----------|--------|
| **One-way** | Cannot reverse hash → password mathematically |
| **Fixed output** | Any input length → same hash length |
| **Deterministic** | Same input always produces same hash |
| **Common algorithms** | MD5, SHA-256, NTLM, bcrypt, DCC2 |

> **Note**: Always use `echo -n` (no trailing newline) when hashing passwords manually.

---

## Cracking Techniques

### 1. Rainbow Tables

Pre-compiled maps of password → hash pairs for instant lookup.

| Password | MD5 Hash |
|----------|----------|
| `123456` | `e10adc3949ba59abbe56e057f20f883e` |
| `password` | `5f4dcc3b5aa765d61d8327deb882cf99` |
| `iloveyou` | `f25a2fc72690b780b2a14e140ef6a9e0` |
| `rockyou` | `f806fc5a2a0d5ba2471600758452799c` |

| Attribute | Detail |
|-----------|--------|
| **Speed** | Instant lookup |
| **Limitation** | Defeated by salting |
| **Storage** | Massive (billions of entries) |

#### Salting Defeats Rainbow Tables

A **salt** is a random byte sequence prepended/appended to the password before hashing.

```bash
# Without salt
echo -n Soccer06! | md5sum
# 40291c1d19ee11a7df8495c4cccefdfa

# With salt
echo -n Th1sIsTh3S@lt_Soccer06! | md5sum
# 90a10ba83c04e7996bc53373170b5474
```
> Shows how prepending a salt changes the hash completely. The salted version can't be looked up in a rainbow table. Real systems append/prepend a unique random salt automatically before storing.

| Salt Property | Detail |
|---------------|--------|
| **Not secret** | Stored alongside the hash (system needs it to verify) |
| **Should be unique** | Different salt per password, not shared across DB |
| **Impact** | 1-byte salt = 256× rainbow table size increase |
| **15B entries + 1-byte salt** | → 3.84 trillion entries needed |

### 2. Brute-Force Attack

Try every possible character combination until the password is found.

| Attribute | Detail |
|-----------|--------|
| **Effectiveness** | 100% — guaranteed to find password given enough time |
| **Practical for** | Short passwords (<9 characters) |
| **Speed varies** | MD5: ~5M guesses/sec · DCC2: ~10K guesses/sec (laptop) |
| **Usually replaced by** | Mask attacks (covered in later sections) |

### 3. Dictionary Attack (Wordlist)

Use a list of statistically likely passwords instead of exhaustive brute-force.

```bash
# Preview rockyou.txt
head --lines=20 /usr/share/wordlists/rockyou.txt
```
> Prints the first 20 lines of rockyou.txt. Change `--lines=20` to see more. Use this to confirm the wordlist is readable and check its format before feeding it to a cracker.

| Wordlist | Entries | Source |
|----------|---------|--------|
| `rockyou.txt` | **14M+** real passwords | RockYou breach (2009) — stored unencrypted |
| SecLists | Various | Curated collections for different attack types |

| Attribute | Detail |
|-----------|--------|
| **Most efficient** | Best for time-constrained pentests |
| **Targets** | Common/likely passwords first |
| **Limitation** | Won't find truly random passwords |

---

## Technique Comparison

| Technique | Speed | Effectiveness | Best For |
|-----------|-------|---------------|----------|
| **Rainbow table** | Instant lookup | Fails against salted hashes | Unsalted hashes |
| **Brute-force** | Slow (exhaustive) | 100% given time | Short passwords (<9 chars) |
| **Dictionary** | Fast (targeted) | High for common passwords | Time-constrained assessments |
| **Mask attack** | Efficient brute-force | High for known patterns | Covered in next sections |

---

## Exercise: Generate SHA1 Hash

**Question**: What is the SHA1 hash for `Academy#2025`?

```bash
echo -n 'Academy#2025' | sha1sum
# 750fe4b402dc9f91cedf09b652543cd85406be8c
```
> Generates the SHA-1 hash of the string. Quote the input when it contains special characters like `#`. The `-n` flag prevents a trailing newline from being hashed.

**Answer: `750fe4b402dc9f91cedf09b652543cd85406be8c`**

> Remember: `-n` flag is critical — without it, the trailing newline changes the hash entirely.

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **Hashing is one-way** | Can't mathematically reverse a hash |
| **`echo -n` is critical** | Newline changes the hash entirely |
| **Salting defeats rainbow tables** | Unique random bytes per password |
| **Salts are not secrets** | Stored with the hash for verification |
| **Brute-force = guaranteed but slow** | Only practical for short passwords |
| **Dictionary attacks are the go-to** | `rockyou.txt` covers most real-world passwords |
| **Speed depends on algorithm** | MD5 is 500× faster to crack than DCC2 |
