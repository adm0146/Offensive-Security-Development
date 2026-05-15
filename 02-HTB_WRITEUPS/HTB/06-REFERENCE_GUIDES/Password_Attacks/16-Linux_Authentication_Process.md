# 16 — Linux Authentication Process

## Overview

Linux uses **Pluggable Authentication Modules (PAM)** for authentication. Key modules like `pam_unix.so` are located in `/usr/lib/x86_64-linux-gnu/security/` on Debian-based systems. They manage user info, authentication, sessions, and password changes via standardized API calls.

---

## Key Files

| File | Purpose | Permissions |
|------|---------|-------------|
| `/etc/passwd` | User account info (7 fields per entry) | World-readable |
| `/etc/shadow` | Password hashes (9 fields per entry) | Root only |
| `/etc/security/opasswd` | Old/previous passwords (PAM history) | Root only |

---

## /etc/passwd Format

```
htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
```

| Field | Example | Notes |
|-------|---------|-------|
| Username | `htb-student` | |
| Password | `x` | `x` = hash in `/etc/shadow`, empty = no password, hash = crackable |
| User ID | `1000` | |
| Group ID | `1000` | |
| GECOS | `,,,` | Comment/description field |
| Home directory | `/home/htb-student` | |
| Default shell | `/bin/bash` | |

### Writable /etc/passwd Exploit

If `/etc/passwd` is writable, remove root's password field:

```bash
# Before: root:x:0:0:root:/root:/bin/bash
# After:  root::0:0:root:/root:/bin/bash

su
# No password prompt — instant root shell
```
> Remove the `x` in root's password field so the file has an empty second field. Linux interprets that as no password required. Then `su` to root without being prompted. Only works if `/etc/passwd` is world-writable — check with `ls -la /etc/passwd`.

---

## /etc/shadow Format

```
htb-student:$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::
```

| Field | Example | Notes |
|-------|---------|-------|
| Username | `htb-student` | |
| Password | `$y$j9T$...` | Format: `$<id>$<salt>$<hash>` |
| Last change | `18955` | Days since epoch |
| Min age | `0` | Min days before change allowed |
| Max age | `99999` | Max days before change required |
| Warning period | `7` | Days before expiry to warn |
| Inactivity period | `-` | |
| Expiration date | `-` | |
| Reserved | `-` | |

- `!` or `*` in password field = cannot log in with Unix password (Kerberos/key-based still works)
- Empty password field = no password required

---

## Hash Algorithm IDs

| ID | Algorithm | Notes |
|----|-----------|-------|
| `1` | MD5 | Weak — easy to crack |
| `2a` | Blowfish | |
| `5` | SHA-256 | |
| `6` | SHA-512 | Common on older systems |
| `sha1` | SHA1crypt | |
| `y` | Yescrypt | **Default on modern Debian** |
| `gy` | Gost-yescrypt | |
| `7` | Scrypt | |

---

## Opasswd (Password History)

PAM stores old passwords in `/etc/security/opasswd` to prevent reuse:

```bash
sudo cat /etc/security/opasswd
# cry0l1t3:1000:2:$1$HjFAfYTG$qNDkF0zJ3v8ylCOrKB0kt0,$1$kcUjWZJX$E9uMSmiQeRh4pAAgzuvkq1
```
> Shows old password hashes stored by PAM to enforce password history. Old entries often use weaker MD5 (`$1$`) hashing. Cracking these reveals password patterns the user likely still follows.

- Old passwords may use weaker hashes (e.g., MD5 `$1$`)
- Users reuse similar passwords — cracking old ones reveals patterns

---

## Cracking Linux Credentials

### Step 1: Combine passwd + shadow

```bash
sudo cp /etc/passwd /tmp/passwd.bak
sudo cp /etc/shadow /tmp/shadow.bak
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```
> `unshadow` merges the passwd and shadow files into a single format JtR and hashcat can read. The result has the username, GECOS, and hash on one line per user. Copy the files first so you have originals.

### Step 2: Crack with hashcat or JtR

```bash
# Hashcat (SHA-512 = mode 1800)
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked

# John the Ripper (single crack mode is ideal for unshadowed files)
john --single /tmp/unshadowed.hashes
```
> `-m 1800` targets SHA-512 crypt (`$6$`) Linux hashes. `-o` saves cracked results to a file. For JtR, single mode uses GECOS data from the combined file to generate guesses — often cracks passwords that rockyou misses.

### Hashcat Modes for Linux Hashes

| Mode | Algorithm |
|------|-----------|
| `500` | MD5 (`$1$`) |
| `3200` | Blowfish (`$2a$`) |
| `7400` | SHA-256 (`$5$`) |
| `1800` | SHA-512 (`$6$`) |

---

## Key Takeaways

- `/etc/passwd` is world-readable — if hashes are stored here (rare), crack them directly
- Writable `/etc/passwd` = instant root by clearing root's password field
- `/etc/shadow` requires root — use `unshadow` to combine with passwd for cracking
- Check `/etc/security/opasswd` for old passwords with weaker hashes (MD5)
- Modern Linux uses yescrypt by default; older systems may use MD5/SHA-512
- JtR's single crack mode was designed specifically for unshadowed file cracking

---

## Practice Exercise Walkthrough

Given `passwd` and `shadow` files from a Linux system:

### Q1: Single Crack Mode (martin)

```bash
# Combine the files
unshadow passwd shadow > unshadowed.hashes

# Single crack mode uses GECOS field (user's real name) to generate guesses
john --single unshadowed.hashes --format=sha512crypt
```
> Merges the provided passwd and shadow files, then runs JtR single crack mode. `--format=sha512crypt` forces the correct format for `$6$` hashes. JtR generates guesses from the GECOS field ("Martin Mendes" → "Martin1", etc.).

- martin's GECOS: `Martin Mendes`
- JtR mangled this into `Martin1` → **cracked**
- Single mode works by deriving password guesses from username, GECOS, home dir, etc.

### Q2: Wordlist Attack (sarah)

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.hashes --format=sha512crypt
```
> Wordlist attack against SHA-512 Linux hashes. Explicit `--format=` prevents JtR from guessing the wrong format. Add `--rules` to apply JtR's built-in mutation rules to every rockyou entry.

- sarah's password: `mariposa` → found in rockyou.txt

### Answers

| User | Password | Method |
|------|----------|--------|
| martin | `Martin1` | JtR single crack (GECOS-derived) |
| sarah | `mariposa` | JtR wordlist (rockyou.txt) |
