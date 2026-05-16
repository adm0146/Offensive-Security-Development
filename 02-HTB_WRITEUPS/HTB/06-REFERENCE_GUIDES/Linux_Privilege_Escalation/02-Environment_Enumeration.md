# Section 2 — Environment Enumeration

> Lab: `ACADEMY-LLPE-SUDO` · `ssh htb-student@<T>` (`HTB_@cademy_stdnt!`)
> Builds on §1 checklist. Companion: `../Foundation/Privilege_Escalation.md` (strategy/decision tree).

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — flag in a sensitive/interesting file | **`HTB{1nt3rn4l_5cr1p7_l34k}`** |

Found in **`/usr/lib/int-check.sh`** — a non-standard, world-readable 26-byte "internal script" dropped into a system lib dir. Recovered with a filesystem-wide `grep` for the flag marker.

---

## 0 — Orient (the 5 quick questions)

```bash
whoami; id; hostname; ip a    # or: ifconfig
sudo -l 2>/dev/null
```
> Who/what/where + can I sudo. `hostname` naming often leaks role (`nixlpe02`, `web01`, `dc01`). Extra NICs in `ip a` = pivot routes. Screenshot these for the report (proves RCE + identifies the host).

---

## 1 — System fingerprint

```bash
cat /etc/os-release            # distro + version (EOL? -> kernel CVEs likely?)
uname -a; cat /proc/version    # kernel -> searchsploit
arch; lscpu | head             # arch/CPU (32 vs 64, hypervisor = VM)
cat /etc/shells                # available shells (tmux/screen present? = pivot/persist)
```
> Distro decides available tooling; kernel decides exploit surface. Note shells — Screen 4.05.00 / old Bash (Shellshock) are version-specific wins.

---

## 2 — Our context: PATH, env, defenses

```bash
echo $PATH                      # writable/relative entry early in PATH = hijack later (§ PATH abuse)
env; cat /proc/self/environ | tr '\0' '\n'   # secrets in env vars?
# defenses (note presence, don't fight blindly):
which aa-status getenforce iptables ufw fail2ban 2>/dev/null
aa-status 2>/dev/null; getenforce 2>/dev/null; ufw status 2>/dev/null
```
> A misordered `$PATH` is its own privesc vector later. `env` sometimes leaks passwords/tokens. Knowing AppArmor/SELinux/ufw/Fail2ban is on saves you wasting time on blocked paths.

---

## 3 — Storage, network, neighbours

```bash
lsblk; df -h; cat /etc/fstab | grep -v '^#' | column -t   # unmounted/extra drives, fstab creds
lpstat -a 2>/dev/null                                      # printers/queued jobs (rare loot)
route -n 2>/dev/null || ip route ; netstat -rn 2>/dev/null # other reachable subnets
arp -a ; cat /etc/resolv.conf                              # neighbours + internal DNS (AD pivot)
```
> Mountable extra disk → backups/creds. `grep -iE 'pass|user|cred' /etc/fstab` for mount creds. `resolv.conf` pointing at an internal DNS = start of AD enumeration on a domain-joined box.

---

## 4 — Users & groups

```bash
cat /etc/passwd                       # accounts; shells; service users
grep 'sh$' /etc/passwd                # only login-capable users (spray/su targets)
grep -vE ':[x*!]+:' /etc/passwd | grep -E '\$[0-9]'   # inline hash in passwd? -> crack
cat /etc/group; getent group sudo     # who's in sudo/lxd/docker/disk/adm = privesc groups
ls -la /home/*                        # other homes readable?
```
> Hash-prefix tells the algo: `$1$`=MD5 `$5$`=SHA256 `$6$`=SHA512 `$2a$`=bcrypt `$7$`=scrypt `$argon2i$`=Argon2. Membership in **sudo/lxd/docker/disk/adm/shadow** is a direct escalation path (later sections). Readable `/etc/shadow` or inline passwd hash → `hashcat`/`john` offline.

---

## 5 — The loot hunt (where the flag was)

```bash
# hidden files / dirs (often hold secrets even read-only)
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep "$(whoami)"
find / -type d -name ".*" -ls 2>/dev/null
# other users' history / keys / configs
find /home -name '.bash_history' -readable -exec cat {} \; 2>/dev/null
find / \( -name 'id_rsa' -o -name 'authorized_keys' -o -name '*.pem' \) -readable 2>/dev/null
# config / cred files
find / -type f \( -name '*.conf' -o -name '*.config' -o -name '*.json' -o -name '*.bak' -o -name '*.notes' \) -readable 2>/dev/null | grep -vE '^/(proc|sys|usr/share|usr/lib/python)'
grep -rniE 'password|passwd|secret|api[_-]?key|token' /var/www /opt /etc /srv /home 2>/dev/null | grep -vi binary | head
# temp dirs
ls -la /tmp /var/tmp /dev/shm
# the catch-all: hunt the flag marker filesystem-wide
grep -rsl 'HTB{' / 2>/dev/null | grep -vE '^/proc|^/sys'
grep -rshoE 'HTB\{[^}]*\}' / 2>/dev/null | head
```
> ✅ **This is how the flag was found:** `/usr/lib/int-check.sh` — a planted "internal" script. **Lesson:** don't over-exclude `/usr/lib`, `/usr/local`, `/var` when loot-hunting *for the answer* — CTF authors (and real attackers) hide payloads/creds in system dirs precisely because defenders skip them. For *speed* you exclude them; for *the flag* do a full `grep -rsl 'HTB{' /` (run in background / with a longer timeout if it's slow).

---

## Exam / Engagement Notes

- **`grep -rsl 'HTB{' / 2>/dev/null`** is the universal HTB-Academy flag finder when the task says "find a sensitive file" — let it run fully; don't prune `/usr` *for the answer* (only for speed during recon).
- `find ... *.sh` then `xargs grep -l 'HTB{'` is the fast variant — non-standard scripts in `/usr/lib`,`/usr/local/bin`,`/opt` are prime hiding spots (this box: `/usr/lib/int-check.sh`).
- Hash prefixes → algo (memorise the `$1/$5/$6/$2a/$7/$argon2i` table) for `hashcat -m`.
- Always check **other users' homes, `.bash_history`, SSH keys, fstab, env** for reuse creds before any exploit.
- Privesc-relevant group membership: `sudo lxd docker disk adm shadow video` — `getent group <g>`.
- Run `linpeas` in parallel in real engagements, but the manual `grep`/`find` sweep is what gets the flag here.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T>  (HTB_@cademy_stdnt!)
2. id; sudo -l; cat /etc/os-release; uname -a        # baseline
3. ls -la ~ ; ls -la /home/*                          # sparse - nothing here
4. grep -rsl 'HTB{' / 2>/dev/null                     # (full sweep - don't exclude /usr/lib)
   -> /usr/lib/int-check.sh
5. cat /usr/lib/int-check.sh                           # -> HTB{1nt3rn4l_5cr1p7_l34k}  ✅
```

> One line: enumeration = `grep`/`find` the whole FS for secrets; the flag was a planted world-readable script in `/usr/lib/` — full sweep beats a pruned one when the answer is the goal.
