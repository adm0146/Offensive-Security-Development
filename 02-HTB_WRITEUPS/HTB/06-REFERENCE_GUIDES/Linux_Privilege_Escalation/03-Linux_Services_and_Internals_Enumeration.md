# Section 3 — Linux Services & Internals Enumeration

> Lab: `ACADEMY-LLPE-SUDO` · `ssh htb-student@<T>` (`HTB_@cademy_stdnt!`). Builds on §1–§2.

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — latest installed Python version | **`3.11.3`** (`/usr/bin/python3.11`; box also has 3.8.10) |

Found by enumerating installed interpreters/packages — exactly the "what tools/packages are installed" step below.

---

## 1 — Network internals (pivot recon)

```bash
ip a            # or ifconfig (needs net-tools) — our IP(s), extra NICs = other subnets to pivot
cat /etc/hosts  # hardcoded hosts / internal names (AD, jump boxes)
ip route ; route -n ; netstat -rn 2>/dev/null     # reachable networks via which iface
arp -a          # neighbours the host talks to
cat /etc/resolv.conf                               # internal DNS -> AD enumeration start
ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null  # listening services/sockets (local-only svcs!)
```
> A second NIC or an internal-DNS `resolv.conf` is often the whole point of the box (pivot/AD). Services bound to `127.0.0.1` only (visible in `ss -tulnp`) are reachable post-shell and frequently the privesc target.

---

## 2 — Who's here / who's been here

```bash
lastlog | grep -v 'Never'      # which accounts actually log in (real users → loot)
last -a | head                 # recent logins + source IPs
w ; who ; finger 2>/dev/null   # who's on NOW (shared box = messier = more loot)
```
> Active/real users → check their homes, history, keys. Login source IPs hint at jump hosts/admin subnets.

---

## 3 — History & proc (cleartext creds)

```bash
history                                                            # our shell history
find / -type f \( -name '*_hist' -o -name '*_history' \) -exec ls -l {} \; 2>/dev/null
find / -name '.bash_history' -readable -exec cat {} \; 2>/dev/null  # other users' — passwords-as-args, ssh, git
# live process args (creds passed on CLI show here):
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr '\0' '\n' | grep -iE 'pass|user|key|token'
ps aux --forest                                                    # who runs what (root scripts!)
```
> `/proc/*/cmdline` and `ps aux` leak credentials passed as command-line args (DB clients, curl, custom scripts). Other users' `.bash_history` is the classic cleartext-cred find.

---

## 4 — Installed packages, versions & binaries  ← (Q1 lives here)

```bash
# package inventory
apt list --installed 2>/dev/null | tr '/' ' ' | cut -d' ' -f1,3 | sed 's/[0-9]://g' | tee installed_pkgs.list   # Debian
rpm -qa 2>/dev/null                                                                                              # RHEL
# version-check the privesc-relevant ones
sudo -V | head -1               # sudo version -> CVE-2021-3156 (Baron Samedit) etc.
ls -la /usr/bin/python* ; for p in /usr/bin/python*; do [ -x "$p" ] && "$p" --version 2>&1; done   # interpreters
apt list --installed 2>/dev/null | grep -iE '^python3?\.[0-9]'
screen -v; tmux -V; bash --version | head -1                       # known-vuln versions
# what offensive tooling is already here (lives off the land)
which nc ncat python3 perl ruby gcc cc make nmap tcpdump socat wget curl 2>/dev/null
ls -l /bin /usr/bin /usr/sbin | wc -l
```
> ✅ **Q1:** `ls /usr/bin/python*` + each `--version` → highest is **3.11.3**. Always inventory interpreters/compilers (used for exploit compilation, reverse shells, file transfer) **and** version-check `sudo`, `screen`, `tmux`, kernel — those map directly to public local-root CVEs.

**GTFOBins cross-reference one-liner** (which installed binaries are exploitable):
```bash
for i in $(curl -s https://gtfobins.github.io/gtfobins.json | jq -r 'keys[]'); do \
  grep -qx "$i" installed_pkgs.list 2>/dev/null && echo "Check GTFO: $i"; done
# offline: keep a local copy of the json; or just check sudo -l / SUID binaries against gtfobins.github.io
```
> Filters the GTFOBins catalogue down to binaries actually present → your sudo/SUID/capability shortlist for later sections.

---

## 5 — Config files, scripts & service ownership

```bash
find / -type f \( -name '*.conf' -o -name '*.config' \) -exec ls -l {} \; 2>/dev/null | grep -vE '/(proc|sys|snap)'
find / -type f -name '*.sh' 2>/dev/null | grep -vE 'src|snap|share'   # custom admin scripts
ps aux | grep -E '^root' | grep -vE '\[' | sort -u                    # root-run services/scripts
strace -f -e trace=network,read,write ping -c1 127.0.0.1 2>&1 | head  # trace a binary's syscalls (creds/tokens to remote hosts)
```
> World-readable `*.conf` can leak keys/paths even when the *directory* is closed. Custom `*.sh` in admin PATHs + run by root cron/service = prime hijack targets (next sections). `strace` reveals what a setuid/service binary actually does (files it reads, hosts/creds it sends).

---

## Exam / Engagement Notes

- **"Latest version of X installed"** → `ls /usr/bin/X*` then `X* --version`, and/or `apt list --installed | grep -i X` — don't trust the `python3` symlink (points at the *default*, not the *latest*; here `python3`→3.8 but 3.11.3 is installed).
- Build `installed_pkgs.list` early → feed GTFOBins/`searchsploit` for the whole module.
- `sudo -V` first line → check CVE-2021-3156 / CVE-2019-14287 / CVE-2023-22809 by version.
- `ss -tulnp` for **localhost-only** services — common privesc/lateral target invisible from outside.
- `/proc/*/cmdline` + `ps aux` = cleartext creds on the command line — always grep them.
- Inventory interpreters/compilers (`python perl ruby gcc nc socat`) — dictates exploit/shell/transfer options when offline.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T>
2. ls -la /usr/bin/python*                  -> python3.8 + python3.11
3. /usr/bin/python3.11 --version            -> Python 3.11.3
   apt list --installed | grep python3.11   -> 3.11.3-1+focal1 (confirms)
4. Q1 = 3.11.3   ✅
```

> One line: enumerate installed interpreters/packages directly (`ls /usr/bin/python*` + `--version`, `apt list --installed`) — the default `python3` symlink lies; the *installed* set is what matters.
