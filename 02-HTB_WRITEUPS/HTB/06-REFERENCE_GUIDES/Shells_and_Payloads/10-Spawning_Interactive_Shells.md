# 10 — Spawning Interactive Shells

## Overview

When you land on a system, you often get a **limited shell** (sometimes called a "jail shell"). To get full functionality — job control, command history, tab completion — you need to spawn an interactive shell.

If Python isn't available, there are many other methods to escape a limited shell.

> **Note:** Anywhere you see `/bin/sh` or `/bin/bash`, you can substitute the shell interpreter present on the target system. Most Linux systems have **bourne shell** (`/bin/sh`) and **bourne again shell** (`/bin/bash`) installed natively.

---

## Methods to Spawn Interactive Shells

### /bin/sh -i

Execute the shell interpreter in interactive mode (`-i`):

```bash
/bin/sh -i
```

```
sh: no job control in this shell
sh-4.2$
```

---

### Perl

If Perl is installed:

```bash
perl -e 'exec "/bin/sh";'
```

From within a Perl script:

```perl
perl: exec "/bin/sh";
```

---

### Ruby

If Ruby is installed (run from a script):

```ruby
ruby: exec "/bin/sh"
```

---

### Lua

If Lua is installed, use `os.execute` (run from a script):

```lua
lua: os.execute('/bin/sh')
```

---

### AWK

AWK is a C-like pattern scanning language present on most Unix/Linux systems. Spawn a shell with:

```bash
awk 'BEGIN {system("/bin/sh")}'
```

---

### Find

The `find` command can execute applications and invoke a shell interpreter.

**Method 1: Find + AWK**

```bash
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```

> Searches for a file, then executes AWK to spawn a shell.

**Method 2: Direct exec**

```bash
find . -exec /bin/sh \; -quit
```

> Uses `-exec` to directly launch the shell interpreter. If `find` can't locate the specified file, no shell is spawned.

---

### VIM

You can spawn a shell from within the VIM text editor:

**Method 1: Command-line flag**

```bash
vim -c ':!/bin/sh'
```

**Method 2: From inside VIM**

```bash
vim
:set shell=/bin/sh
:shell
```

---

## Quick Reference Table

| Method | Command |
|--------|---------|
| **sh -i** | `/bin/sh -i` |
| **Perl** | `perl -e 'exec "/bin/sh";'` |
| **Ruby** | `ruby: exec "/bin/sh"` (script) |
| **Lua** | `lua: os.execute('/bin/sh')` (script) |
| **AWK** | `awk 'BEGIN {system("/bin/sh")}'` |
| **Find + AWK** | `find / -name file -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;` |
| **Find exec** | `find . -exec /bin/sh \; -quit` |
| **VIM** | `vim -c ':!/bin/sh'` |
| **VIM (inside)** | `:set shell=/bin/sh` then `:shell` |

---

## Execution Permissions Considerations

Once you have a shell, check what permissions your account has.

### Check File/Binary Permissions

```bash
ls -la <path/to/fileorbinary>
```

### Check Sudo Permissions

```bash
sudo -l
```

Example output:

```
Matching Defaults entries for apache on ILF-WebSrv:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User apache may run the following commands on ILF-WebSrv:
    (ALL : ALL) NOPASSWD: ALL
```

> ⚠️ **Important:** `sudo -l` requires a **stable interactive shell**. If you're in a limited or unstable shell, the command may return nothing.

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **Limited shell** | Initial shells often lack job control and full functionality |
| **Multiple methods** | Python isn't always available — know Perl, AWK, find, VIM alternatives |
| **Shell path** | `/bin/sh` and `/bin/bash` are interchangeable based on what's installed |
| **Permissions first** | Check `sudo -l` immediately — it reveals privesc paths |
| **Stable shell required** | Some commands only work in a full interactive shell |
