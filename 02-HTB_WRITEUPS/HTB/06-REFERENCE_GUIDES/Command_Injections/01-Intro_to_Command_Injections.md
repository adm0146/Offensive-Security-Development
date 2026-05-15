# Section 1 — Intro to Command Injections

> Theory only. No lab.

---

## What Command Injection Is

User-controlled input is joined into a string that gets passed to an OS command execution function — like `system()`, `exec()`, `child_process.exec()`, or `Runtime.exec()` — without sanitization. The attacker breaks out of the intended argument context and appends their own commands.

```
Intended:    touch /tmp/<USER_FILENAME>.pdf
Attacker:    USER_FILENAME = "x; whoami"
Executed:    touch /tmp/x; whoami.pdf
```

The shell parses the `;` as a command separator. It runs `touch /tmp/x`, then runs `whoami`. The server returns command output, or the attacker exfiltrates it via DNS or HTTP if the injection is blind.

---

## Injection Family Tree

| Injection type | Sink | Risk |
|----------------|------|------|
| **OS Command Injection** | `system()`, `exec()`, shell pipes | Direct RCE — highest immediate impact |
| **Code Injection** | `eval()`, `assert()`, `pickle.loads()` | Direct RCE inside the app's language |
| **SQL Injection** | DB query string | Data exfil, often → RCE via SQL features |
| **NoSQL Injection** | MongoDB / similar query objects | Auth bypass, data leak |
| **LDAP Injection** | LDAP search filters | Auth bypass, dir enum |
| **HTML/XSS Injection** | Page rendering | Client-side compromise |
| **HTTP Header Injection** | Response headers | Cache poisoning, CRLF |
| **XPath / Template Injection** | XML / template engines | RCE if SSTI |
| **ORM Injection** | ORM query builders | Like SQLi but via objects |

Common thread: **user input → query/code context → boundary break → attacker controls behavior**.

OS Command Injection sits at OWASP Top 10 #3 because:
- It produces direct Remote Code Execution (RCE) without needing a chain
- It is easy to find — any feature that runs a shell command with user input is a candidate
- It is hard to filter completely without breaking functionality

---

## Vulnerable Code Patterns (by language)

### PHP
```php
// All of these are RCE-prone with unsanitized input:
system("touch /tmp/" . $_GET['filename']);
exec("ping -c 1 " . $_GET['host']);
shell_exec("ls " . $_POST['dir']);
passthru("cat " . $_GET['file']);
popen("grep " . $_GET['q'] . " /var/log/app.log", "r");
`ls {$_GET['dir']}`;   // backtick = shell_exec
```

### Node.js
```javascript
const { exec, spawn, execSync } = require('child_process');

exec(`touch /tmp/${req.query.filename}.txt`);          // vulnerable
execSync(`ping -c 1 ${req.query.host}`);                // vulnerable
spawn('sh', ['-c', `ls ${req.query.dir}`]);            // vulnerable (sh -c interprets)

// Safer (but still risky if args are tainted):
spawn('ping', ['-c', '1', req.query.host]);            // argv array — no shell interpretation
```

### Python
```python
import os, subprocess

os.system(f"ping -c 1 {host}")                          # vulnerable
subprocess.call(f"ls {dir}", shell=True)                # vulnerable (shell=True)
subprocess.run(["ls", user_input])                      # safer (no shell)

# eval/exec — code injection, not OS injection:
eval(user_input)                                         # RCE
```

### Java
```java
Runtime.getRuntime().exec("ping -c 1 " + host);         // vulnerable
new ProcessBuilder("sh", "-c", "ls " + dir).start();   // vulnerable
new ProcessBuilder("ls", userInput).start();           // safer (no shell parsing)
```

### Ruby
```ruby
system("ping #{host}")                                   # vulnerable
`ls #{dir}`                                              # vulnerable (backticks)
%x{cat #{file}}                                          # vulnerable
exec(["ls", user_input])                                # safer (no shell)
```

### .NET
```cs
Process.Start("cmd.exe", "/c ping " + host);            // vulnerable
Process.Start(new ProcessStartInfo("cmd.exe", "/c " + cmd)); // vulnerable
```

---

## Indirect Sinks (Easy to Miss)

Command injection isn't only about explicit `system()` calls. These also touch shells under the hood:

| Function / API | Hidden shell |
|----------------|--------------|
| `os.popen()` (Python) | Yes |
| `subprocess.Popen(shell=True)` | Yes |
| `pcntl_exec` (PHP) | No, but takes argv array |
| `child_process.execFile` (Node) | No, but careful with args |
| `Runtime.exec(String cmd)` (Java) | Tokenizes first, but interpreted by libc — depends |
| `os.system` (everywhere) | Always invokes `/bin/sh -c` |
| ImageMagick `convert`, `ffmpeg`, `wkhtmltopdf` — common in upload pipelines | Often called via shell with user input |
| Mail libraries (`mail()`, `sendmail` calls) | Header injection → command injection on some MTAs |
| Git operations on user-controlled repo names | `git clone <user>` → injection via `--upload-pack=cmd` |

---

## Why It's Still Common

Despite being well-known, command injection keeps showing up because:
- Developers reach for `exec("cmd " + input)` because it feels intuitive compared to argv arrays.
- Codebases inherit legacy shell-based command invocations.
- Third-party libraries internally shell out without exposing safer APIs.
- Sanitization is hard to get right — new bypass payloads keep being discovered.
- Containerized environments feel "safe," so developers skip input validation.

---

## Module Roadmap

```
Section 2-3   Detection methods + identifying injection points
Section 4-7   Command separators, payload construction, blind injection
Section 8-9   Filter bypasses (chars, keywords, encoding)
Section 10    Real-world: exfiltration when output isn't shown
Section 11    Prevention
Section 12    Skills assessment
```

---

## Exam Notes

- Command injection = #3 OWASP risk; pairs with SQLi as the highest-impact web vulns
- Look for any user input that lands in: filename ops, network ops (ping, dig, curl), system queries (whoami, hostname), conversion/processing tools (ImageMagick, ffmpeg)
- The sink doesn't need to look obvious — even `mail()`, `git clone`, `tar -xf` can inject when called via shell
- `argv array` invocation (no shell) is the canonical fix — `subprocess.run(["ls", input])` instead of `subprocess.run(f"ls {input}", shell=True)`
- Modern containers/k8s don't mitigate command injection — they just sandbox the blast radius
