# Section 11 — Command Injection Prevention

> Theory only. No lab.

---

## Defense Hierarchy

```
1. Don't call system commands         ← best
2. Use safe APIs (argv arrays, no shell)
3. Validate input strictly (whitelist format)
4. Sanitize before passing to any sink
5. Lock down server permissions       ← contains damage
6. WAF                                ← last line
```

---

## 1 — Avoid Shell Commands Entirely

Whenever possible, use the language's **built-in equivalent** instead of shelling out.

| Task | Bad (shell-out) | Good (built-in) |
|------|-----------------|-----------------|
| Check host reachability | `system("ping -c 1 $host")` | PHP `fsockopen()` / Python `socket.create_connection()` |
| Read a file | `system("cat $file")` | PHP `file_get_contents()` / Python `open().read()` |
| List directory | `system("ls $dir")` | PHP `scandir()` / Python `os.listdir()` |
| Make HTTP request | `system("curl $url")` | PHP cURL extension / Python `requests` |
| DNS lookup | `system("dig $name")` | PHP `dns_get_record()` / Python `socket.gethostbyname()` |
| Image manipulation | `system("convert $f $out")` | GD library / Pillow |
| Run a binary | `system("$bin $args")` | Can't avoid — see #2 |

---

## 2 — Use Safe Invocation APIs (argv arrays, no shell)

If you MUST run a binary, pass arguments as an array — never as a single string the shell parses.

### Python
```python
# BAD — shell parses, attacker controls
subprocess.call(f"ls {user_dir}", shell=True)

# GOOD — argv array, no shell
subprocess.run(["ls", user_dir])
```

### Node.js
```javascript
// BAD
exec(`ls ${userDir}`)

// GOOD — argv array
execFile('ls', [userDir])
spawn('ls', [userDir])
```

### Java
```java
// BAD
Runtime.getRuntime().exec("ls " + dir);

// GOOD
new ProcessBuilder("ls", dir).start();
```

### PHP
```php
// BAD
system("ls " . $dir);

// GOOD — pcntl_exec takes argv array (POSIX only)
pcntl_exec("/bin/ls", [$dir]);

// Or use escapeshellarg as middle-ground:
system("ls " . escapeshellarg($dir));
```

### Ruby
```ruby
# BAD
system("ls #{dir}")

# GOOD — array form skips shell
system("ls", dir)
exec(["ls", dir])
```

The principle: **argument vector passes intent (a list of strings) — string passes a script the shell will interpret**.

---

## 3 — Input Validation (whitelist format)

Before the input reaches anything dangerous, check it matches the expected shape.

### PHP — `filter_var`
```php
// IPv4 only
if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
    http_response_code(400); exit("Bad IP");
}

// Email
filter_var($email, FILTER_VALIDATE_EMAIL)

// URL
filter_var($url, FILTER_VALIDATE_URL)

// Integer with range
filter_var($n, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 100]])
```

### JavaScript / Node.js
```javascript
// Strict IPv4 regex
const ipRegex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)(\.(25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$/;
if (!ipRegex.test(ip)) { return res.status(400).send("Bad IP"); }

// Or use a library:
const isIp = require('is-ip');
if (!isIp.v4(ip)) { /* reject */ }
```

### Python
```python
import ipaddress
try:
    ipaddress.IPv4Address(user_input)
except ValueError:
    abort(400)

# Or via regex:
import re
if not re.fullmatch(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', user_input):
    abort(400)
```

### Whitelist principles
- Use `^...$` anchors in regex (full match, not "contains")
- Define what's allowed, NOT what's blocked
- Validate before sanitization (validation rejects; sanitization scrubs)
- Match the narrowest format possible — "IP address" not "string up to 50 chars"

---

## 4 — Input Sanitization

After validation, strip anything special that snuck through.

### PHP
```php
// Strict whitelist — only A-Z, a-z, 0-9, and dot
$ip = preg_replace('/[^A-Za-z0-9.]/', '', $_GET['ip']);

// For shell args specifically:
$safe = escapeshellarg($input);   // wraps in quotes + escapes embedded quotes
system("ls " . $safe);

// For full shell commands:
$safe = escapeshellcmd($input);   // escapes shell metacharacters
```

### JavaScript / Node.js
```javascript
// Strip everything but alphanumerics + dot
ip = ip.replace(/[^A-Za-z0-9.]/g, '');

// For HTML output (different threat):
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(input);
```

### Python
```python
# Allowlist only — keep alphanum + dot
import re
ip = re.sub(r'[^A-Za-z0-9.]', '', ip)

# For shell args (use sparingly — argv is better):
import shlex
safe_arg = shlex.quote(user_input)
```

> **`escapeshellcmd`/`escapeshellarg` are still bypassable in some shell contexts** (especially with nested commands, `$()` substitution, or non-shell-aware sinks). The CPTS module explicitly notes this. Argv arrays + validation > escaping.

---

## 5 — Server Hardening

### Run with least privilege
- Web server as `www-data` / `nginx` / `apache` — never root
- Use systemd `User=`/`Group=` directives
- Docker containers as non-root via `USER` directive

### Disable dangerous functions (PHP)
```ini
; php.ini
disable_functions = system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec,popen
open_basedir = /var/www/html/
```

### Reject double-encoded requests
Some WAFs decode the URL once; if the app decodes again, single-encoded payloads bypass. Configure nginx/Apache to reject `%25` sequences in suspicious contexts.

### Restrict file access
```ini
open_basedir = /var/www/html/   ; PHP
```
```apache
<Directory />
    AllowOverride None
    Require all denied
</Directory>
```

### Drop privileges in subprocesses
If you must shell out, do it as a less-privileged user:
```bash
sudo -u nobody /usr/local/bin/safe-tool "$arg"
```

---

## 6 — WAF (Defense-in-Depth)

| WAF | Strength |
|-----|----------|
| **ModSecurity + OWASP CRS** | Free, robust, integrates with Apache/nginx |
| **Cloudflare WAF** | Cloud-edge filtering, large ruleset |
| **AWS WAF** | AWS-native, customizable rules |
| **Imperva** | Enterprise, paid |
| **F5 ASM** | Enterprise, paid |

Default OWASP CRS rules catch:
- Common shell operators (`;`, `&`, `|`, `&&`)
- Known command names (`whoami`, `cat`, `nc`)
- Base64-decode-exec patterns
- Encoded versions of the above

**Don't rely on WAF as the only defense** — module's Section 9 demonstrated that ML-aware obfuscators can bypass everything. WAF is a layer, not a fix.

---

## Defense Priority Table

| Attack class | Stops it |
|--------------|----------|
| Direct injection via blacklisted char | Argv array invocation (no shell) |
| Filter bypass via obfuscation | Input validation (whitelist format), then argv |
| Encoded payload | Validation BEFORE decoding; reject double-encoded |
| Polyglot input (cmd + sqli) | Layer-specific defenses for each |
| Indirect (stored input → later exec) | Sanitize on both input and use |
| Library CVE (e.g., ImageMagick) | Patch + restrict policy.xml |

---

## Secure Reference Implementation (PHP)

```php
<?php
// 1. Validate format
$ip = $_GET['ip'] ?? '';
if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
    http_response_code(400); exit("Invalid IP");
}

// 2. Sanitize as defense-in-depth (redundant but safe)
$ip = preg_replace('/[^0-9.]/', '', $ip);

// 3. Use argv-style invocation when possible
// pcntl_exec takes an array — no shell involved
// (Note: pcntl is POSIX, requires the extension)
pcntl_exec('/bin/ping', ['-c', '1', $ip]);

// Or if proc_open is the only option (still safer than system()):
$proc = proc_open(
    ['ping', '-c', '1', $ip],  // PHP 7.4+: array form, no shell
    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes
);
$out = stream_get_contents($pipes[1]);
proc_close($proc);
echo nl2br(htmlspecialchars($out));  // output-safe rendering
?>
```

---

## Exam Notes

- **Argv arrays > escaping > blacklist filtering** — memorize this hierarchy
- `escapeshellarg`/`escapeshellcmd` are convenient but BYPASSABLE (multiple CVE histories) — use argv arrays when possible
- Whitelist validation via `filter_var` (PHP) / `isIp` (Node) / `ipaddress` (Python) is the canonical input check for typed data
- `disable_functions` + `open_basedir` are the safety net — even if injection succeeds, blast radius is limited
- WAF (ModSecurity / OWASP CRS) is layer 6 — never the only defense
- Real-world: most command injection bugs are because devs wrote `system("cmd " + input)` thinking escaping was enough. The fix is to never concatenate.
- For audit: `grep -rE 'system\(|exec\(|shell_exec\(|passthru\(|popen\(' .` finds candidate sinks in PHP source
