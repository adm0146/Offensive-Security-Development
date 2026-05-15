# Section 10 — File Inclusion Prevention

---

## The Hierarchy of Defenses

```
1. Don't use user input in include functions     ← best
2. Whitelist allowed values                       ← if input must drive inclusion
3. Sanitize paths (basename, recursive strip)     ← belt-and-suspenders
4. Lock down the server (open_basedir, disable    ← contains damage if all else fails
   url_include, disable dangerous functions)
5. WAF (ModSecurity)                              ← detect + alert
```

---

## Defense 1 — Don't Pass User Input To Include Sinks

The strongest fix. If `?page=about` controls inclusion, replace with:
- Server-side routing (`/about` → renders `about.php` server-side)
- An integer ID mapped server-side to a static path
- A fixed switch/case lookup

```php
// Vulnerable
include($_GET['page']);

// Fixed — whitelist mapping
$allowed = ['home' => 'home.php', 'about' => 'about.php', 'contact' => 'contact.php'];
$page = $_GET['page'] ?? 'home';
if (!isset($allowed[$page])) { http_response_code(404); exit; }
include($allowed[$page]);
```
> The whitelist maps user-supplied keys to server-controlled file paths. The user picks a key like `about`; the server decides what file to include. No path traversal is possible because the user never touches the file path directly.

The whitelist is **server-controlled** — the user picks a key, never supplies the filename.

---

## Defense 2 — Path Sanitization

When unavoidable (e.g., user-specified attachment filename):

```php
// PHP's basename() strips directory components — returns just the filename
$file = basename($_GET['file']);
include("./uploads/" . $file);

// Recursive strip of ../ (covers the ....// bypass)
while (strpos($input, '../') !== false) {
    $input = str_replace('../', '', $input);
}
```

> `basename()` is great for filenames but breaks if the app needs to descend into subdirs. Combine with whitelist where possible. Custom sanitizers tend to have edge cases — prefer framework primitives.

---

## Defense 3 — PHP Configuration Hardening

These go in `php.ini`:

```ini
# Block remote URL inclusion (kills RFI + data:// + php://input attacks)
allow_url_fopen = Off
allow_url_include = Off

# Sandbox PHP to a single directory tree (no /etc/passwd, no /tmp games)
open_basedir = /var/www/html/

# Disable dangerous functions per app needs
disable_functions = system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec

# Don't reveal PHP version
expose_php = Off
```
> These settings go in `php.ini`. `allow_url_include = Off` kills Remote File Inclusion (RFI) and PHP wrapper attacks. `open_basedir` confines PHP to the webroot so traversal out of it fails. `disable_functions` removes shell execution functions individually.

After editing, restart the web server: `systemctl restart apache2` (or `php-fpm`).

### Verify the changes
```bash
php -i | grep -E '(allow_url_include|open_basedir|disable_functions)'
```
> Dumps the active PHP configuration and filters for the three key security settings. Confirm each is set correctly after restarting the web server.

---

## Defense 4 — Web Server Configuration

### Apache
```apache
# In /etc/apache2/apache2.conf or vhost
<Directory />
    AllowOverride None
    Require all denied
</Directory>

<Directory /var/www/html>
    Require all granted
</Directory>
```

### nginx
```nginx
# Restrict PHP execution to specific directory
location ~ /uploads/.*\.php$ {
    deny all;
}
```

> Locks PHP execution out of upload dirs — defeats the file-upload-then-include chain.

---

## Defense 5 — WAF (ModSecurity)

Drop in front of Apache/nginx. Default OWASP CRS rules block:
- `../` traversal
- `php://filter` and `data://` wrappers
- `/etc/passwd` and other sensitive path reads
- Encoded variants (`%2e%2e%2f`, double-encoded, mixed-case)

```bash
sudo apt install libapache2-mod-security2
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf

# Start in permissive mode — log only, don't block:
# SecRuleEngine DetectionOnly

# After tuning false positives:
# SecRuleEngine On
```
> Installs ModSecurity and copies the recommended config. Start in `DetectionOnly` mode to log attacks without blocking. Switch to `On` only after tuning out false positives, or you risk breaking legitimate app requests.

Permissive mode is critical. False positives in blocking mode break legitimate apps. Tune for at least two weeks before switching to `On`.

---

## Lab — Hardening Walkthrough

**Target:** `10.129.29.112` (HTB VPN) — SSH `htb-student:HTB_@cademy_stdnt!`

### Q1 — Apache php.ini location

```bash
ssh htb-student@10.129.29.112 'php --ini; find /etc/php -name php.ini'
```
> SSH into the target and run two commands: `php --ini` shows which config files PHP loaded, and `find` locates all `php.ini` files. The Apache-specific one at `/etc/php/7.4/apache2/php.ini` is what controls the web process.

PHP shows two configs:
- `/etc/php/7.4/cli/php.ini` — for CLI scripts
- `/etc/php/7.4/apache2/php.ini` — for Apache module

**Answer:** `/etc/php/7.4/apache2/php.ini`

### Q2 — Block system() and trigger error

```bash
# Edit php.ini to disable system()
sudo sed -i 's/^disable_functions =.*/disable_functions = system/' /etc/php/7.4/apache2/php.ini
sudo systemctl restart apache2

# Create a test PHP that calls system()
echo '<?php system("id"); ?>' | sudo tee /var/www/html/test.php
curl -s http://localhost/test.php

# Read the error log
sudo tail /var/log/apache2/error.log | grep system
# → PHP Warning:  system() has been disabled for security reasons in /var/www/html/test.php on line 1
```
> Updates the `disable_functions` line in `php.ini` using `sed`, restarts Apache, then writes a test script that calls `system()`. The error log confirms the function was disabled and reveals the exact warning message format.

**Answer:** `security`

> The full error: *"system() has been disabled for **security** reasons"*

---

## Defense Priority Table

| Defense | Stops |
|---------|-------|
| `allow_url_include = Off` | RFI, `data://`, `php://input`, remote payload hosting |
| `allow_url_fopen = Off` | All remote file ops, kills `file_get_contents("http://...")` |
| `open_basedir = /var/www/html/` | Path traversal out of webroot |
| `disable_functions = system,exec,...` | OS command execution from PHP |
| Whitelist mapping in code | All LFI vectors |
| `basename()` on user input | Path traversal in filename context |
| ModSecurity OWASP CRS | Generic LFI/RFI payload signatures |
| Drop PHP execution in upload dirs | Upload-then-include RCE chain |

---

## Exam Notes

- The CPTS exam tests the **conceptual chain**: which defense stops which attack
- `allow_url_include = Off` is the single most impactful PHP setting against RFI — knows by name
- `open_basedir` defeats `../` traversal entirely — also know by name
- `disable_functions` is the function-by-function blocklist; the error message format is *"`function()` has been disabled for security reasons"* (memorize for the lab Q2 pattern)
- Whitelist mapping is the only defense that survives all bypass techniques — code-level fix, not config
- WAF should be in **DetectionOnly** mode initially — blocking false positives is operationally worse than missing some malicious traffic
- The error log entry pattern is a great IOC for blue teams — `disabled for security reasons` is grep-friendly
