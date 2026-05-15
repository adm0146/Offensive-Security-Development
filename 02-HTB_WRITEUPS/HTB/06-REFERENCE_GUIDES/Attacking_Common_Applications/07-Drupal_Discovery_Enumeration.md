# Section 7 — Drupal: Discovery & Enumeration

Drupal = ~2.4% CMS market share, ~950k instances. Written in PHP, MySQL/PostgreSQL/SQLite backend.
56% of government websites worldwide. 3 user types: Administrator, Authenticated User, Anonymous.

---

## Fingerprinting Drupal

| Signal | Location |
|--------|----------|
| `<meta name="Generator" content="Drupal X ...">` | Page `<head>` |
| "Powered by Drupal" in footer | Page HTML |
| `/node/<N>` URL structure | Content pages |
| `/robots.txt` references `/node` | robots.txt |
| Drupal logo (if default theme) | Visual |

```bash
curl -s http://target/ | grep -i drupal
curl -s http://target/robots.txt | grep -i node
```
> Fingerprints Drupal via the generator tag and `/node` references in robots.txt; swap `target` for the host.

---

## Version Fingerprinting

### 1. CHANGELOG.txt (older installs — newer versions block this)
```bash
curl -s http://target/CHANGELOG.txt | grep -m2 ""
# Drupal 7.57, 2018-02-21

# If 404 → newer Drupal with hardening, try other methods
```
> Reads the exact Drupal version from CHANGELOG.txt (older installs only); swap `target` for the host.

### 2. README.txt
```bash
curl -s http://target/README.txt | head -5
```
> Reads Drupal version info from README.txt; swap `target` for the host.

### 3. Meta generator tag
```bash
curl -s http://target/ | grep -i 'name="Generator"'
# <meta name="Generator" content="Drupal 8 (https://www.drupal.org)" />
# Note: this gives major version only, not minor
```
> Reads the Drupal major version from the meta generator tag; swap `target` for the host.

### 4. droopescan (automated — most thorough)
```bash
droopescan scan drupal -u http://target/
# Returns: possible version range, installed plugins, admin login URL
```
> Runs droopescan against Drupal for version range, modules, and admin URL; swap `target` for the host.

droopescan has much more Drupal functionality than Joomla — use it as primary tool for Drupal.

---

## User Roles

| Role | Access |
|------|--------|
| Administrator | Full control |
| Authenticated User | Login, add/edit content (permissions-based) |
| Anonymous | Read only (default) |

---

## Key Drupal Paths

| Path | Purpose |
|------|---------|
| `/user/login` | Login page |
| `/node/<N>` | Content nodes (blog posts, polls, articles) |
| `/admin/` | Admin panel |
| `/CHANGELOG.txt` | Version (if not blocked) |
| `/README.txt` | Version info |
| `/modules/php/LICENSE.txt` | PHP module present (droopescan finds this) |

---

## droopescan Output Interpretation

```
[+] Plugins found:
    php http://target/modules/php/          ← PHP filter module (enables PHP execution if enabled)
        http://target/modules/php/LICENSE.txt

[+] Possible version(s):
    8.9.0
    8.9.1

[+] Possible interesting urls found:
    Default admin - http://target/user/login
```

The **PHP module** is a key finding — if enabled and you have admin access, it allows direct PHP code execution in content nodes (covered in next section).

---

## Lab Walkthrough

### Q1 — Version on `drupal-qa.inlanefreight.local`

```bash
# Try CHANGELOG.txt first
curl -s http://drupal-qa.inlanefreight.local/CHANGELOG.txt | grep -m2 ""

# If blocked, try droopescan or meta tag
curl -s http://drupal-qa.inlanefreight.local/ | grep -i generator
```
> Checks the lab's Drupal version via CHANGELOG.txt then falls back to the generator tag; swap the host.

```bash
curl -s http://drupal-qa.inlanefreight.local/CHANGELOG.txt | grep -m2 ""
# Drupal 7.30, 2014-07-24
```
> Confirms the lab's exact Drupal version from CHANGELOG.txt; swap the host for your target.

**Answer:** `7.30`

---

## Exam Notes

- CHANGELOG.txt = fastest version check; blocked on newer/hardened installs (returns 404)
- `/node/<N>` structure is a reliable Drupal fingerprint regardless of theme
- droopescan is the go-to automated scanner for Drupal — far more capable than for Joomla
- PHP module in droopescan output is high-value — means PHP execution possible if enabled (check next section)
- Three version sources to try in order: CHANGELOG.txt → README.txt → droopescan
- Major version from meta generator; exact minor from CHANGELOG.txt or droopescan
- Default login at `/user/login` (not `/wp-login.php` or `/administrator/`)
