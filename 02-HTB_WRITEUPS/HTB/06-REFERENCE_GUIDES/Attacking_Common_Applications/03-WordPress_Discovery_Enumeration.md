# Section 3 — WordPress: Discovery & Enumeration

WordPress = ~32.5% of the internet. Almost every external pentest will involve at least one WP instance. Per WPScan, **54% of known WP vulnerabilities live in plugins**, 31.5% in core, 14.5% in themes. → Plugin enumeration is the highest-leverage step.

---

## Discovery Signals

| Signal | What it tells you |
|--------|-------------------|
| `/robots.txt` mentions `/wp-admin/` or `/wp-content/` | WordPress |
| `<meta name="generator" content="WordPress X.Y">` | WordPress + version |
| `/wp-login.php` 200 | WordPress admin login |
| `wp-content/plugins/*` in HTML | Installed plugins |
| `wp-content/themes/*` in HTML | Active theme |
| `/?feed=rss2` shows `<generator>https://wordpress.org/?v=X.Y</generator>` | Version |
| `/readme.html` 200 | Version + sometimes patch notes |
| Author URL `/?author=N` redirects to `/author/username/` | User enumeration |

### Quick fingerprint
```bash
curl -s http://target | grep -i 'wp-content\|wordpress\|generator'
curl -s http://target/robots.txt
curl -s http://target/?feed=rss2 | grep generator
```

---

## User Roles (5 standard)

| Role | Capabilities | Attacker payoff |
|------|--------------|-----------------|
| **Administrator** | All admin features, theme/plugin code edit | RCE via theme/plugin editor |
| Editor | Manage all posts | Stored XSS in posts (admin-targeted) |
| Author | Manage own posts; access some plugins | Sometimes vulnerable plugin access |
| Contributor | Write but not publish | Stored XSS |
| Subscriber | Read/edit profile | Often unauthenticated-equivalent, but can sometimes hit authenticated CVEs |

**Admin = RCE** in most installs — the Theme Editor and Plugin Editor write directly to PHP files.

---

## Manual Enumeration

### Core version
```bash
curl -s http://target | grep -i 'name="generator"'
# <meta name="generator" content="WordPress 5.8" />

curl -s http://target/?feed=rss2 | grep generator
# <generator>https://wordpress.org/?v=5.8</generator>

curl -s http://target/readme.html | grep -i version
```

### Theme
```bash
curl -s http://target | grep -oE 'wp-content/themes/[a-z0-9-]+' | sort -u
```
Then pull `style.css`:
```bash
curl -s http://target/wp-content/themes/THEME/style.css | head
# Theme Name, Version, Author all in the header
```

### Plugins via HTML scrape
```bash
# Single page
curl -s http://target | grep -oE 'wp-content/plugins/[a-zA-Z0-9_-]+' | sort -u

# Crawl multiple posts/pages — plugins vary by page
for i in $(seq 1 30); do
  out=$(curl -s "http://target/?p=$i" | grep -oE 'wp-content/plugins/[a-zA-Z0-9_-]+' | sort -u | tr '\n' ' ')
  [ -n "$out" ] && echo "p=$i: $out"
done
```

**Key:** plugins are added page-by-page. The homepage may show contact-form-7 + mail-masta, but a specific post may load wpdiscuz (comments) or wp-sitemap-page (sitemap shortcode). Always crawl multiple pages.

### Plugin version
```bash
# Best: readme.txt — Stable tag is the released version
curl -s http://target/wp-content/plugins/PLUGIN/readme.txt | head -10

# Fallback: ?ver= query string in <link>/<script> tags
curl -s http://target | grep -oE 'plugins/[^/]+/[^?]+\?ver=[0-9.]+'
```

### "Powered by" footer leaks
Some plugins write themselves into rendered output:
```html
<p><a href="http://wordpress.org/plugins/wp-sitemap-page/">Powered by "WP Sitemap Page"</a></p>
```
Grep page output for `Powered by` and `wordpress.org/plugins/`.

### User enumeration via login error
```
"The password for username admin is incorrect."   ← admin exists
"The username someone is not registered..."        ← invalid user
```
Different error text per case = enumerable.

### User enumeration via author param
```bash
for i in $(seq 1 20); do
  loc=$(curl -sI "http://target/?author=$i" | grep -i location | awk '{print $2}')
  [ -n "$loc" ] && echo "$i  $loc"
done
# /?author=1 → /author/admin/   → user=admin
# /?author=2 → /author/john/    → user=john
```

### XML-RPC (`/xmlrpc.php`)
```bash
curl -s http://target/xmlrpc.php
# "XML-RPC server accepts POST requests only." → enabled
```
If enabled → password brute force via `wp.getUsersBlogs`, pingback SSRF, and amplification.

---

## WPScan (Automated)

### Install
```bash
sudo gem install wpscan
# OR: pre-installed on Kali / Parrot
```

### API token
Free tier: 25 lookups/day. Register at wpscan.com → grab token → pass via `--api-token`.

### Basic scan
```bash
wpscan --url http://target \
       --enumerate ap,at,u,vp,vt \
       --api-token <TOKEN> \
       --plugins-detection aggressive
```

| `--enumerate` flag | Targets |
|--------------------|---------|
| `vp` | Vulnerable plugins (default) |
| `ap` | All plugins (aggressive) |
| `vt` | Vulnerable themes (default) |
| `at` | All themes |
| `u` | Usernames |
| `tt` | Timthumbs |
| `cb` | Config backups |
| `dbe` | DB exports |
| `m` | Media |

### Detection modes
- `passive` — pulls from HTML only (stealthier)
- `aggressive` — also probes file paths, readme.txt, etc. (thorough)
- `mixed` (default) — both

### Brute force login
```bash
wpscan --url http://target --usernames users.txt --passwords passwords.txt
wpscan --url http://target -U admin -P /usr/share/wordlists/rockyou.txt --max-threads 5
```

### XML-RPC brute force (often faster, fewer rate limits)
```bash
wpscan --url http://target -U admin -P passwords.txt --password-attack xmlrpc
```

---

## What WPScan Misses

The example scan in the section found `mail-masta` but missed `wpDiscuz` and `Contact Form 7`. Reason: WPScan's homepage-only passive mode didn't trigger the wpdiscuz comment script (comments only render on individual post pages).

**Always supplement WPScan with manual crawling across multiple posts/pages.** Set `--enumerate ap` + `--plugins-detection aggressive` to force readme-path probing.

---

## Lab Walkthrough (`blog.inlanefreight.local`)

### /etc/hosts setup
```bash
sudo sed -i '/inlanefreight.local/d' /etc/hosts
IP=10.129.98.141
echo "$IP   app.inlanefreight.local dev.inlanefreight.local drupal-dev.inlanefreight.local drupal-qa.inlanefreight.local drupal-acc.inlanefreight.local drupal.inlanefreight.local blog.inlanefreight.local" | sudo tee -a /etc/hosts
```

### Q1 — flag.txt in accessible directory

The blog has directory listings enabled. Walk `/wp-content/uploads/`:
```bash
URL="http://blog.inlanefreight.local"
curl -sk "$URL/wp-content/uploads/" | grep -oE 'href="[^"]+"'
# 2021/  2026/

curl -sk "$URL/wp-content/uploads/2021/" | grep -oE 'href="[^"]+"'
# 08/  09/

curl -sk "$URL/wp-content/uploads/2021/08/" | grep -oE 'href="[^"]+"'
# ...flag.txt...

curl -sk "$URL/wp-content/uploads/2021/08/flag.txt"
```
**Flag:** `0ptions_ind3xeS_ftw!`

The flag's content nods at the Apache `Options +Indexes` directive that enables directory listing.

### Q2 — Discover another plugin (3 words)

Crawling page sources for plugin paths yields the same three plugins the module text already mentions (contact-form-7, mail-masta, wpdiscuz). The fourth shows up via a "Powered by" footer leak — grep `?p=1` HTML for that string:

```bash
curl -sk "$URL/?p=1" | grep -i "powered by"
# <a href="http://wordpress.org/plugins/wp-sitemap-page/">Powered by "WP Sitemap Page"</a>
```

**Plugin name:** `WP Sitemap Page`

### Q3 — Version of WP Sitemap Page

readme.txt is publicly readable on every plugin's directory:
```bash
curl -sk "$URL/wp-content/plugins/wp-sitemap-page/readme.txt" | head
```
```
=== WP Sitemap Page ===
Contributors: funnycat
Stable tag: 1.6.4
```
**Version:** `1.6.4`

---

## Building the Data Picture

After this section's enumeration on `blog.inlanefreight.local`:

| Component | Value | Note |
|-----------|-------|------|
| WP core | 5.8 | Has CVEs but not RCE-worthy |
| Theme | transport-gravity 1.0.1 | Child of business-gravity |
| Plugin: Contact Form 7 | 5.4.2 | Active |
| Plugin: mail-masta | 1.0 | LFI + SQLi public exploits |
| Plugin: wpDiscuz | 7.0.4 | **Unauthenticated RCE** (CVE-2020-24186) |
| Plugin: WP Sitemap Page | 1.6.4 | Known CVEs |
| Users | admin, john | Confirmed valid via login error |
| XML-RPC | Enabled | Brute-force amplifier |
| Directory listing | Enabled site-wide | Indexed `/wp-content/uploads/` etc. |

**Strongest attack:** wpDiscuz 7.0.4 unauth RCE (used in next section).

---

## Exam Notes

- WP fingerprint trinity: `/robots.txt`, meta generator tag, `/?feed=rss2`
- **Crawl multiple posts** for plugins — comments, sitemaps, contact forms each load different scripts
- `wp-content/plugins/PLUGIN/readme.txt` → `Stable tag: X.Y.Z` is the most reliable version source
- "Powered by" leaks often reveal plugins that don't show in HTML asset tags
- User enumeration: distinct login errors, `?author=N` redirects, `/wp-json/wp/v2/users` REST API
- WPScan defaults miss plugins that only render on specific pages — pair with manual enum
- XML-RPC enabled = preferred brute-force endpoint (`--password-attack xmlrpc`)
- Directory listing on `/wp-content/uploads/` = files attacker uploaded persist and may be enumerable
- The 5-role hierarchy matters for plugin abuse — Author-level access sometimes opens up CVEs that Subscriber-level can't reach
- Strongest path on most engagements: cred reuse → wp-login.php → admin → theme/plugin editor → RCE
