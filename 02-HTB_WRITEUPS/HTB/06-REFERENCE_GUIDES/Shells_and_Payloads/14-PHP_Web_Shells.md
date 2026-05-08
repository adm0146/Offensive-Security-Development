# 14 — PHP Web Shells

## Overview

**PHP (Hypertext Preprocessor)** is an open-source server-side scripting language and the most popular web backend language — used by **78.6% of all websites** with a known server-side language (W3Techs, October 2021). If a target runs PHP, there's a strong chance you can deploy a PHP-based web shell.

---

## Why PHP Matters for Pentesting

| Aspect | Detail |
|--------|--------|
| **Market share** | ~78.6% of server-side web apps |
| **Server-side execution** | PHP processes code on the server before sending HTML to the browser |
| **Common targets** | WordPress, Joomla, Drupal, rConfig, custom apps |
| **Indicator** | Seeing `.php` files (e.g., `login.php`) confirms PHP is in use |
| **Implication** | PHP-based web shells are likely executable on the target |

---

## How PHP Web Apps Work

```
User fills out form (username/password)
          ↓
Browser sends HTTP POST to login.php
          ↓
PHP processes input server-side
          ↓
Server returns HTML response to browser
```

> **Example:** rConfig uses `login.php` — seeing this tells us the server processes PHP, meaning we can likely upload and execute a `.php` web shell.

---

## PHP Web Shell Attack Workflow

```
1. Identify PHP is in use (look for .php files)
          ↓
2. Find an upload vulnerability or misconfiguration
          ↓
3. Upload PHP web shell payload
          ↓
4. Bypass file type restrictions (if any)
          ↓
5. Navigate to uploaded shell via browser
          ↓
6. Execute commands on underlying OS
```

---

## Recommended PHP Web Shell

| Tool | Detail |
|------|--------|
| **WhiteWinterWolf's PHP Web Shell** | Feature-rich, browser-based shell |
| **How to get it** | Download from source or copy/paste into a `.php` file |
| **File extension** | Must be `.php` — file type matters for execution |

---

## Hands-On: Uploading a PHP Web Shell (rConfig 3.9.6)

### Step 1: Log In to rConfig

```
Default credentials: admin:admin
```

### Step 2: Navigate to Upload Point

```
Devices → Vendors → Add Vendor
```

The **Vendor Logo** browse button accepts file uploads.

### Step 3: Upload the PHP Shell

- Select your `.php` web shell file via the browse button
- **Problem:** rConfig enforces file type restrictions (only `.png`, `.jpg`, `.gif`, etc.)
- Upload will fail without bypassing the restriction

---

## Bypassing File Type Restrictions with Burp Suite

### Configure Browser Proxy

| Setting | Value |
|---------|-------|
| **Proxy IP** | `127.0.0.1` |
| **Proxy Port** | `8080` |
| **Purpose** | Route all traffic through Burp to intercept and modify requests |

### Intercept and Modify the Upload

1. **Enable Burp Intercept** → turn intercept on
2. **Upload the `.php` file** via the Vendor Logo browse button → click Save
3. **Forward requests in Burp** until you see the `POST` request containing your file upload
4. **Find the `Content-type` header** in the request — it will show:
   ```
   Content-type: application/x-php
   ```
5. **Change it to:**
   ```
   Content-type: image/gif
   ```
6. **Forward the request** twice
7. **Turn off Burp interceptor** and return to the browser

### Why This Works

| Original | Modified | Effect |
|----------|----------|--------|
| `application/x-php` | `image/gif` | Server thinks it's an image, allows the upload |

> The server validates `Content-type` headers, not the actual file content. Changing this value tricks the server into accepting the `.php` file.

---

## Confirming the Upload

After bypassing the restriction:

| Indicator | Meaning |
|-----------|---------|
| **"Added new vendor [name] to Database"** | Upload was successful |
| **Ripped paper icon as logo** | rConfig didn't recognize the file as an image — defaulted to placeholder |

---

## Navigating to the Shell

Browse to the uploaded file:

```
http://<target>/images/vendor/connect.php
```

This executes the PHP payload and presents a web-based shell interface with:
- Command execution field
- File fetching capabilities
- Output display area

---

## Considerations When Using Web Shells

| Issue | Detail |
|-------|--------|
| **Auto-deletion** | Some apps automatically delete uploaded files after a set period |
| **Limited interactivity** | Navigating the file system, uploading/downloading files is clunky |
| **Command chaining** | May not work (e.g., `whoami && hostname` can fail) |
| **Instability** | Non-interactive shell sessions can be unreliable |
| **Evidence left behind** | Web shells leave artifacts — increases detection risk |

---

## Operational Security Best Practices

| Practice | Reason |
|----------|--------|
| **Establish reverse shell first** | More stable than relying on web shell alone |
| **Delete the payload after** | Remove the uploaded shell when you have a better connection |
| **Remove comments/signatures** | Strip author credits and ASCII art to evade AV |
| **Document everything** | Record methods attempted, filenames, upload locations |
| **Include file hashes** | Provide SHA1/MD5 of uploaded files in your report as proof |
| **Note what worked and didn't** | Valuable for the final report and future engagements |

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **PHP prevalence** | Most common server-side language — always check for it |
| **File extension matters** | Shell must be `.php` to execute |
| **Burp Suite bypass** | Change `Content-type` from `application/x-php` to `image/gif` |
| **Upload location** | rConfig stores vendor logos in `/images/vendor/` |
| **Web shells are temporary** | Upgrade to reverse shell, then clean up |
| **Document and hash** | Always log filenames, paths, and file hashes for your report |
