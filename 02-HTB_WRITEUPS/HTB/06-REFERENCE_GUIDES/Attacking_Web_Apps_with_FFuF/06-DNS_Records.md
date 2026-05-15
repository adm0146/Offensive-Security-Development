# Section 6 — DNS Records

> Concepts only. No lab. Explains why vhost/subdomain fuzzing is necessary and how to add entries to /etc/hosts for HTB targets.

---

## The Problem

When your browser gets a domain name, it checks two places in order:
1. Your local `/etc/hosts` file
2. Public DNS (e.g. 8.8.8.8)

HTB lab domains like `academy.htb` are not in public DNS. If you try to visit `http://academy.htb:PORT`, the browser fails right away because it can't look up the IP address.

---

## Adding a Domain to /etc/hosts

```bash
sudo sh -c 'echo "TARGET_IP  academy.htb" >> /etc/hosts'

# Verify it was added:
grep academy.htb /etc/hosts
```
> Appends a line to `/etc/hosts` so your machine resolves `academy.htb` to the target IP without using public DNS. The `grep` confirms the entry was written correctly before you try to browse it.

After adding the entry, `http://academy.htb:PORT` works. Your browser finds the IP in `/etc/hosts` before it ever queries DNS.

---

## Why This Matters for Subdomain Fuzzing

Once the base domain (`academy.htb`) is in `/etc/hosts`, it resolves to the same content as the IP. But subdomains like `admin.academy.htb` are not there yet. You need to fuzz for them first, then add each one you find.

A message like **"Admin panel moved to academy.htb"** somewhere on the page is a hint. The admin panel is probably at something like `admin.academy.htb`. Start vhost fuzzing when you see anything like that.

---

## /etc/hosts Management

```bash
# Add a single entry:
sudo sh -c 'echo "10.10.10.10  academy.htb" >> /etc/hosts'

# Add multiple subdomains on one line:
sudo sh -c 'echo "10.10.10.10  academy.htb admin.academy.htb" >> /etc/hosts'

# View current entries:
cat /etc/hosts

# Remove an entry (edit manually):
sudo nano /etc/hosts
```
> Multiple hostnames on one line all resolve to the same IP. After vhost fuzzing finds a new subdomain, add it here before trying to browse it.

---

## Exam Notes

- On HTB/CPTS labs: always add the target domain to `/etc/hosts` before attempting vhost fuzzing
- The IP stays the same — only the `Host:` header changes when fuzzing vhosts
- A hint like "admin panel moved to X.domain.com" = immediate signal to fuzz for subdomains
- After finding a vhost with ffuf, add it to `/etc/hosts` to visit it in the browser
