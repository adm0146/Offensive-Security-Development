# Section 6 — DNS Records

> Concepts only. No lab. Explains why vhost/subdomain fuzzing is necessary and how to add entries to /etc/hosts for HTB targets.

---

## The Problem

Browsers resolve domain names by checking:
1. Local `/etc/hosts` file
2. Public DNS (e.g. 8.8.8.8)

HTB lab domains like `academy.htb` don't exist in public DNS. Visiting `http://academy.htb:PORT` fails with a connection error because the browser can't resolve the hostname to an IP.

---

## Adding a Domain to /etc/hosts

```bash
sudo sh -c 'echo "TARGET_IP  academy.htb" >> /etc/hosts'

# Verify it was added:
grep academy.htb /etc/hosts
```

After adding the entry, `http://academy.htb:PORT` works — the browser maps the hostname to the IP via `/etc/hosts` before hitting DNS.

---

## Why This Matters for Subdomain Fuzzing

Once the base domain (`academy.htb`) is added to `/etc/hosts`, it resolves to the same content as the IP. But subdomains like `admin.academy.htb` won't be in `/etc/hosts` yet — they require vhost fuzzing to discover, then a separate `/etc/hosts` entry to access.

The presence of a message like **"Admin panel moved to academy.htb"** buried in a page is a signal to start looking for subdomains or vhosts — the admin panel is likely hiding at something like `admin.academy.htb`.

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

---

## Exam Notes

- On HTB/CPTS labs: always add the target domain to `/etc/hosts` before attempting vhost fuzzing
- The IP stays the same — only the `Host:` header changes when fuzzing vhosts
- A hint like "admin panel moved to X.domain.com" = immediate signal to fuzz for subdomains
- After finding a vhost with ffuf, add it to `/etc/hosts` to visit it in the browser
