# Nmap Scripting Engine (NSE)

## Overview

The **Nmap Scripting Engine (NSE)** is a powerful feature that allows you to create custom scripts in **Lua** for advanced interaction with services and systems. NSE scripts enable:

- **Automated vulnerability detection** - Identify known vulnerabilities
- **Service enumeration** - Extract detailed service information
- **Brute-force attacks** - Test weak credentials
- **Host discovery** - Find hosts using broadcasts
- **Exploitation attempts** - Try known exploits
- **Fuzzing** - Identify unexpected behavior and vulnerabilities

---

## NSE Script Categories

NSE scripts are organized into **14 categories** based on their function and risk level:

| Category | Description | Use Case |
|----------|-------------|----------|
| **auth** | Determine authentication credentials | Identify default/weak credentials |
| **broadcast** | Host discovery via broadcasting; discovered hosts added to scan | Network reconnaissance |
| **brute** | Brute-force attacks on services with credential lists | Credential testing |
| **default** | Safe scripts executed with `-sC` option | Standard reconnaissance |
| **discovery** | Evaluate accessible services | Service information gathering |
| **dos** | Check for denial of service vulnerabilities | Vulnerability assessment (use cautiously) |
| **exploit** | Attempt to exploit known vulnerabilities | Active exploitation |
| **external** | Use external services for processing | Third-party data enrichment |
| **fuzzer** | Identify vulnerabilities via field mutation and fuzzing | Vulnerability discovery (time-intensive) |
| **intrusive** | Scripts that may negatively affect target system | Advanced testing (destructive) |
| **malware** | Check if target is infected with malware | Malware detection |
| **safe** | Non-destructive, non-intrusive scripts | Safe reconnaissance |
| **version** | Extend service version detection capabilities | Enhanced version fingerprinting |
| **vuln** | Identify specific known vulnerabilities | Vulnerability scanning |

---

## Quick Reference Commands

| Command | Purpose |
|---------|---------|
| `nmap <target> -sC` | Run default NSE scripts |
| `nmap <target> --script <category>` | Run all scripts in a category |
| `nmap <target> --script <script1>,<script2>` | Run specific scripts |
| `nmap <target> -sV --script vuln` | Service detection + vulnerability check |
| `nmap <target> -A` | Aggressive scan (service, OS, traceroute, default scripts) |

---

## Using NSE Scripts

### 1. Default Scripts (-sC)

Run the default safe scripts category automatically.

**Command:**
```bash
sudo nmap <target> -sC
```

**Equivalent to:**
```bash
sudo nmap <target> --script default
```

**What It Does:**
- Runs all scripts in the "default" category
- Safe, non-intrusive scripts
- Generally takes longer than basic scans
- Useful for standard reconnaissance

---

### 2. Specific Script Category

Run all scripts within a particular category.

**Command:**
```bash
sudo nmap <target> --script <category>
```

**Examples:**
```bash
sudo nmap 10.129.2.28 --script discovery
sudo nmap 10.129.2.28 --script vuln
sudo nmap 10.129.2.28 --script safe
```

---

### 3. Specific Scripts

Run only the named scripts you specify.

**Command:**
```bash
sudo nmap <target> --script <script-name>,<script-name>,...
```

**Example: SMTP Banner and Commands**
```bash
sudo nmap 10.129.2.28 -p 25 --script banner,smtp-commands
```

**Output:**
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-16 23:21 CEST
Nmap scan report for 10.129.2.28
Host is up (0.050s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_banner: 220 inlane ESMTP Postfix (Ubuntu)
|_smtp-commands: inlane, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8,
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
```

**Analysis:**
- **banner script** - Reveals Ubuntu Linux distribution
- **smtp-commands script** - Shows available SMTP commands (VRFY can enumerate users)
- Combined information helps identify exploitation opportunities

### Command Breakdown

| Parameter | Description |
|-----------|-------------|
| `10.129.2.28` | Target IP address |
| `-p 25` | Scan only port 25 (SMTP) |
| `--script banner,smtp-commands` | Run two specific NSE scripts |

---

## Aggressive Scanning (-A)

The aggressive option combines multiple scanning techniques into one comprehensive command.

**Command:**
```bash
sudo nmap <target> -A
```

**What -A Includes:**
- `-sV` - Service version detection
- `-O` - OS detection
- `--traceroute` - Trace network path to target
- `-sC` - Run default NSE scripts

### Aggressive Scan Example

**Command:**
```bash
sudo nmap 10.129.2.28 -p 80 -A
```

**Output:**
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-17 01:38 CEST
Nmap scan report for 10.129.2.28
Host is up (0.012s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: WordPress 5.3.4
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: blog.inlanefreight.com
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 3.2 - 4.9 (96%), Linux 2.6.32 - 3.10 (96%), Linux 3.4 - 3.10 (95%), Linux 3.1 (95%), Linux 3.2 (95%),
AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Synology DiskStation Manager 5.2-5644 (94%), Netgear RAIDiator 4.2.28 (94%),
Linux 2.6.32 - 2.6.35 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

TRACEROUTE
HOP RTT      ADDRESS
1   11.91 ms 10.129.2.28

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.36 seconds
```

**Information Discovered:**
- **Web Server:** Apache httpd 2.4.29
- **Web Application:** WordPress 5.3.4
- **Domain:** blog.inlanefreight.com
- **OS Guess:** Linux (96% confidence)
- **Network Distance:** 1 hop away

### Command Breakdown

| Parameter | Description |
|-----------|-------------|
| `10.129.2.28` | Target IP address |
| `-p 80` | Scan only port 80 (HTTP) |
| `-A` | Aggressive scan (service, OS, traceroute, default scripts) |

---

## Vulnerability Assessment

The `vuln` category focuses on identifying known vulnerabilities affecting the target.

**Command:**
```bash
sudo nmap <target> -p <port> -sV --script vuln
```

### Vulnerability Assessment Example

**Command:**
```bash
sudo nmap 10.129.2.28 -p 80 -sV --script vuln
```

**Output:**
```
Nmap scan report for 10.129.2.28
Host is up (0.036s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-enum:
|   /wp-login.php: Possible admin folder
|   /readme.html: Wordpress version: 2
|   /: WordPress version: 5.3.4
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|_  /readme.html: Interesting, a readme.
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-wordpress-users:
| Username found: admin
|_Search stopped at ID #25. Increase the upper limit if necessary with 'http-wordpress-users.limit'
| vulners:
|   cpe:/a:apache:http_server:2.4.29:
|     CVE-2019-0211	7.2	https://vulners.com/cve/CVE-2019-0211
|     CVE-2018-1312	6.8	https://vulners.com/cve/CVE-2018-1312
|     CVE-2017-15715	6.8	https://vulners.com/cve/CVE-2017-15715
```

### Information Discovered

**Web Application Enumeration:**
- WordPress version: 5.3.4
- Admin login page: /wp-login.php
- WordPress user: admin

**Service Information:**
- Apache httpd 2.4.29 (Ubuntu)

**Known Vulnerabilities:**
- CVE-2019-0211 (CVSS 7.2)
- CVE-2018-1312 (CVSS 6.8)
- CVE-2017-15715 (CVSS 6.8)

**Security Checks:**
- No stored XSS vulnerabilities found
- Upgrade page detected

### Command Breakdown

| Parameter | Description |
|-----------|-------------|
| `10.129.2.28` | Target IP address |
| `-p 80` | Scan only port 80 |
| `-sV` | Perform service version detection |
| `--script vuln` | Run all vulnerability detection scripts |

---

## How NSE Scripts Work

### Script Execution Flow

1. **Connection** - Script connects to the target service
2. **Probing** - Sends crafted requests/probes to the service
3. **Response Analysis** - Analyzes service responses
4. **Database Matching** - Compares against known vulnerability databases
5. **Result Formatting** - Presents findings in readable format

### Key Advantages

✅ **Automated Vulnerability Detection** - Identifies known CVEs automatically  
✅ **Service-Specific Testing** - Tailored probes for each service type  
✅ **Database Integration** - Cross-references external vulnerability databases  
✅ **Extensible** - Write custom scripts in Lua for specialized tests  
✅ **Time-Efficient** - Automates what would take manual enumeration hours  

---

## Real-World Workflow

### Example: Complete Web Server Assessment

**Step 1: Aggressive Scan for Overview**
```bash
sudo nmap 10.129.2.28 -p 80 -A
```
Result: Identifies Apache 2.4.29 + WordPress 5.3.4

**Step 2: Vulnerability Check**
```bash
sudo nmap 10.129.2.28 -p 80 -sV --script vuln
```
Result: Finds CVE-2019-0211, admin user, WordPress vulnerabilities

**Step 3: Deep Discovery**
```bash
sudo nmap 10.129.2.28 -p 80 --script discovery,http-enum
```
Result: Maps all accessible resources and endpoints

**Step 4: Exploitation Planning**
- Use discovered CVEs for targeted exploit research
- Test default/weak credentials on WordPress login
- Further enumerate user accounts
- Test for common misconfigurations

---

## Best Practices for NSE

✅ **Start with default scripts** - Use `-sC` for initial reconnaissance  
✅ **Use categories strategically** - Match script categories to your goals  
✅ **Be aware of intrusive scripts** - Test impacts before using in production environments  
✅ **Review results carefully** - False positives can occur, especially with version detection  
✅ **Cross-reference findings** - Use multiple scripts to confirm discoveries  
✅ **Document all findings** - Save output for reporting (`-oA` format)  
✅ **Update NSE scripts** - Run `nmap --script-updatedb` periodically  

---

## Finding Additional Scripts

NSE scripts are well-documented at the official Nmap NSE documentation:

**Resource:** https://nmap.org/nsedoc/index.html

This site provides:
- Complete script listings by category
- Detailed documentation for each script
- Usage examples
- Output format descriptions
- Script authors and modification history

---

## Common NSE Script Examples

| Script | Purpose | Category |
|--------|---------|----------|
| `banner` | Grab service banner | default |
| `smtp-commands` | List SMTP commands | discovery |
| `http-enum` | Enumerate web server | discovery |
| `http-wordpress-users` | Enumerate WordPress users | discovery |
| `ssl-enum-ciphers` | Check SSL/TLS ciphers | discovery |
| `smb-enum-shares` | Enumerate SMB shares | discovery |
| `mysql-info` | Gather MySQL info | discovery |
| `ftp-anon` | Check FTP anonymous access | auth |
| `vnc-title` | Get VNC server title | discovery |
| `vulners` | Check against vulnerability database | vuln |

---

## Real-World Practice Problem: Multi-Service Enumeration

### Scenario
Target: 10.129.35.145 - A machine with multiple open services requiring systematic enumeration.

### Step 1: Service Detection with Default Scripts

**Command:**
```bash
nmap -sV -sC 10.129.35.145
```

**Output:**
```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-10 10:43 -0600
Stats: 0:01:49 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 85.71% done; ETC: 10:45 (0:00:18 remaining)
Nmap scan report for 10.129.35.145
Host is up (0.054s latency).
Not shown: 993 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 71:c1:89:90:7f:fd:4f:60:e0:54:f3:85:e6:35:6c:2b (RSA)
|   256 e1:8e:53:18:42:af:2a:de:c0:12:1e:2e:54:06:4f:70 (ECDSA)
|_  256 1a:cc:ac:d4:94:5c:d6:1d:71:e7:39:de:14:27:3c:3c (ED25519)
80/tcp    open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
110/tcp   open  pop3        Dovecot pop3d
|_pop3-capabilities: RESP-CODES SASL PIPELINING TOP UIDL CAPA AUTH-RESP-CODE
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp   open  imap        Dovecot imapd (Ubuntu)
|_imap-capabilities: listed ID LOGIN-REFERRALS post-login LOGINDISABLEDA0001 more have Pre-login SASL-IR capabilities IDLE OK IMAP4rev1 LITERAL+ ENABLE
445/tcp   open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
31337/tcp open  Elite?
| fingerprint-strings: 
|   GetRequest: 
|_    220 HTB{pr0F7pDv3r510nb4nn3r}
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31337-TCP:V=7.98%I=7%D=2/10%Time=698B6034%P=aarch64-unknown-linux-g
SF:nu%r(GetRequest,1F,"220\x20HTB{pr0F7pDv3r510nb4nn3r}\r\n");
Service Info: Host: NIX-NMAP-DEFAULT; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -20m00s, deviation: 34m38s, median: 0s
| smb2-time: 
|   date: 2026-02-10T16:45:59
|_  start_date: N/A
|_nbstat: NetBIOS name: NIX-NMAP-DEFAUL, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: nix-nmap-default
|   NetBIOS computer name: NIX-NMAP-DEFAULT\x00
|   Domain name: \x00
|   FQDN: nix-nmap-default
|_  System time: 2026-02-10T17:45:59+01:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 171.11 seconds
```

**Discoveries from First Scan:**

| Service | Version | Key Finding |
|---------|---------|-------------|
| **SSH** | OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 | Multiple key types exposed via NSE |
| **HTTP** | Apache httpd 2.4.29 (Ubuntu) | Default Apache page (interesting target for enum) |
| **POP3** | Dovecot pop3d | Email service available (user enumeration possible) |
| **NetBIOS** | Samba smbd 3.X - 4.X | SMB shares may be accessible |
| **IMAP** | Dovecot imapd (Ubuntu) | Email service with capabilities listed |
| **SMB** | Samba smbd 4.7.6-Ubuntu | Guest auth available, message signing disabled |
| **Port 31337** | Elite? (Unknown) | **Banner captured: `HTB{pr0F7pDv3r510nb4nn3r}`** |

**NSE Script Results:**
- SSH key fingerprints captured
- SMB guest authentication confirmed
- Message signing disabled (security concern)
- Clock skew detected (-20 minutes)
- Unknown service on port 31337 (but banner grabbed)

---

### Step 2: HTTP Enumeration with http-enum Script

**Command:**
```bash
sudo nmap 10.129.35.145 -p 80 --script http-enum
```

**Output:**
```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-10 11:17 -0600
Nmap scan report for 10.129.35.145
Host is up (0.044s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|_  /robots.txt: Robots file

Nmap done: 1 IP address (1 http-enum port in 10.48 seconds
```

**Discoveries:**
- **robots.txt found** - Web application enumeration opportunity
- Standard web server enumeration path discovered

---

### Step 3: Manual Enumeration of robots.txt

**Command:**
```bash
curl http://10.129.35.145/robots.txt
```

**Output:**
```
User-agent: *

Allow: /

HTB{873nniuc71bu6usbs1i96as6dsv26}
```

**Discoveries:**
- **robots.txt doesn't restrict any paths** (Allow: /)
- **Second flag captured: `HTB{873nniuc71bu6usbs1i96as6dsv26}`**
- No specific directory restrictions

---

### Enumeration Workflow Summary

**Phase 1: Service Discovery**
- Used `-sV -sC` for comprehensive service version detection
- Identified 7 open ports with version information
- Captured banner from unknown port 31337
- Found first flag in service banner

**Phase 2: Web Application Targeting**
- Used `http-enum` NSE script on port 80
- Discovered robots.txt file (common enumeration point)

**Phase 3: Manual Verification**
- Used curl to access robots.txt directly
- Confirmed web server accessibility
- Captured second flag from web content

### Key Takeaways

✅ **Combine automated and manual enumeration** - NSE scripts find targets, manual review extracts details  
✅ **Don't overlook service banners** - Unrecognized services often contain valuable information  
✅ **Always check common web paths** - robots.txt, /readme.html, /.git, etc.  
✅ **Review NSE script output thoroughly** - Service capabilities reveal attack surfaces  
✅ **Follow up NSE findings with manual tools** - curl, nc, telnet for direct verification  
✅ **Document all discoveries** - Every flag, user, version, and path is valuable  

---

## Next Steps

- [Firewall/IDS Evasion](Firewall_IDS_Evasion.md) - Techniques to bypass network defenses
- [Quick Reference Cheat Sheet](Nmap_Quick_Reference.md) - Commands and syntax reference
