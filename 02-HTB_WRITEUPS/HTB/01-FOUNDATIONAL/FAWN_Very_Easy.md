# FAWN - Very Easy

**Date:** January 23, 2026  
**Difficulty:** Very Easy  
**Time Spent:** 32 minutes  
**Status:** ✅ PWNED

---

## Machine Overview

FAWN is an introductory machine focused on FTP (File Transfer Protocol) enumeration and exploitation. It demonstrates anonymous FTP access, file enumeration, and data exfiltration through basic FTP commands.

---

## Key Concepts Learned

- FTP vs SFTP (secure file transfer)
- Port 21 identification and FTP service detection
- Anonymous FTP access exploitation
- FTP response codes (230 = successful login)
- FTP command help (? command instead of help)
- File exfiltration via FTP get command
- Service version enumeration with nmap -sV

---

## Reconnaissance

### Connection Verification
- Used ping to confirm OpenVPN connection to target
- Connection stable and responsive

### Service Enumeration
```
nmap -sV -p- TARGET_IP
```

**Findings:**
- Port 21: FTP service (vsftpd 3.0.3)
- OS: Unix
- Version detection: Crucial for identifying default behaviors
- Response: Clear FTP banner with version information

---

## Service Information

**FTP (File Transfer Protocol)**
- **Port:** 21
- **Service:** vsftpd (Very Secure FTP Daemon)
- **Version:** 3.0.3
- **Protocol Type:** Unencrypted file transfer
- **Secure Alternative:** SFTP (SSH File Transfer Protocol) on port 22

**Key Difference:**
- FTP: Legacy, unencrypted, credentials visible
- SFTP: Secure wrapper around SSH, encrypted communications

---

## Vulnerabilities Identified

### Vulnerability 1: Anonymous FTP Access Enabled
- **Type:** Authentication Bypass / Information Disclosure
- **Port:** 21
- **Severity:** High
- **Impact:** Unauthenticated file access and exfiltration
- **Discovery Method:** Nmap service detection + FTP banner hints
- **Root Cause:** Anonymous login permitted without credentials
- **Response Code:** 230 (Login successful)

### Vulnerability 2: Sensitive Files in FTP Root
- **Type:** Information Disclosure
- **Finding:** flag.txt stored in FTP-accessible directory
- **Impact:** Direct flag retrieval without authentication

---

## Exploitation Chain

### Phase 1: FTP Connection and Anonymous Access

**Step 1: Connect to FTP Service**
```
ftp TARGET_IP
```

**Step 2: Login with Anonymous Credentials**
```
Username: anonymous
Password: (none/blank)
```

**Response:** 230 (Login successful)

### Phase 2: File Enumeration

**Step 1: List directory contents**
```
ftp> ls
```

**Output:** Directory listing with flag.txt identified

**Note:** Help command in FTP is `?` (not `help`)
```
ftp> ?
```

### Phase 3: File Exfiltration

**Step 1: Download flag file**
```
ftp> get flag.txt
```

**Step 2: Exit FTP server**
```
ftp> quit
```

### Phase 4: Flag Capture

**Step 1: Read exfiltrated file in home terminal**
```
cat flag.txt
```

**Flag Retrieved:** [flag content]

---

## Attack Summary

1. Verified network connectivity with ping
2. Ran nmap -sV to detect FTP service and version
3. Identified vsftpd 3.0.3 on port 21
4. Connected to FTP server
5. Exploited anonymous access (no credentials required)
6. Enumerated files with ls command
7. Exfiltrated flag.txt using get command
8. Retrieved flag with cat command

---

## Key Techniques Used

- **Nmap -sV:** Service version detection
- **Nmap -p-:** Full port range scan (all 65535 ports)
- **FTP Anonymous Access:** Unauthenticated login exploitation
- **FTP ls:** Directory enumeration
- **FTP get:** File exfiltration
- **FTP ? :** Help command (not help!)
- **Cat:** Local file reading

---

## Tools Used

- Ping (network testing)
- Nmap with -sV flag (service version detection)
- FTP client (anonymous access)
- Linux shell commands (cat)

---

## FTP Command Reference

**Common FTP Commands:**
```
?              # Help (use ? not help in this FTP)
ls             # List files
cd             # Change directory
pwd            # Print working directory
get            # Download file
put            # Upload file
binary         # Set binary mode
ascii          # Set ASCII mode
quit           # Exit FTP
```

---

## Lessons Learned

1. **Anonymous FTP is a Real Risk** - Enabled by default on many systems, grants file access
2. **Response Codes Matter** - 230 = successful login, useful for scripting detection
3. **Service Versions are Critical** - vsftpd 3.0.3 has known default behaviors
4. **FTP vs SFTP** - Understand the difference: legacy unencrypted vs secure SSH wrapper
5. **File Exfiltration is Simple** - FTP get + cat = complete data theft
6. **Help Command Varies** - Different services use ? vs help (always try both)

---

## Methodology Confirmation

This machine confirmed the enumeration process for file services:
- Step 1: Reconnaissance ✅ (ping, nmap -sV)
- Step 2: Service Identification ✅ (FTP port 21, vsftpd 3.0.3)
- Step 3: Vulnerability Identification ✅ (anonymous access)
- Step 4: Exploitation ✅ (anonymous login)
- Step 5: File Enumeration ✅ (ls command)
- Step 6: Data Exfiltration ✅ (get flag.txt)
- Step 7: Flag Capture ✅ (cat flag.txt)

---

## Speed Optimization

**What Worked:**
- Nmap -sV immediately revealed service version
- Anonymous hint in FTP banner saved trial-and-error
- Quick file enumeration with ls
- Direct get command for exfiltration

**Time Breakdown:**
- Reconnaissance: 5 minutes (ping, nmap)
- FTP Connection: 2 minutes (connect, authenticate)
- File Enumeration: 3 minutes (ls, identify flag)
- Exfiltration: 2 minutes (get, cat)
- Total: 32 minutes

---

## Comparison to MEOW

| Aspect | MEOW | FAWN |
|--------|------|------|
| Service | Telnet | FTP |
| Port | 23 | 21 |
| Auth | Default password (none) | Anonymous access |
| Time | <20 mins | 32 mins |
| Complexity | Minimal | Slightly increased |
| Technique | Default credentials | Anonymous access + file exfil |

**Key Difference:** FAWN required understanding file transfer protocols vs direct shell access (Telnet)

---

## Notes

Second box complete! Speed is increasing. Key observations:

- Nmap -sV is proving invaluable for service identification
- Anonymous access is a common real-world vulnerability
- FTP protocol fundamentals (commands, response codes) critical for exploitation
- File exfiltration workflow: get → cat on local system
- Pattern emerging: Enum → Identify → Exploit → Extract

**Status:** BOX PWNED ✅

---

## What's Next

- Continue Easy boxes (target 6-8 total)
- Speed should decrease further as patterns become automatic
- Look for boxes combining multiple services
- Start seeing privilege escalation requirements on remaining Easy boxes
