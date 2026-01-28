# Enumeration Process - Systematic Approach

---

## Phase 1: Initial Reconnaissance (Nmap)

### Step 1: Full Port Scan
```
nmap -p- -T4 target > full_port_scan.txt
```

Purpose: Identify ALL open ports
Output: List of open ports to investigate

### Step 2: Service & Version Detection
```
nmap -sV -p [open_ports] target > service_versions.txt
```

Purpose: Identify services and versions
Output: Service names, versions for CVE research

### Step 3: Aggressive Enumeration
```
nmap -A -p [open_ports] target > aggressive_scan.txt
```

Purpose: OS detection, script scanning, traceroute
Output: Comprehensive service info

---

## Phase 2: Service-Specific Enumeration

### Priority 1: Check for EASY WINS (No Credentials Needed)

| Service | Check | Command |
|---------|-------|---------|
| FTP (21) | Anonymous login | `ftp target` then `anonymous` |
| SMB (445) | Null session | `nmap --script=smb-enum-shares -p 445 target` |
| SNMP (161) | Default community | `snmpwalk -c public -v1 target` |
| HTTP (80) | Page title, tech stack | `curl -I target`, `whatweb target` |
| DNS (53) | Zone transfer | `nslookup`, `dig axfr @target domain.com` |

### If Easy Wins Found: Extract & Document
- Credentials discovered
- File listings and sensitive data
- System information
- User accounts
- Configuration files

---

## Phase 3: Deeper Service Enumeration

### If Service Requires Credentials

| When | Then |
|------|------|
| FTP anonymous fails | Try: ftp/ftp, admin/admin, test/test |
| SMB null session fails | Try found credentials from other services |
| SNMP public fails | Try: private, manager, cisco, etc. |
| HTTP accessible | Try: default credentials, common paths |

### NMAP Script Enumeration by Service

**For SMB:**
```
nmap --script=smb-* -p 445 target
```
Scripts run: smb-enum-shares, smb-enum-users, smb-os-discovery, smb-security-mode

**For FTP:**
```
nmap --script=ftp-* -p 21 target
```
Scripts run: ftp-anon, ftp-bounce, ftp-syst

**For SNMP:**
```
nmap --script=snmp-* -p 161 target
```
Scripts run: snmp-sysdescr, snmp-interfaces, snmp-processes

**For HTTP:**
```
nmap --script=http-* -p 80,443 target
```
Scripts run: http-title, http-headers, http-enum

---

## Phase 4: Web Application Enumeration (If HTTP/HTTPS Open)

### Step 1: Identify Web Server & Technology
```
curl -I target
whatweb target
```

### Step 2: Directory & File Discovery
```
gobuster dir -u http://target -w /usr/share/wordlists/common.txt
ffuf -u http://target/FUZZ -w /usr/share/wordlists/common.txt
```

### Step 3: Check for Common Vulnerabilities
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Remote File Inclusion (RFI)
- Local File Inclusion (LFI)
- Authentication bypass
- Command injection

---

## Phase 5: Privilege Escalation Enumeration (After Initial Access)

### On Linux Shell:
```
sudo -l
find / -type f -perm -4000 2>/dev/null
find / -type f -name "*.sh" 2>/dev/null
cat /etc/crontab
```

### On Windows Shell:
```
whoami /priv
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember Administrators
```

---

## Complete Enumeration Checklist

### Initial Access

- [ ] Nmap full port scan completed
- [ ] Service versions identified
- [ ] CVE research started for identified versions
- [ ] FTP anonymous access tested
- [ ] SMB null session tested
- [ ] SNMP public community tested
- [ ] HTTP/HTTPS accessible and analyzed
- [ ] Default credentials attempted

### Information Gathering

- [ ] File listings extracted (FTP/SMB)
- [ ] User accounts enumerated
- [ ] System information gathered (SNMP)
- [ ] Web application tech stack identified
- [ ] Hidden directories found (web)
- [ ] Potential credentials discovered
- [ ] Configuration files reviewed
- [ ] Process lists examined (SNMP)

### Vulnerability Identification

- [ ] Version-specific CVEs identified
- [ ] Misconfigurations found
- [ ] Weak permissions documented
- [ ] Default credentials confirmed
- [ ] Web vulnerabilities tested
- [ ] Lateral movement paths identified
- [ ] Privilege escalation vectors found

### Documentation

- [ ] All findings recorded
- [ ] Attack chain mapped
- [ ] Next steps prioritized
- [ ] Writeup template started

---

## Decision Tree: When to Move to Exploitation

```
Easy Win Found?
├── YES (Anonymous FTP / Null SMB / Default SNMP)
│   └── Extract Data → Exploitation
│
└── NO
    ├── CVE Found for Identified Version?
    │   ├── YES → Research & Prepare Exploit
    │   │   └── Test Exploit
    │   │       └── Exploitation
    │   │
    │   └── NO → Check for Web Vulnerabilities
    │       ├── Web Vuln Found? → Exploitation
    │       │
    │       └── Dead End? → Re-enumerate deeper
    │           ├── Try more shares/directories
    │           ├── Test more default credentials
    │           └── Check for configuration leaks
```

---

## Command Reference by Phase

### Phase 1: Scanning
```
nmap -p- -T4 target
nmap -sV -p [ports] target
nmap -A -p [ports] target
```

### Phase 2: Quick Wins
```
ftp target
nmap --script=smb-enum-shares -p 445 target
snmpwalk -c public -v1 target
```

### Phase 3: Service Enumeration
```
nmap --script=smb-* -p 445 target
smbclient -L //target -N
smbget -R smb://target/share
```

### Phase 4: Web Enumeration
```
whatweb target
gobuster dir -u http://target -w wordlist.txt
curl -I target
```

### Phase 5: Post-Exploitation
```
sudo -l
find / -perm -4000 2>/dev/null
cat /etc/crontab
```

---

## Common Patterns on Easy Machines

Pattern 1: Easy Win
- Anonymous FTP with sensitive data → Credentials found → Use on SSH/SMB

Pattern 2: Version Vulnerability
- Nmap identifies vulnerable version → Search CVE → Exploit version → RCE

Pattern 3: Web Vulnerability
- HTTP open → Directory enumeration → Web app vulnerability → RCE

Pattern 4: Misconfiguration Chain
- SNMP info disclosure → Find process/config → SMB share with configs → Credentials → Lateral movement

---

## How to Document Findings

Create a simple table:

| Service | Port | Status | Findings | Next Step |
|---------|------|--------|----------|-----------|
| FTP | 21 | Open | Anonymous access enabled | Extract files |
| SMB | 445 | Open | Null session failed | Try found creds |
| HTTP | 80 | Open | Apache 2.4.49 | Check CVE-2021-41773 |
| SNMP | 161 | Open | Public works | Extract system info |

---

## Timeline Goal: Easy Machines (6-8 hours each)

- Enumeration: 2-3 hours (thorough reconnaissance)
- Exploitation: 2-3 hours (execute attack)
- Privilege Escalation: 1-2 hours (get root/SYSTEM)
- Documentation: 30 mins (writeup)

Total: 6-8 hours per machine

---

## Start Using This Process Now

1. Pick first HTB Easy machine
2. Run through each phase systematically
3. Document findings in table format
4. Follow decision tree to exploitation
5. Update this checklist as you learn what works

This is your foundation for CPTS success!
