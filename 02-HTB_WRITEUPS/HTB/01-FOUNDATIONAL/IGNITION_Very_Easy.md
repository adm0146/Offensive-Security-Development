# IGNITION - Very Easy

**Date Started:** February 3, 2026  
**Difficulty:** Very Easy  
**Status:** ✅ COMPLETE

---

## Phase 1: Initial Reconnaissance

### Step 1: Initial Service Enumeration Scan

**Command:**
```bash
nmap -sV -sC TARGET_IP
```

**Explanation:**
- `-sV`: Service version enumeration
- `-sC`: Run default NSE scripts for vulnerability detection

**Scan Results:**

| Port | Service | Version | Status |
|------|---------|---------|--------|
| 80 | HTTP | nginx/1.14.2 | Open |

**Key Findings:**
- Web server nginx version 1.14.2 running on port 80
- HTTP header reveals: `http-title: Did not follow redirect to http://ignition.htb/`
- **Important:** The page attempts a redirect to `ignition.htb` domain (not just IP)

---

## Phase 2: Host Configuration & Web Access

### Step 1: Identify Domain Requirement

**Finding:** Browser shows "This site can't be reached" when visiting `ignition.htb` directly

**Root Cause:** Domain name `ignition.htb` is not in the local hosts file. The web server is configured to respond only to this specific domain name.

### Step 2: Add Domain to /etc/hosts

**Command:**
```bash
echo "TARGET_IP ignition.htb" | sudo tee -a /etc/hosts
```

**Explanation:**
- `echo`: Print text
- `sudo tee -a`: Append to file with elevated privileges
- File location: `/etc/hosts` (local DNS resolution for testing)
- This allows the local system to resolve `ignition.htb` to the target IP

**Result:** Domain now resolves to target IP, browser can access the site

### Step 3: Access Web Application

**Action:** Navigate to `http://ignition.htb/` in browser

**Response:** LUMA e-commerce application homepage

**Technology Identified:** Magento (popular e-commerce platform)

---

## Phase 3: Directory Enumeration

### Step 1: Enumerate Web Directories with Gobuster

**Command:**
```bash
gobuster dir --url http://ignition.htb/ --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

**Explanation:**
- `gobuster dir`: Directory/file enumeration mode
- `--url`: Target URL
- `--wordlist`: Dictionary file containing common directory names (small list for quick scan)

**Results:**

| Directory | Status | Notes |
|-----------|--------|-------|
| / | 200 | Homepage |
| /admin | 200 | **Magento admin login panel** |

**Finding:** Admin panel discovered at `/admin`

---

## Phase 4: Credential Discovery & Access

### Step 1: Access Admin Login Panel

**Action:** Navigate to `http://ignition.htb/admin`

**Response:** Magento administration login prompt

### Step 2: Test Default/Common Credentials

**Strategy:** Magento installations often use weak default credentials. Tested common username/password combinations.

**Common Credentials Tested:**
- admin / admin
- admin / password
- admin / 123456
- admin / qwerty123 ✅ **SUCCESS**

**Valid Credentials Found:**
- **Username:** `admin`
- **Password:** `qwerty123`

### Step 3: Gain Admin Access

**Action:** Login with credentials `admin:qwerty123`

**Result:** ✅ Successfully authenticated to Magento admin dashboard

**Access Level:** Full administrative access to Magento installation

---

## Key Findings

| Item | Details |
|------|---------|
| **Application** | Magento e-commerce platform |
| **Vulnerability Type** | Weak credentials / Default password |
| **Attack Vector** | Admin login form |
| **Credential Source** | Common weak passwords (top 10 most used) |
| **Root Cause** | Administrator failed to change default/weak credentials |
| **Privilege Level** | Full admin access |

### Exploitation Chain Summary

1. **Reconnaissance** → Identify nginx web server and domain requirement
2. **Host Configuration** → Add domain to /etc/hosts for local DNS resolution
3. **Directory Enumeration** → Find `/admin` directory with Gobuster
4. **Credential Testing** → Attempt common Magento credentials
5. **Successful Login** → Gain admin access with `admin:qwerty123`
6. **Box Complete** → Administrative dashboard accessible

### Security Issues Identified

- **Weak Password Policy:** Default/weak credentials not changed during installation
- **No Account Lockout:** No attempt limiting visible on login form
- **No Brute Force Protection:** Repeated failed attempts not blocked
- **Standard Paths:** Admin panel at predictable `/admin` path (industry standard but enumerable)

### Defensive Recommendations

- **Strong Passwords:** Enforce complex password requirements (length, character types)
- **Change Defaults:** Always change default credentials immediately after installation
- **Account Lockout Policy:** Implement lockout after N failed attempts
- **Rate Limiting:** Limit login attempts per IP/user to prevent brute force
- **Security Monitoring:** Log and alert on failed login attempts
- **Multi-Factor Authentication:** Implement MFA for admin accounts
- **Web Application Firewall:** Deploy WAF to detect common attack patterns

---

**Status:** ✅ ADMIN ACCESS ACHIEVED

