# TryHackMe - Authentication Bypass
**Date Completed:** January 2, 2026  
**Difficulty:** Easy-Medium  
**Time Spent:** ~2-3 hours  
**Room Link:** TryHackMe Authentication Bypass

---

## Overview

This room covered various authentication bypass techniques used in web application penetration testing. I learned how to exploit weaknesses in login systems, password reset flows, and session management to gain unauthorized access to user accounts.

---

## Skills Learned

- Username enumeration via error message analysis
- Password brute forcing with multiple wordlists
- Logic flaw exploitation in password reset flows
- Cookie manipulation and session hijacking
- Hash identification and cracking
- Base64 encoding/decoding for cookie tampering

---

## Attack Chain

### Phase 1: Reconnaissance & Username Enumeration

**Objective:** Find valid usernames on the target system

**Method:** Analyzed error messages during signup process
- Invalid usernames returned: "An account with this username already exists"
- Valid usernames returned different response

**Tool Used:** ffuf (Fuzz Faster U Fool)

**Command:**
```bash
ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt \
  -X POST \
  -d "username=FUZZ&email=x&password=x" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u http://10.67.171.173/customer/signup \
  -mr "username already exists"
```

**Results Found:**
- admin
- steve
- simon
- robert

**Key Insight:** Error messages that differ between valid and invalid inputs leak information about what exists in the database.

---

### Phase 2: Password Brute Force

**Objective:** Find password for identified usernames

**Method:** Brute force attack using valid usernames + common password wordlist

**Tool Used:** ffuf with dual wordlists

**Command:**
```bash
ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/xato-net-10-million-passwords-10.txt:W2 \
  -X POST \
  -d "username=W1&password=W2" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u http://10.67.171.173/customers/login \
  -fc 200
```

**Result:**
- **Username:** robert
- **Password:** qwertyuiop (weak password in common wordlist)

**Key Insight:** Many users still use weak, common passwords. Password complexity requirements are critical.

---

### Phase 3: Logic Flaw Exploitation (Password Reset)

**Objective:** Hijack another user's password reset process

**Vulnerability:** Password reset function trusted user-supplied email parameter without validation

**Attack Flow:**
1. Trigger password reset for victim (robert@acmeitsupport.thm)
2. Intercept request and modify POST data to include attacker email
3. Application sends reset link to attacker-controlled email instead of victim's

**Tool Used:** curl

**Command:**
```bash
curl 'http://10.64.133.188/customers/reset?email=robert@acmeitsupport.thm' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=robert&email=attacker@customer.acmeitsupport.thm"
```

**Result:**
- Password reset email sent to `attacker@customer.acmeitsupport.thm`
- Accessed reset link from support ticket system
- Successfully reset robert's password
- **Complete account takeover achieved**

**Key Insight:** Never trust client-supplied data. Server must validate that password reset email matches the account owner's registered email.

---

### Phase 4: Cookie Manipulation

**Objective:** Escalate privileges by modifying session cookies

**Vulnerability:** Application stored sensitive data in client-side cookies without integrity checks

**Techniques Used:**

#### 1. Cookie Tampering
- Identified cookies: `admin=false`, `logged_in=false`
- Modified values: `admin=true`, `logged_in=true`
- Application accepted modified cookies without validation

#### 2. Base64 Decoding/Encoding
- Some cookie values were base64 encoded (NOT encrypted)
- Decoded cookies revealed plaintext values
- Modified values and re-encoded to base64
- Successfully bypassed authentication

**Tools:**
- Browser DevTools (F12 → Application → Cookies)
- base64 command line: `echo "value" | base64`
- CyberChef for encoding/decoding

**Key Insight:** 
- Base64 is encoding, NOT encryption - easily reversible
- Never store sensitive data client-side without cryptographic signing
- Implement proper session management server-side

---

### Phase 5: Hash Cracking

**Objective:** Crack password hashes found in cookies/application

**Method:** Used online hash cracking service

**Tool:** CrackStation (https://crackstation.net/)

**Process:**
1. Identified hash type (MD5, SHA1, etc.)
2. Submitted hash to CrackStation
3. Retrieved plaintext password

**Key Insight:** 
- Weak passwords can be cracked even when hashed
- Rainbow tables make common password hashes trivial to crack
- Always use strong hashing algorithms (bcrypt, Argon2) with salt

---

## Tools & Resources Used

### Tools
- **ffuf** - Web fuzzing and brute forcing
- **curl** - Custom HTTP request crafting
- **Browser DevTools** - Cookie inspection and manipulation
- **CrackStation** - Online hash cracking
- **base64** - Encoding/decoding utility

### Wordlists
- `/usr/share/wordlists/SecLists/Usernames/Names/names.txt`
- `/usr/share/wordlists/SecLists/Passwords/Common-Credentials/xato-net-10-million-passwords-10.txt`
- `/usr/share/wordlists/rockyou.txt` (alternative password list)

### Key File Paths (Kali Linux)
```
/usr/share/wordlists/SecLists/
├── Usernames/
│   └── Names/names.txt
└── Passwords/
    └── Common-Credentials/
        ├── xato-net-10-million-passwords-10.txt
        ├── xato-net-10-million-passwords-100.txt
        └── 10-million-password-list-top-100.txt
```

---

## Technical Challenges Encountered

### 1. Wordlist File Path Issues
**Problem:** Initial confusion about exact wordlist paths in Kali Linux

**Solution:**
```bash
# Find wordlists
ls /usr/share/wordlists/SecLists/Passwords/Common-Credentials/

# Search for specific wordlists
find /usr/share/wordlists -name "*password*" -type f
```

### 2. Terminal Line Wrapping
**Problem:** Long commands caused terminal display issues with overlapping text

**Solutions:**
- Used backslashes for multi-line commands:
```bash
ffuf -w /path/to/wordlist \
  -X POST \
  -d "data=value" \
  -u http://target
```
- Used `reset` command to fix terminal display
- Used `clear` to clean up screen

### 3. ffuf Filter Confusion
**Problem:** Initially used wrong filter flag

**Learning:**
- `-mr` = Match Regexp (SHOW ONLY matches)
- `-fr` = Filter Regexp (HIDE matches)
- `-fc` = Filter HTTP Code (hide specific status codes)
- `-fs` = Filter Size (hide specific response sizes)

---

## Key Vulnerabilities Identified

### 1. Username Enumeration (CWE-200: Information Exposure)
- **CVSS:** Medium
- **Description:** Different error messages reveal valid vs invalid usernames
- **Remediation:** Use generic error message: "Invalid username or password"

### 2. Weak Password Policy (CWE-521)
- **CVSS:** High
- **Description:** System accepts common, weak passwords
- **Remediation:** Enforce strong password requirements, check against common password lists

### 3. Logic Flaw in Password Reset (CWE-640)
- **CVSS:** Critical
- **Description:** Password reset accepts user-supplied email without validation
- **Remediation:** Server-side validation that reset email matches account email

### 4. Insecure Session Management (CWE-384)
- **CVSS:** High
- **Description:** Session data stored client-side without integrity protection
- **Remediation:**
  - Store session data server-side only
  - Use cryptographically signed cookies (HMAC)
  - Implement proper session tokens

### 5. Insufficient Hash Security (CWE-327)
- **CVSS:** Medium
- **Description:** Weak hashing algorithm used for passwords
- **Remediation:** Use bcrypt, scrypt, or Argon2 with proper salt

---

## Lessons Learned

### Technical Lessons
- **Error messages leak information** - Always return generic errors for authentication
- **Never trust client-side data** - Cookies, hidden fields, JavaScript validation can all be manipulated
- **Test every input parameter** - Even seemingly innocuous fields like email in password reset
- **Base64 ≠ Encryption** - Base64 is reversible encoding, not security
- **Hashing alone isn't enough** - Weak passwords can still be cracked from hashes

### Methodology Lessons
- **Enumeration is critical** - Identify valid users before attempting password attacks
- **Use wordlists effectively** - SecLists is comprehensive but need to know file structure
- **Logic flaws > Technical exploits** - Poor business logic often easier to exploit than code vulnerabilities
- **Document as you go** - Taking notes during exploitation helps with writeups
- **Command organization matters** - Multi-line commands with backslashes are much more readable

### Tool Proficiency Gained
- **ffuf** - Comfortable with basic fuzzing, multiple wordlists, filtering
- **curl** - Can craft custom POST requests with headers and data
- **Browser DevTools** - Cookie inspection and modification
- **Linux terminal** - Better at navigation, command structure, troubleshooting

---

**Updated:** January 2, 2026  
**Status:** Completed ✅  
**Portfolio Ready:** Yes
