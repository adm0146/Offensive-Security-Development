# 04 — Finding Sensitive Information

## Overview

Attacking services requires a detective mindset — every piece of information collected, no matter how small, can be the thread that unravels the entire target. A username found in an anonymous FTP share may unlock email access, which may contain database credentials, which leads to RCE. **No detail is insignificant.**

---

## The Two Requirements

| Requirement | Why It Matters |
|-------------|----------------|
| **Understand the service and how it works** | Knowing what data a service stores/exposes tells you where to look |
| **Know what you are looking for** | Target-specific context determines what information is "sensitive" |

---

## Types of Sensitive Information

| Category | Examples |
|----------|---------|
| **Credentials** | Usernames, passwords, API keys, tokens |
| **Identity** | Email addresses, PII (names, SSNs, DOBs) |
| **Infrastructure** | IP addresses, DNS records, hostnames, network topology |
| **Code & Config** | Source code, configuration files, connection strings |
| **Business Data** | Proprietary information, client data, internal documents |

---

## Services to Target for Sensitive Information

| Service | What to Hunt For |
|---------|-----------------|
| **File Shares (SMB/FTP/NFS)** | Config files, credential files, backup files, scripts, docs |
| **Email** | Password reset threads, shared credentials, internal comms |
| **Databases** | User tables, stored credentials, connection strings, notes |

---

## The Detective Methodology

### Step 1 — Enumerate Everything
Don't assume any service is empty or irrelevant. Try:
- Anonymous/unauthenticated access first
- Default credentials if anonymous fails
- Note all filenames, usernames, addresses, and identifiers found

### Step 2 — Correlate Findings Across Services
Information from one service often unlocks another:

```
FTP (anonymous) → filename "johnsmith"
         ↓
Email login → johnsmith:johnsmith (credential reuse)
         ↓
Email contents → search "password" → MSSQL credentials
         ↓
MSSQL → xp_cmdshell → RCE
```

### Step 3 — Understand the Target's Context
Ask:
- What does this organization do?
- What data would be most sensitive to them?
- What services are critical to their operations?
- Who are the key users/admins?

---

## What to Search For (Quick Reference)

### Filename/Path Keywords
```
*cred*, *password*, *pass*, *secret*, *key*, *token*
*config*, *backup*, *.bak, *.conf, *.env, *.xml, *.ini
*users*, *accounts*, *admin*, *.sql, *.db
```

### Content Search Keywords
```
password, passwd, credentials, secret, token, apikey
username, user=, login, auth, connectionstring
BEGIN RSA, BEGIN OPENSSH, BEGIN PGP
```

---

## Key Takeaways

| Concept | Takeaway |
|---------|----------|
| Every detail matters | A filename, address, or partial string can unlock further access |
| Chain discoveries | Use info from one service to attack the next |
| Context drives prioritization | Understand the target before deciding what's valuable |
| Three primary targets | File shares, email, and databases are the richest sources |
| Anonymous access is the starting point | Always test before attempting credentials |
