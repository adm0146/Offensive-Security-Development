# 03 — Service Misconfigurations

## Overview

Misconfigurations occur when administrators, developers, or support staff fail to properly secure a service during setup or over time. They represent one of the most common and exploitable attack surfaces in real-world engagements — often granting unauthorized access without needing to exploit any code vulnerability.

> Security Misconfiguration is listed in the **OWASP Top 10**.

---

## The Four Misconfiguration Categories

| Category | Description | Example |
|----------|-------------|---------|
| **Authentication** | Weak, default, or missing credentials | `admin:admin`, blank password |
| **Anonymous Authentication** | Service allows access without any credentials | Anonymous FTP, open SMB share |
| **Misconfigured Access Rights** | Users have more permissions than their role requires | FTP upload user can read all files |
| **Unnecessary Defaults** | Default settings left unchanged after installation | Default ports, services, accounts enabled |

---

## Authentication Misconfigurations

### Default Credentials

Many legacy services ship with hardcoded default credentials. Administrators often leave these unchanged, especially during initial setup.

**Common weak/default combos to try:**
```
admin:admin
admin:password
admin:<blank>
root:12345678
administrator:Password
root:root
admin:1234
```

**Attack workflow:**
1. Banner grab the service to identify the software and version
2. Search for known default credentials for that software
3. If no defaults exist, try weak credential combinations above

**Resources:**
- [DefaultCreds-Cheat-Sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet)
- [CIRT.net default password database](https://www.cirt.net/passwords)

---

## Anonymous Authentication

Some services are configured to accept connections without any credentials — intentionally or by mistake.

| Service | Anonymous Auth Example |
|---------|----------------------|
| **FTP** | `ftp` or `anonymous` as username, blank/any password |
| **SMB** | Null session — connect to share with no credentials |
| **LDAP** | Anonymous bind enabled |
| **NFS** | No_root_squash + world-readable export |
| **Redis** | No `requirepass` set |
| **MongoDB** | No auth enabled (older default) |

**Quick check for anonymous access:**
```bash
# FTP
ftp <target>           # try: anonymous / anonymous@domain

# SMB null session
smbclient -N -L //<target>

# LDAP anonymous bind
ldapsearch -x -H ldap://<target> -b "dc=domain,dc=com"
```

---

## Misconfigured Access Rights

Even with authentication in place, users may be granted excessive permissions.

### Common Examples

| Scenario | Risk |
|----------|------|
| FTP upload user can read all files | Exposure of config files, credentials, PII |
| Dev user has prod DB read access | Data leakage |
| Service account in Domain Admins | Full AD compromise if service is exploited |
| World-readable backup files | Password hashes, config exposure |

### Access Control Models

| Model | Description | Best For |
|-------|-------------|---------|
| **RBAC** (Role-Based Access Control) | Permissions tied to job roles | Large organizations, standardized roles |
| **ACL** (Access Control Lists) | Explicit per-user/resource permissions | Granular control needs |
| **ABAC** (Attribute-Based Access Control) | Permissions based on attributes/context | Dynamic or complex environments |

> **Principle of Least Privilege:** Every account should have only the minimum permissions required to perform its function.

---

## Unnecessary Defaults (OWASP Top 10 — A05)

Default configurations are designed for **usability**, not security. In production environments, defaults must be hardened.

### OWASP-Identified Default Issues

| Default Issue | Risk |
|---------------|------|
| Unnecessary ports/services enabled | Expanded attack surface |
| Default accounts with default passwords | Trivial authentication bypass |
| Verbose error messages / stack traces | Information disclosure |
| Upgraded systems with security features disabled | Known vulnerabilities remain exploitable |

### Common Unnecessary Defaults to Disable

| Component | Default to Remove |
|-----------|-----------------|
| Web servers (Apache/Nginx/IIS) | Default pages, directory listing, server version headers |
| Databases | Default `sa`/`root` accounts, sample databases |
| Network devices | Default SNMP community strings (`public`/`private`) |
| Applications | Admin interfaces accessible from the internet |
| OS | Guest accounts, unnecessary services, debug ports |

---

## Preventing Misconfigurations

### OWASP Hardening Recommendations

| Practice | Description |
|----------|-------------|
| **Repeatable hardening process** | Automate secure baseline deployment across dev/QA/prod |
| **Minimal platform** | Remove unused features, components, docs, sample configs |
| **Patch management integration** | Review configs as part of every update cycle |
| **Segmented architecture** | Isolate components via segmentation, containers, or cloud security groups |
| **Security headers** | Send security directives to clients (CSP, HSTS, X-Frame-Options) |
| **Automated verification** | Continuously test that configurations remain compliant |

### Operational Lockdown Checklist

| Action | Purpose |
|--------|---------|
| Disable admin interfaces | Reduce remote management exposure |
| Turn off debugging | Prevent information leakage |
| Disable default credentials | Eliminate trivial auth bypass |
| Restrict directory listing | Prevent file enumeration |
| Run regular scans/audits | Catch drift and new misconfigurations |
| Use different credentials per environment | Prevent dev creds from working in prod |

---

## From an Attacker's Perspective

| Recon Step | What to Look For |
|------------|-----------------|
| Service banner grabbing | Software name + version → search for default creds |
| Anonymous access testing | Try unauthenticated connections to all services |
| Permission auditing | Check if low-privilege accounts can access sensitive paths |
| Default config search | Google `"<software> default credentials"` or `"<software> default config"` |

---

## Key Takeaways

| Concept | Takeaway |
|---------|----------|
| Misconfigs are everywhere | Often easier to exploit than code vulnerabilities |
| Default creds are still common | Always test them — especially on older or internal software |
| Anonymous auth is often overlooked | Services like FTP, SMB, LDAP allow it by default |
| Excessive permissions compound impact | A misconfigured account + a foothold = escalated access |
| OWASP A05 | Security Misconfiguration is a top-10 risk — patch, harden, automate |
