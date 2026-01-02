# Offensive Security Quick Reference Guide

## Critical Acronyms for OSCP

### Encryption & Cryptography
- **AES** - Advanced Encryption Standard (symmetric, use this)
- **RSA** - Asymmetric encryption (slow, for key exchange)
- **ECC** - Elliptic Curve Cryptography (faster asymmetric)
- **TLS/SSL** - Secure protocols (HTTPS uses TLS)
- **SHA** - Secure Hash Algorithm (SHA-256 standard)
- **HMAC** - Hash-based Message Authentication Code
- **PKI** - Public Key Infrastructure
- **CA** - Certificate Authority
- **CRL** - Certificate Revocation List
- **OCSP** - Online Certificate Status Protocol

### Authentication & Access Control
- **MFA/2FA** - Multi/Two-Factor Authentication
- **TOTP** - Time-based One-Time Password
- **SSO** - Single Sign-On
- **SAML** - Security Assertion Markup Language
- **OAuth** - Open Authorization (3rd-party access)
- **LDAP** - Lightweight Directory Access Protocol
- **Kerberos** - Network authentication (Windows domains)
- **RADIUS** - Remote Authentication Dial-In User Service
- **TACACS+** - Terminal Access Controller Access Control System
- **RBAC** - Role-Based Access Control
- **ABAC** - Attribute-Based Access Control
- **DAC** - Discretionary Access Control
- **MAC** - Mandatory Access Control

### Network & Protocols
- **TCP** - Transmission Control Protocol (reliable, ordered)
- **UDP** - User Datagram Protocol (fast, unreliable)
- **DHCP** - Dynamic Host Configuration Protocol (assigns IPs)
- **DNS** - Domain Name System (domain → IP)
- **SSH** - Secure Shell (port 22, encrypted remote access)
- **HTTPS** - HyperText Transfer Protocol Secure (port 443)
- **FTP/SFTP/FTPS** - File Transfer Protocol (21, encrypted versions)
- **VPN** - Virtual Private Network
- **IPSec** - IP Security (VPN protocol)
- **IKEv2** - Internet Key Exchange v2
- **ARP** - Address Resolution Protocol (IP → MAC mapping)
- **SNMP** - Simple Network Management Protocol

### Security Tools & Detection
- **IDS** - Intrusion Detection System (alerts on attacks)
- **IPS** - Intrusion Prevention System (blocks attacks)
- **WAF** - Web Application Firewall
- **DLP** - Data Loss Prevention
- **SIEM** - Security Information & Event Management (log aggregation)
- **NAC** - Network Access Control
- **EDR** - Endpoint Detection & Response
- **CASB** - Cloud Access Security Broker
- **MDM** - Mobile Device Management

### Vulnerabilities & Attacks
- **CVE** - Common Vulnerabilities and Exposures
- **CVSS** - Common Vulnerability Scoring System
- **OWASP** - Open Web Application Security Project
- **SQL** - Structured Query Language (SQL injection)
- **XSS** - Cross-Site Scripting
- **CSRF** - Cross-Site Request Forgery
- **XXE** - XML External Entity
- **SSRF** - Server-Side Request Forgery
- **RCE** - Remote Code Execution (worst case)
- **LPE/PE** - Local/Privilege Escalation
- **MITM** - Man-in-the-Middle attack
- **DoS/DDoS** - Denial of Service / Distributed
- **APT** - Advanced Persistent Threat
- **Zero-day** - Unpatched vulnerability

### Cloud & Infrastructure
- **IaaS/PaaS/SaaS** - Infrastructure/Platform/Software as a Service
- **VPC** - Virtual Private Cloud
- **VM** - Virtual Machine
- **DMZ** - Demilitarized Zone

### Compliance
- **GDPR** - EU General Data Protection Regulation
- **HIPAA** - Healthcare privacy law
- **PCI-DSS** - Payment Card Industry standard
- **NIST** - National Institute of Standards & Technology

---

## Essential Network Ports

| Port | Protocol | Service | Security Note |
|------|----------|---------|---------------|
| 21 | FTP | File Transfer | Unencrypted, use SFTP |
| 22 | SSH | Secure Shell | Encrypted remote access |
| 23 | Telnet | Remote Access | NEVER USE - unencrypted |
| 25 | SMTP | Email Send | Often filtered |
| 53 | DNS | Name Resolution | TCP & UDP |
| 67/68 | DHCP | IP Assignment | UDP only |
| 80 | HTTP | Web | Unencrypted |
| 110 | POP3 | Email Retrieval | Old, use IMAP |
| 143 | IMAP | Email Retrieval | Better than POP3 |
| 443 | HTTPS | Web Secure | Encrypted |
| 445 | SMB | Windows Sharing | Vulnerability vector |
| 3306 | MySQL | Database | Expose carefully |
| 3389 | RDP | Remote Desktop | Windows remote access |
| 5900 | VNC | Remote Desktop | Cross-platform |

---

## Cryptography Quick Reference

### When to Use

| Scenario | Use |
|----------|-----|
| Encrypt bulk data | AES (symmetric) |
| Key exchange | RSA or ECDH (asymmetric) |
| Digital signatures | RSA or ECDSA |
| Hash for integrity | SHA-256 |
| Password hashing | bcrypt or PBKDF2 |
| Message authentication | HMAC-SHA256 |

### Key Sizes

| Algorithm | Key Size | Notes |
|-----------|----------|-------|
| AES | 128/192/256 bits | 256-bit for maximum security |
| RSA | 2048/4096 bits | 2048 minimum, 4096 recommended |
| ECC | 256/384/521 bits | 256-bit ECC ≈ 3072-bit RSA |
| SHA-256 | N/A | 256-bit hash output |

---

## OSI Layers & Attacks

| Layer | Name | Examples | Attacks |
|-------|------|----------|---------|
| 2 | Data Link | Frames, MAC addresses | ARP poisoning, MAC flooding |
| 3 | Network | IP addresses, routing | IP spoofing, ICMP redirect |
| 4 | Transport | TCP, UDP, ports | SYN flood, UDP flood |
| 5-7 | Application | HTTP, FTP, DNS, SMTP | SQL injection, XSS, command injection |

---

## Authentication Methods Comparison

| Method | Security | Convenience | Use Case |
|--------|----------|-------------|----------|
| Password only | Low | High | Legacy systems |
| Password + TOTP | Medium | Medium | Online accounts |
| Password + U2F | High | Medium | High-security accounts |
| Biometric | High | High | Mobile devices |
| Certificate | High | Low | Enterprise, APIs |

---

## OSCP Exam Mindset

✓ **Read questions carefully** - One word changes everything
✓ **Know your acronyms** - Half the battle is understanding the question
✓ **Practice exploitation** - Theory + hands-on practice
✓ **Document everything** - Writeups force deep understanding
✓ **Focus on techniques, not just tools** - Tools change, techniques persist
✓ **Test your exploits** - Verify every step works
✓ **Master the fundamentals** - Linux, networking, web apps
✓ **Think like attacker** - How would you compromise this system?

---

**Last Updated:** January 2, 2026
**Status:** In Active Use
