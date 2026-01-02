# Security+ Foundations - Complete Study Notes

## Overview
These notes cover Security+ SY0-701 Domains 1-6 with comprehensive coverage of:
- Threats, vulnerabilities, and risks
- Architecture and design
- Implementation
- Operations and incident response
- Governance, risk, and compliance

This foundational knowledge is essential for OSCP preparation.

---

## Domain 1: General Security Concepts

### 1.2 Security Concepts

#### CIA Triad
- **Confidentiality**: Only authorized users access data (encryption, access controls)
- **Integrity**: Data is accurate, complete, not modified by unauthorized parties (hashing, digital signatures, MAC)
- **Availability**: Systems and data accessible when needed (redundancy, backups, DDoS protection)

#### AAA Model
- **Authentication**: Verify identity (who are you?)
  - Username/password, biometrics, certificates, tokens
- **Authorization**: Grant access based on identity (what can you do?)
  - RBAC, ABAC, permissions lists
- **Accounting**: Log and track user actions (audit trail)
  - Syslog, SIEM, audit logs

#### Non-Repudiation
- **Principle**: User cannot deny taking an action
- **Implementation**: Digital signatures, timestamps, audit logs
- **Example**: Email signed with private key proves sender

#### Gap Analysis
- Identify differences between current state and desired security posture
- Assess vulnerabilities and missing controls
- Prioritize remediation efforts

#### Zero Trust Architecture
- **Principle**: Never trust, always verify
- **Approach**: Assume breach, verify every access attempt
- **Implementation**: MFA, microsegmentation, least privilege
- **Benefits**: Reduces attack surface, faster breach detection

#### Physical Security
- **Access controls**: Badge readers, keypads, biometrics
- **Surveillance**: CCTV, motion sensors
- **Environmental**: Fire suppression, temperature control, humidity control
- **Data destruction**: Shredders, incinerators, degaussing

---

### 1.3 Change Management

#### Change Approval Process
1. **Request**: Propose change with business justification
2. **Impact Analysis**: Assess risk, dependencies, affected systems
3. **Approval**: CAB (Change Advisory Board) review and sign-off
4. **Testing**: Sandbox/test environment validation
5. **Implementation**: Execute in maintenance window
6. **Documentation**: Update runbooks, configurations

#### Key Stakeholders
- **Change Manager**: Oversee process
- **CAB**: Review and approve changes
- **System Owner**: Responsible for system
- **Operations**: Execute the change
- **Security**: Assess security impact

#### Maintenance Windows
- **Definition**: Scheduled downtime for changes/updates
- **Planning**: Outside business hours (nights, weekends)
- **Communication**: Notify users in advance
- **Rollback Plan**: Prepared if change fails

#### Backout Plans
- **Purpose**: Return to previous state if change breaks system
- **Testing**: Verify backout procedure works
- **Documentation**: Clear steps to reverse change
- **Communication**: Notify stakeholders if backout needed

#### Testing
- **Sandbox**: Isolated environment matching production
- **UAT**: User Acceptance Testing
- **Regression Testing**: Ensure existing functionality still works
- **Performance Testing**: Check system performance with changes

#### Documentation & Version Control
- **Change Logs**: Track what changed, when, why
- **Version Control**: Git/GitHub for code and configs
- **Runbooks**: Standard procedures for system operation
- **Dependencies**: Document system relationships

---

### 1.4 Cryptographic Solutions

#### Symmetric Encryption
- **Definition**: Single key encrypts and decrypts
- **Speed**: Fast (good for bulk data)
- **Key Management**: Challenge - must securely share secret key
- **Algorithm Examples**: AES, DES (outdated), 3DES (outdated)

#### Asymmetric Encryption
- **Definition**: Public key encrypts, private key decrypts
- **Speed**: Slow (used for key exchange, not bulk data)
- **Key Management**: Easy - public key is public, private key is secret
- **Algorithm Examples**: RSA, ECC
- **Use Cases**: 
  - Public key encryption (encrypt for recipient)
  - Digital signatures (sign with private key)
  - Key exchange (share symmetric keys)

#### Public Key Infrastructure (PKI)
- **Components**:
  - **CA (Certificate Authority)**: Issues digital certificates
  - **RA (Registration Authority)**: Verifies identities
  - **CRL (Certificate Revocation List)**: List of revoked certificates
  - **OCSP (Online Certificate Status Protocol)**: Real-time cert status check
- **Digital Certificates**: Contain public key, subject info, CA signature
- **Certificate Chain**: Root CA → Intermediate CA → End entity certificate

#### Key Exchange
- **Purpose**: Securely share symmetric encryption key over untrusted channel
- **Methods**:
  - **Diffie-Hellman**: Two parties derive shared secret
  - **RSA Key Exchange**: Encrypt symmetric key with public key
  - **ECDH (Elliptic Curve Diffie-Hellman)**: Modern, efficient version

#### Key Management
- **Key Generation**: Create cryptographically strong keys
- **Key Storage**: Secure storage (HSM, TPM)
- **Key Rotation**: Regularly change keys (annually, quarterly)
- **Key Escrow**: Third party holds copy of key (government requirement, risky)
- **Key Stretching**: Derive strong key from password (PBKDF2, bcrypt)

#### Hashing
- **Purpose**: Create fixed-size fingerprint of data
- **One-way**: Cannot reverse (cannot decrypt)
- **Deterministic**: Same input = same output
- **Collision-resistant**: Two different inputs shouldn't produce same hash
- **Algorithms**: 
  - SHA-256 (good, modern)
  - MD5 (broken, don't use)
  - SHA-1 (deprecated, don't use)

#### HMAC (Hash-based Message Authentication Code)
- **Purpose**: Verify integrity AND authenticate sender
- **Components**: Hash + secret key
- **Use Case**: Secure APIs, message authentication
- **Algorithm**: HMAC-SHA256 (good choice)

#### Session Keys
- **Purpose**: Temporary key for single communication session
- **Lifecycle**: Generated at session start, discarded at end
- **Example**: HTTPS TLS session key
- **Benefits**: Limits damage if key is compromised

#### Encryption in Transit vs At Rest
- **In Transit**: Data moving over network (TLS, VPN)
- **At Rest**: Data stored on disk (file encryption, database encryption)
- **Both Required**: Defense in depth

#### TPM (Trusted Platform Module)
- **Purpose**: Hardware security module on motherboard
- **Functions**: 
  - Secure key storage
  - Random number generation
  - Secure boot
  - Measured boot
- **Use Case**: Prevent unauthorized OS modifications

#### HSM (Hardware Security Module)
- **Purpose**: Physical device for cryptographic operations
- **Benefits**: 
  - High-security key storage
  - Offload crypto operations
  - Tamper-resistant
- **Use Case**: CA servers, banks, high-security environments

---

## Key Takeaways for OSCP

1. **Understand cryptographic fundamentals**: Symmetric vs asymmetric, hashing, key exchange
2. **Know PKI**: Certificates, CAs, certificate validation
3. **Authentication methods**: Know MFA types, Kerberos, SAML
4. **Access control models**: RBAC, ABAC, DAC, MAC
5. **Change management**: Why it matters for stability
6. **Physical security**: Understand the complete security picture

---

## Study Tips

- Focus on **practical application** - how would you implement these?
- Understand **why** each concept exists, not just what it is
- Practice identifying real-world scenarios for each control
- Review acronyms frequently
- Explain concepts to someone else - best way to cement understanding
