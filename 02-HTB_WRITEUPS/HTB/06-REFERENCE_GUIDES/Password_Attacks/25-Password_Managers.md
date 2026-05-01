# 🔐 Password Managers

> **Module Section:** 25 / 26 — Password Attacks

## Overview

Per a NordPass study, the **average person has ~100 passwords**. It's unrealistic for anyone to memorize that many complex, unique credentials — which is exactly why users **reuse** and **simplify** passwords, creating attack surface.

A **password manager** is an application that stores passwords and sensitive information in an **encrypted database**, protected by a **master password**.

### Typical Features

- 🔑 Password generation
- 🔐 Two-factor authentication (2FA) support
- ✍️ Secure form filling
- 🌐 Browser integration
- 📱 Multi-device synchronization
- 🚨 Security alerts (breach monitoring)

---

## How Password Managers Work

Encryption and authentication rely on **cryptographic hash functions** and **key derivation functions (KDFs)** to protect the encrypted database.

Implementation varies per vendor and depends on whether the manager is **cloud-based** or **local**.

---

## ☁️ Cloud Password Managers

Sync the encrypted database across devices via a cloud service. Typically provides:

- Mobile app
- Browser extension
- Desktop client

### Zero-Knowledge Encryption

Most reputable cloud managers implement **Zero-Knowledge Encryption** — the vendor **cannot** decrypt your vault even if compelled. Encryption keys are **derived locally** from your master password and never sent to the service.

### Example: Bitwarden Key Derivation

```
Master Password
       │
       ▼  (PBKDF2-SHA256 / Argon2id)
  Master Key
       │
       ├──► Master Password Hash ──► (sent to server for auth)
       │
       ▼
  Stretched Master Key
       │
       ▼  (AES-256)
  Vault Decryption
```

| Artifact | Purpose |
|----------|---------|
| **Master Key** | Derived from master password via a KDF (PBKDF2, Argon2) |
| **Master Password Hash** | Authenticates the user to the cloud service |
| **Decryption Key** | Symmetric key used to decrypt vault items (AES-256) |

> 📖 Bitwarden, 1Password, and LastPass all publish technical whitepapers detailing their crypto design. Read them to understand a manager's security model before trusting it.

### Popular Cloud Managers

| Manager | Notes |
|---------|-------|
| **Bitwarden** | Open-source, self-hostable |
| **1Password** | Uses Secret Key + master password (2 factors in the vault key) |
| **Dashlane** | Focus on UX + dark web monitoring |
| **Keeper** | Enterprise-oriented |
| **LastPass** | ⚠️ Suffered major breaches (2022) — model caution |
| **NordPass** | XChaCha20 encryption |
| **RoboForm** | Long-standing option |

---

## 💻 Local Password Managers

Store the encrypted database **locally** — no cloud component. You are responsible for the database file's security, backup, and sync.

### Key Differences vs Cloud

| Aspect | Cloud | Local |
|--------|-------|-------|
| **Storage** | Encrypted on vendor servers | Encrypted on your disk |
| **Sync** | Built-in | DIY (e.g., Syncthing, Dropbox — adds risk) |
| **Attack surface** | Provider breach risk | Local device compromise risk |
| **Convenience** | High | Lower |
| **Trust required** | In vendor + code | In yourself + backup hygiene |

### Protections Used

- **Strong KDFs** with **random salt** — blocks precomputed keys, slows dictionary attacks
- **Memory protection** — limit unencrypted keys in RAM
- **Keylogger resistance** — secure desktop (like Windows UAC)
- Cryptographic hash functions per vendor

### Popular Local Managers

| Manager | Platforms |
|---------|-----------|
| **KeePass** / **KeePassXC** | Windows, Linux, macOS (KeePassXC is the recommended fork) |
| **KWalletManager** | KDE Linux |
| **Password Safe** | Windows (Schneier-created) |
| **Pleasant Password Server** | Enterprise (KeePass-compatible) |

---

## Feature Comparison Checklist

Use this when selecting a manager:

| Feature | Why It Matters |
|---------|----------------|
| **2FA support** | Second factor on the vault itself |
| **Multi-platform** | Android, iOS, Windows, Linux, macOS, ChromeOS |
| **Browser extension** | Autofill + phishing-resistant URL matching |
| **Login autocomplete** | Usability → adoption |
| **Import / export** | Vendor lock-in avoidance |
| **Password generation** | Built-in strong random |
| **Breach monitoring** | HIBP integration |
| **Emergency access** | Trusted contact recovery |
| **Secure notes / files** | Beyond just passwords |
| **Shared vaults** | Family / team password sharing |

---

## 🔑 Alternatives to Passwords

Passwords are vulnerable to **cracking, guessing, shoulder surfing, phishing, keylogging, reuse**. Modern identity strategies layer alternative factors.

### Additional / Alternative Factors

| Mechanism | Category | Notes |
|-----------|----------|-------|
| **MFA** | Multi-factor | Combines knowledge + possession / inherence |
| **FIDO2 / WebAuthn** | Possession | Hardware keys (YubiKey, Titan) — **phishing-resistant** |
| **OTP** | Possession | One-time codes (usually via token/app) |
| **TOTP** | Possession | Time-based OTP (Google Authenticator, Authy) |
| **Push notifications** | Possession | MFA apps (Duo, Microsoft Authenticator) |
| **IP restrictions** | Contextual | Geo / network fencing |
| **Device compliance** | Contextual | Microsoft Intune, Workspace ONE |

### Factor Categories

| Category | Examples |
|----------|----------|
| **Knowledge** (something you know) | Password, PIN, security questions |
| **Possession** (something you have) | Phone, hardware token, smart card |
| **Inherent** (something you are) | Fingerprint, face, iris |

> ⚠️ **Knowledge factors are the weakest** — they can be stolen, shared, reused, phished. Always layer additional factors.

---

## 🚀 Going Passwordless

Many vendors — **Microsoft**, **Auth0**, **Okta**, **Ping Identity** — are pushing toward eliminating passwords entirely.

### The Concept

Instead of "something you know" (password), authenticate with:

- **Possession factor** — FIDO2 key, phone biometric tied to device
- **Inherent factor** — fingerprint / face with secure enclave

### Benefits

- Eliminates **reuse, phishing, and credential stuffing** attacks
- Removes the cognitive burden on users
- **Phishing-resistant** (especially FIDO2/WebAuthn)

### Reading List

- **Microsoft Passwordless**
- **Auth0 Passwordless**
- **Okta Passwordless**
- **Ping Identity Passwordless**

---

## Decision Matrix — Which Manager?

| Scenario | Recommendation |
|----------|---------------|
| Self-host, open source priority | **Bitwarden** (self-hosted Vaultwarden) |
| Best UX with strong security model | **1Password** |
| No cloud trust at all, highly technical user | **KeePassXC** |
| Enterprise with SSO / SCIM | **1Password Business** or **Keeper Enterprise** |
| Linux + KDE user | **KWalletManager** or **KeePassXC** |
| Everyone else | **Bitwarden** (free tier is generous) |

---

## Red Flags to Avoid

- 🚩 No published whitepaper / crypto design documentation
- 🚩 Vendor that can reset your master password (means they have decryption capability)
- 🚩 No independent security audit
- 🚩 Weak KDF (low PBKDF2 iterations, no Argon2 option)
- 🚩 History of breaches with **poor disclosure** (not just the breach itself)

---

## Key Takeaways

1. **~100 passwords per person** — human memory cannot scale; a manager is mandatory
2. **Master password + KDF** derive encryption keys locally → Zero-Knowledge
3. **Cloud** = convenient multi-device sync; **Local** = full control but sync is DIY
4. **Use a strong, unique master password** (passphrase) + **enable 2FA on the vault**
5. Read the vendor's **whitepaper** before trusting them
6. **Bitwarden / 1Password / KeePassXC** are the dominant safe choices
7. **FIDO2 hardware keys** are phishing-resistant — strongest possession factor
8. **MFA on top of the manager** is non-negotiable
9. **Passwordless** is the industry direction — FIDO2/WebAuthn + biometrics
10. **Knowledge factors alone are insufficient** — always layer possession or inherence

---

## References

- [NIST SP 800-63B — Authenticator Guidance](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)
- [1Password Security Design](https://1passwordstatic.com/files/security/1password-white-paper.pdf)
- [KeePassXC](https://keepassxc.org/)
- [FIDO Alliance](https://fidoalliance.org/)
- [Microsoft Passwordless](https://www.microsoft.com/en-us/security/business/identity-access/azure-active-directory-passwordless-authentication)
- [Computerphile — How Password Managers Work](https://www.youtube.com/watch?v=w68BBPDAWr8)
- [HaveIBeenPwned](https://haveibeenpwned.com/)
