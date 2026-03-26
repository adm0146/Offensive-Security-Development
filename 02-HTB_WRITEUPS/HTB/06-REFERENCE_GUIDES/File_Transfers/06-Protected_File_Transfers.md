# 06 — Protected File Transfers

## Overview

During penetration tests, we frequently handle sensitive data — credentials, NTDS.dit files, enumeration results containing AD infrastructure details. **Encrypting data before transfer is mandatory** to prevent interception and data leakage.

> ⚠️ **Professional Responsibility:** Never exfiltrate real PII, financial data, or trade secrets. When testing DLP/egress controls, create **dummy data files** that mimic the protected data format.

> Data leakage during an engagement can have severe legal and professional consequences for you, your company, and your client.

---

## Windows — AES Encryption with PowerShell

Uses the `Invoke-AESEncryption.ps1` script for AES-256-CBC encryption of files and strings.

### Setup

```powershell
# Transfer script to target, then import
Import-Module .\Invoke-AESEncryption.ps1
```

### Encrypt a String

```powershell
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Text "Secret Text"
# Output: Base64 encoded ciphertext
```

### Decrypt a String

```powershell
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Text "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs="
# Output: plain text
```

### Encrypt a File

```powershell
Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt
# Output: scan-results.txt.aes
```

### Decrypt a File

```powershell
Invoke-AESEncryption -Mode Decrypt -Key "p4ssw0rd" -Path .\scan-results.txt.aes
# Output: scan-results.txt
```

> 💡 The script uses SHA-256 to derive the AES key from your password, CBC mode, zero-padding, 128-bit blocks, 256-bit key size. The IV is prepended to the ciphertext.

---

## How the Script Works (Under the Hood)

| Component | Detail |
|-----------|--------|
| **Key Derivation** | SHA-256 hash of password string |
| **Cipher** | AES-256-CBC |
| **Padding** | Zeros |
| **IV Handling** | Encrypt: IV prepended to ciphertext. Decrypt: first 16 bytes extracted as IV |
| **String Output** | Base64 encoded |
| **File Output** | `.aes` extension appended, preserves original LastWriteTime |

---

## Linux — OpenSSL Encryption

OpenSSL is pre-installed on most Linux distributions and supports many ciphers.

### Encrypt a File

```bash
openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc
# Prompts for password twice (enter + verify)
```

### Decrypt a File

```bash
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd
# Prompts for decryption password
```

### Key Flags

| Flag | Purpose |
|------|---------|
| `-aes256` | Cipher selection (AES-256-CBC) |
| `-iter 100000` | Override default iteration count (brute-force resistance) |
| `-pbkdf2` | Use PBKDF2 key derivation (stronger than default) |
| `-d` | Decrypt mode |
| `-in FILE` | Input file |
| `-out FILE` | Output file |

> Run `openssl enc -list` to see all available ciphers.

---

## Operational Best Practices

| Practice | Why |
|----------|-----|
| **Unique password per engagement** | Prevents one leaked password from compromising multiple clients' data |
| **Strong passwords** | Resists brute-force if encrypted file is intercepted |
| **Encrypt BEFORE transfer** | Data is protected even if transport is unencrypted |
| **Combine with secure transport** | Use HTTPS, SFTP, or SSH when possible — encryption is defense-in-depth |
| **Delete sensitive files after use** | Minimize exposure window on both attack host and target |
| **Use dummy data for DLP testing** | Never exfiltrate real sensitive data unless explicitly authorized |

---

## Quick Reference: When to Use What

| Scenario | Tool | Command |
|----------|------|---------|
| Encrypt file on Windows | PowerShell AES | `Invoke-AESEncryption -Mode Encrypt -Key "pass" -Path .\file.txt` |
| Encrypt file on Linux | OpenSSL | `openssl enc -aes256 -iter 100000 -pbkdf2 -in file -out file.enc` |
| Encrypt string for transfer | PowerShell AES | `Invoke-AESEncryption -Mode Encrypt -Key "pass" -Text "data"` |
| Transfer after encryption | Any method | Netcat, HTTP, SMB, SCP — data is already protected |
