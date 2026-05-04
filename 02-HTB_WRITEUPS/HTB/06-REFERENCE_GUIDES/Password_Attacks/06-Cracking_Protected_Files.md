# 06 — Cracking Protected Files

## Overview

Encrypted and password-protected files are high-value targets during post-exploitation. JtR's `*2john` scripts extract crackable hashes from SSH keys, Office documents, PDFs, archives, and more. The workflow is always: **extract hash → crack with wordlist → access file**.

---

## Hunting for Encrypted Files

### Find Common Document Types

```bash
for ext in $(echo ".xls .xls* .xltx .od* .doc .doc* .pdf .pot .pot* .pp*"); do
  echo -e "\nFile extension: " $ext
  find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core"
done
```

### Find SSH Private Keys

```bash
# Search for private key headers recursively
grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null
```

| Key Format | Header |
|-----------|--------|
| RSA (PEM) | `-----BEGIN RSA PRIVATE KEY-----` |
| OpenSSH | `-----BEGIN OPENSSH PRIVATE KEY-----` |
| Encrypted PEM | Contains `Proc-Type: 4,ENCRYPTED` + `DEK-Info:` |
| Modern encrypted | Looks the same as unencrypted — must test |

### Check if SSH Key is Encrypted

```bash
# If it prompts for passphrase → encrypted
ssh-keygen -yf ~/.ssh/id_rsa

# If it prints the public key directly → not encrypted
ssh-keygen -yf ~/.ssh/id_ed25519
```

---

## Cracking Workflow

### General Pattern

```bash
# 1. Extract hash from protected file
<tool>2john <protected_file> > file.hash

# 2. Crack with wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt file.hash

# 3. View cracked password
john file.hash --show
```

---

## File-Specific Cracking

### SSH Private Keys

```bash
ssh2john.py SSH.private > ssh.hash
john --wordlist=rockyou.txt ssh.hash
john ssh.hash --show
# SSH.private:1234
```

### Microsoft Office Documents

```bash
office2john.py Protected.docx > protected-docx.hash
john --wordlist=rockyou.txt protected-docx.hash
john protected-docx.hash --show
# Protected.docx:1234
```

### PDF Files

```bash
pdf2john.py PDF.pdf > pdf.hash
john --wordlist=rockyou.txt pdf.hash
john pdf.hash --show
# PDF.pdf:1234
```

### Quick Reference: `*2john` Tools

| File Type | Tool | Example |
|-----------|------|---------|
| SSH key | `ssh2john.py` | `ssh2john.py id_rsa > ssh.hash` |
| Office docs | `office2john.py` | `office2john.py file.docx > office.hash` |
| PDF | `pdf2john.py` | `pdf2john.py file.pdf > pdf.hash` |
| ZIP archive | `zip2john` | `zip2john file.zip > zip.hash` |
| RAR archive | `rar2john` | `rar2john file.rar > rar.hash` |
| 7-Zip | `7z2john.pl` | `7z2john.pl file.7z > 7z.hash` |
| KeePass DB | `keepass2john` | `keepass2john file.kdbx > kp.hash` |
| PuTTY key | `putty2john` | `putty2john key.ppk > putty.hash` |
| BitLocker | `bitlocker2john` | `bitlocker2john drive.img > bl.hash` |
| GPG key | `gpg2john` | `gpg2john key.gpg > gpg.hash` |

```bash
# Find all available *2john tools on your system
locate *2john*
```

---

## Encryption Context

| Type | Description | Key Usage |
|------|-------------|-----------|
| **Symmetric** (AES-256) | Same key encrypts and decrypts | File/folder encryption at rest |
| **Asymmetric** (RSA) | Public key encrypts, private key decrypts | File transmission, SSH |

| Regulation | Requirement |
|-----------|-------------|
| GDPR (EU) | Personal data must be encrypted in transit and at rest |

---

## Exercise: Cracking a Protected XLSX

**File**: `cracking-protected-files.zip` → contains `Confidential.xlsx` (password-protected Office 2013)

### Step 1: Extract the ZIP (not encrypted itself)

```bash
unzip cracking-protected-files.zip
# inflating: Confidential.xlsx
```

### Step 2: Extract hash from the Office document

```bash
office2john.py Confidential.xlsx > office.hash
cat office.hash
# Confidential.xlsx:$office$*2013*100000*256*16*cb0e251c...
```

### Step 3: Crack with JtR

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt office.hash
# beethoven        (Confidential.xlsx)
```

### Step 4: Verify

```bash
john office.hash --show
# Confidential.xlsx:beethoven
```

**Answer: `beethoven`**

> **Lesson**: The ZIP wasn't encrypted — always check what's actually protected. `zip2john` returned "not encrypted", so the protection was on the xlsx itself (Office 2013, SHA-512 with 100K iterations).

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **`*2john` → `john` → `--show`** | Extract, crack, display — always the same workflow |
| **Hunt for keys with grep** | `grep -rnE 'BEGIN.*PRIVATE KEY'` finds SSH keys anywhere |
| **`ssh-keygen -yf` to test encryption** | Prompts for passphrase = encrypted |
| **Modern SSH keys look identical** | Can't tell encrypted vs unencrypted from header alone |
| **Office + PDF cracking is trivial** | `office2john.py` / `pdf2john.py` + rockyou handles most |
| **Custom wordlists may be needed** | Standard lists are increasingly blocked or insufficient |
| **Protected files = sensitive data** | Worth cracking — may contain creds for further access |
