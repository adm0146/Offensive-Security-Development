# 10 — Windows Authentication Process

## Overview

Understanding how Windows authenticates users is critical for knowing **where credentials are stored** and **how to extract them**. The process involves multiple components: WinLogon, LSASS, SAM, credential providers, and authentication packages.

---

## Authentication Flow

```
User Input → LogonUI → Credential Provider → WinLogon → LSASS → Auth Package → SAM / AD (ntds.dit)
```

| Step | Component | Role |
|------|-----------|------|
| 1 | **WinLogon** (`winlogon.exe`) | Trusted process that manages security-related user interactions (login, lock, password change) |
| 2 | **LogonUI** | Graphical interface for credential input |
| 3 | **Credential Providers** | COM objects (DLLs) that collect credentials |
| 4 | **LSASS** (`lsass.exe`) | Authenticates users, enforces security policy, generates audit logs |
| 5 | **Auth Package** | DLL that performs the actual authentication check (NTLM or Kerberos) |
| 6 | **SAM / AD** | Validates credentials against stored hashes |

---

## LSASS (Local Security Authority Subsystem Service)

- Located at `%SystemRoot%\System32\Lsass.exe`
- Central gatekeeper for all authentication in Windows
- Enforces local security policy, authenticates users, sends audit logs to Event Log

### Authentication Packages (DLLs loaded by LSASS)

| Package | Description |
|---------|-------------|
| `Lsasrv.dll` | LSA Server service — enforces security policies, selects NTLM or Kerberos via Negotiate function |
| `Msv1_0.dll` | Handles local machine logons (non-domain, interactive) |
| `Samsrv.dll` | SAM service — stores local accounts, enforces local policies, supports APIs |
| `Kerberos.dll` | Kerberos-based authentication |
| `Netlogon.dll` | Network-based logon service |
| `Ntdsa.dll` | Directory System Agent — manages `ntds.dit`, handles LDAP queries and DC replication (**Domain Controllers only**) |

---

## SAM Database (Security Account Manager)

- Stores **local** user account credentials as password hashes (LM or NTLM)
- File location: `%SystemRoot%\system32\config\SAM`
- Registry mount: `HKLM\SAM`
- Requires **SYSTEM level privileges** to view/access
- **SYSKEY** (since NT 4.0): partially encrypts the SAM on disk so password hashes are encrypted with a system key

### Workgroup vs. Domain

| Setup | Credential Storage |
|-------|-------------------|
| **Workgroup** | SAM database (local) |
| **Domain-joined** | Domain Controller validates against `ntds.dit` (Active Directory) |

---

## Credential Manager

- Built-in Windows feature for storing credentials (network resources, websites, apps)
- Stored **per user profile** in the Credential Locker
- Encrypted and saved at:

```
C:\Users\<Username>\AppData\Local\Microsoft\Vault\
C:\Users\<Username>\AppData\Local\Microsoft\Credentials\
```

- Various methods exist to decrypt saved credentials (covered in later sections)

---

## NTDS.dit (Active Directory Database)

- Present on **Domain Controllers** only
- Synchronized across all DCs (except Read-Only DCs / RODCs)
- Stores:
  - User accounts (username + password hash)
  - Group accounts
  - Computer accounts
  - Group Policy Objects (GPOs)
- Location: `%SystemRoot%\ntds.dit`

---

## Key Credential Storage Locations

| Location | Scope | Contains |
|----------|-------|----------|
| `SAM` (`%SystemRoot%\system32\config\SAM`) | Local accounts | LM/NTLM password hashes |
| `NTDS.dit` (`%SystemRoot%\ntds.dit`) | Domain accounts | All AD data including password hashes |
| `LSASS` memory (`lsass.exe`) | Active sessions | Cached credentials, Kerberos tickets |
| Credential Manager (`AppData\Local\Microsoft\Vault\`) | Per-user | Saved network/web credentials |
| `HKLM\SAM` | Local registry | SAM database (encrypted) |

---

## Key Takeaways

- **LSASS** is the central authentication authority — dumping its memory is a primary credential extraction technique
- **SAM** holds local account hashes, requires SYSTEM access, and is partially encrypted by SYSKEY
- **NTDS.dit** holds all domain account data — extracting it gives you every hash in the domain
- **Credential Manager** stores saved creds per-user — can be decrypted with the right access
- WinLogon is the only process that intercepts keyboard login requests (via RPC from `Win32k.sys`)
- Domain-joined machines validate creds against the DC; workgroup machines validate locally against SAM
- Understanding this flow tells you **what to target**: LSASS memory, SAM file, NTDS.dit, or Credential Manager vaults
