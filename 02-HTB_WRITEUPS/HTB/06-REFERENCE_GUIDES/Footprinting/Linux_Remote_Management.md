# Linux Remote Management Protocols

> Protocols and services for remotely managing Linux servers — essential targets during penetration tests due to frequent misconfigurations.

---

## SSH (Secure Shell)

### Overview

**SSH** enables two computers to establish an **encrypted, direct connection** within a possibly insecure network.

| Characteristic | Details |
|----------------|---------|
| **Default Port** | TCP 22 |
| **Protocol** | SSH-1 (deprecated), SSH-2 (current) |
| **Server Software** | OpenSSH (open-source fork of commercial SSH) |
| **Native Support** | Linux, macOS (built-in), Windows (requires install) |
| **Purpose** | Remote shell, file transfer, port forwarding |

> ⚠️ **SSH-1 is vulnerable to MITM attacks.** SSH-2 is not — always use SSH-2.

---

### SSH Authentication Methods

OpenSSH supports **six** authentication methods:

| Method | Description |
|--------|-------------|
| **Password** | Standard username/password login |
| **Public-key** | Private/public key pair (most secure for daily use) |
| **Host-based** | Authenticates based on the client host |
| **Keyboard** | Interactive keyboard-based prompts |
| **Challenge-response** | Server issues a challenge, client responds |
| **GSSAPI** | Kerberos-based authentication |

---

### Public Key Authentication Flow

1. **Server → Client:** Server sends its public host key
2. **Client verifies** the server's identity (first connection = trust-on-first-use risk)
3. **Server → Client:** Creates cryptographic challenge using client's public key
4. **Client → Server:** Decrypts challenge with private key, sends solution back
5. **Connection established** — passphrase only entered once per session

> 💡 **Key Point:** Private key stays on your machine, never transmitted. Protected by a passphrase (should be longer than a typical password).

---

### Default Configuration

```bash
cat /etc/ssh/sshd_config | grep -v "#" | sed -r '/^\s*$/d'
```
> Prints the active SSH server config with comments and blank lines stripped, so only effective settings remain. Run on a host where you have local access to audit for dangerous SSH options.

```
Include /etc/ssh/sshd_config.d/*.conf
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server
```

> 📝 **Note:** X11 forwarding is enabled by default. OpenSSH 7.2p1 (2016) had a **command injection vulnerability** in X11 forwarding.

---

### Dangerous Settings

| Setting | Description |
|---------|-------------|
| `PasswordAuthentication yes` | Allows password-based auth (enables brute-force) |
| `PermitEmptyPasswords yes` | Allows **empty passwords** |
| `PermitRootLogin yes` | Allows direct root login |
| `Protocol 1` | Uses outdated, vulnerable SSH-1 encryption |
| `X11Forwarding yes` | Allows X11 GUI forwarding (potential command injection) |
| `AllowTcpForwarding yes` | Allows TCP port forwarding |
| `PermitTunnel` | Allows tunneling through SSH |
| `DebianBanner yes` | Displays OS-specific banner (information leakage) |

---

### Footprinting SSH

#### Nmap — SSH Version Detection

```bash
sudo nmap -sV -p 22 10.129.14.132
```
> Version-scans only SSH port 22 to grab the OpenSSH banner for CVE research. Swap `10.129.14.132` for your target IP.

#### ssh-audit — Comprehensive SSH Audit

```bash
git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
./ssh-audit.py 10.129.14.132
```
> Clones ssh-audit then audits the target's SSH crypto posture, flagging weak key-exchange/host-key/cipher algorithms. Swap `10.129.14.132` for your target IP.

Sample output:

```
# general
(gen) banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
(gen) software: OpenSSH 8.2p1
(gen) compatibility: OpenSSH 7.4+, Dropbear SSH 2018.76+
(gen) compression: enabled (zlib@openssh.com)

# key exchange algorithms
(kex) curve25519-sha256                     -- [info] available since OpenSSH 7.4
(kex) ecdh-sha2-nistp256                    -- [fail] using weak elliptic curves
(kex) ecdh-sha2-nistp384                    -- [fail] using weak elliptic curves
(kex) ecdh-sha2-nistp521                    -- [fail] using weak elliptic curves
(kex) diffie-hellman-group-exchange-sha256  -- [info] available since OpenSSH 4.4
(kex) diffie-hellman-group16-sha512         -- [info] available since OpenSSH 7.3
(kex) diffie-hellman-group18-sha512         -- [info] available since OpenSSH 7.3

# host-key algorithms
(key) rsa-sha2-512 (3072-bit)              -- [info] available since OpenSSH 7.2
(key) ssh-rsa (3072-bit)                   -- [fail] using weak hashing algorithm
(key) ecdsa-sha2-nistp256                  -- [fail] using weak elliptic curves
(key) ssh-ed25519                          -- [info] available since OpenSSH 6.5
```

Key things to look for:
- **Banner** reveals OpenSSH version (check for known CVEs like CVE-2020-14145)
- **Weak algorithms** flagged as `[fail]` or `[warn]`
- **Compression** and compatibility info

#### SSH Verbose Mode — Enumerate Auth Methods

```bash
ssh -v cry0l1t3@10.129.14.132
```
> Connects with verbose output so the server's advertised authentication methods are printed (publickey, password, etc.). Swap `cry0l1t3` for a username and `10.129.14.132` for your target IP.

```
debug1: Authentications that can continue: publickey,password,keyboard-interactive
```

#### Force Password Authentication (for brute-force testing)

```bash
ssh -v cry0l1t3@10.129.14.132 -o PreferredAuthentications=password
```
> Forces SSH to use password auth only, confirming the server accepts it before launching a brute-force. Swap the username and `10.129.14.132` for your target.

```
debug1: Authentications that can continue: publickey,password,keyboard-interactive
debug1: Next authentication method: password
cry0l1t3@10.129.14.132's password:
```

---

### SSH Banner Interpretation

| Banner | Meaning |
|--------|---------|
| `SSH-1.99-OpenSSH_3.9p1` | Supports both SSH-1 and SSH-2; OpenSSH 3.9p1 |
| `SSH-2.0-OpenSSH_8.2p1` | SSH-2 only; OpenSSH 8.2p1 |

> 📝 **Protocol prefix:** `SSH-1.99` = both versions, `SSH-2.0` = SSH-2 only.

---

## Rsync

### Overview

**Rsync** is a fast, efficient tool for copying files locally and remotely, known for its **delta-transfer algorithm** — only transmitting differences between source and destination files.

| Characteristic | Details |
|----------------|---------|
| **Default Port** | TCP 873 |
| **Secure Mode** | Can piggyback on SSH (`-e ssh`) |
| **Key Feature** | Delta-transfer — only sends changes, not full files |
| **Common Use** | Backups, mirroring, file synchronization |

---

### Footprinting Rsync

#### Nmap — Detect Rsync

```bash
sudo nmap -sV -p 873 127.0.0.1
```
> Version-scans the rsync port to confirm the daemon and its protocol version. Swap `127.0.0.1` for your target IP.

```
PORT    STATE SERVICE VERSION
873/tcp open  rsync   (protocol version 31)
```

#### Netcat — List Available Shares

```bash
nc -nv 127.0.0.1 873
```
> Raw-connects to the rsync daemon; type `#list` to enumerate available modules/shares. Swap `127.0.0.1` for your target IP.

```
@RSYNCD: 31.0
@RSYNCD: 31.0
#list
dev             Dev Tools
@RSYNCD: EXIT
```

#### Enumerate a Share

```bash
rsync -av --list-only rsync://127.0.0.1/dev
```
> Lists the contents of the `dev` rsync module without downloading anything. Swap `127.0.0.1` for your target IP and `dev` for the share name from `#list`.

```
drwxr-xr-x             48 2022/09/19 09:43:10 .
-rw-r--r--              0 2022/09/19 09:34:50 build.sh
-rw-r--r--              0 2022/09/19 09:36:02 secrets.yaml
drwx------             54 2022/09/19 09:43:10 .ssh
```

#### Download All Files from a Share

```bash
# Standard (rsync protocol)
rsync -av rsync://127.0.0.1/dev

# Over SSH
rsync -av -e ssh rsync://127.0.0.1/dev

# Over SSH on non-standard port
rsync -av -e "ssh -p2222" rsync://127.0.0.1/dev
```
> Downloads the entire `dev` share to the current directory, either over the raw rsync protocol or tunnelled through SSH (use `-e "ssh -pPORT"` for non-standard SSH ports). Swap the IP, share name, and port for your target.

> ⚠️ **Pentesting Insight:** Look for `.ssh` directories, config files, and credentials. Rsync shares are sometimes accessible **without authentication**. Always try password reuse if you have creds.

---

## R-Services (Legacy)

### Overview

**R-Services** are a legacy suite of Unix remote access services, replaced by SSH due to **inherent security flaws** — all traffic is transmitted **unencrypted**.

| Characteristic | Details |
|----------------|---------|
| **Ports** | TCP 512, 513, 514 |
| **Encryption** | **None** — plaintext transmission |
| **Replaced By** | SSH |
| **Still Found On** | Solaris, HP-UX, AIX, older Unix systems |

---

### R-Commands Reference

| Command | Daemon | Port | Description |
|---------|--------|------|-------------|
| `rcp` | rshd | 514/TCP | Remote file copy (like `cp`, no overwrite warning) |
| `rsh` | rshd | 514/TCP | Remote shell — no login procedure required |
| `rexec` | rexecd | 512/TCP | Remote command execution (username/password, unencrypted) |
| `rlogin` | rlogind | 513/TCP | Remote login (like telnet, Unix-only) |
| `rwho` | rwhod | 513/UDP | List interactive sessions on local network |
| `rusers` | — | — | Detailed info on logged-in users across network |

---

### Access Control — Trusted Hosts

R-services authenticate via **trusted host files** instead of passwords:

| File | Scope | Location |
|------|-------|----------|
| `/etc/hosts.equiv` | **Global** — all users on the system | System-wide |
| `~/.rhosts` | **Per-user** configuration | User home directory |

#### Syntax

```
# <username> <ip address or hostname>
pwnbox    cry0l1t3
+         10.0.17.10       # Any user from this host
+         +                # ANY user from ANY host (dangerous!)
```

> ⚠️ **Critical:** The `+ +` wildcard grants **any external user** access without credentials — instant compromise.

---

### Footprinting R-Services

#### Nmap — Scan R-Service Ports

```bash
sudo nmap -sV -p 512,513,514 10.0.17.2
```
> Version-scans the three legacy R-services ports (rexec/rlogin/rsh) to confirm they're exposed. Swap `10.0.17.2` for your target IP.

```
PORT    STATE SERVICE    VERSION
512/tcp open  exec?
513/tcp open  login?
514/tcp open  tcpwrapped
```

#### Rlogin — Attempt Login

```bash
rlogin 10.0.17.2 -l htb-student
```
> Attempts an rlogin session as the given user — succeeds without a password if the target trusts your host via `.rhosts`/`hosts.equiv`. Swap `10.0.17.2` for your target IP and `htb-student` for the username.

```
Last login: Fri Dec  2 16:11:21 from localhost
[htb-student@localhost ~]$
```

#### Rwho — List Active Sessions

```bash
rwho
```
> Lists users currently logged into hosts on the local network that run the rwhod daemon — harvest these usernames for later attacks. No arguments; broadcasts on the local segment.

```
root          web01:pts/0 Dec  2 21:34
htb-student   workstn01:tty1  Dec  2 19:57  2:25
```

#### Rusers — Detailed User Info

```bash
rusers -al 10.0.17.5
```
> Queries a specific host for detailed info on its logged-in users (`-a` all hosts, `-l` long format). Swap `10.0.17.5` for your target IP.

```
htb-student     10.0.17.5:console          Dec 2 19:57     2:25
```

> 💡 **Tip:** Use `rwho` and `rusers` output to compile usernames for further attacks across the network.

---

## Key Takeaways

1. **SSH TCP 22** — Primary remote management protocol; always check version and auth methods
2. **ssh-audit** — Reveals weak algorithms, version info, and potential CVEs
3. **Dangerous SSH settings** — `PermitRootLogin yes`, `PermitEmptyPasswords yes`, `Protocol 1`
4. **Force auth method** — Use `-o PreferredAuthentications=password` for brute-force testing
5. **Rsync TCP 873** — Check for unauthenticated share access; look for `.ssh` dirs and secrets
6. **Rsync over SSH** — Use `-e ssh` flag for encrypted transfers
7. **R-Services 512-514** — Legacy, unencrypted; rare but still found on Solaris/HP-UX/AIX
8. **hosts.equiv / .rhosts** — Trusted host files can bypass all authentication
9. **`+ +` wildcard** — Grants any user from any host access — critical misconfiguration
10. **Password reuse** — Always try discovered credentials against remote management services

---

*HTB Academy - Footprinting Module*
