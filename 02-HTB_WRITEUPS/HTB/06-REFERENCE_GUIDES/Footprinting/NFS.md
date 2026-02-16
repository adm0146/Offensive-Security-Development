# NFS (Network File System)

> Network file system developed by Sun Microsystems — access remote file systems as if they were local.

---

## Overview

| Property | Description |
|----------|-------------|
| **Purpose** | Access file systems over a network as if local |
| **Developer** | Sun Microsystems |
| **Used Between** | Linux and Unix systems |
| **Port** | TCP/UDP 2049 (NFSv4), TCP/UDP 111 (RPC) |

**Key Difference from SMB:**
- NFS = Linux/Unix to Linux/Unix
- SMB = Windows (and cross-platform via Samba)
- NFS clients **cannot** communicate directly with SMB servers

---

## NFS Versions

| Version | Features |
|---------|----------|
| **NFSv2** | Older, widely supported, initially operated entirely over UDP |
| **NFSv3** | Variable file size, better error reporting, not fully compatible with NFSv2 clients |
| **NFSv4** | Kerberos authentication, works through firewalls/Internet, no portmappers needed, supports ACLs, stateful protocol, performance improvements, high security |
| **NFSv4.1** | Cluster server deployments, parallel access (pNFS), session trunking (NFS multipathing) |

### NFSv4 Advantages

- **Single port:** Only TCP/UDP 2049 needed (simplifies firewall rules)
- **Kerberos support:** Proper user authentication
- **Stateful protocol:** First NFS version with state-based operations
- **ACL support:** Fine-grained access control
- **Internet-ready:** Works through firewalls

---

## Protocol Architecture

### Underlying Protocols

| Protocol | Port | Purpose |
|----------|------|---------|
| **ONC-RPC / SUN-RPC** | TCP/UDP 111 | Remote Procedure Call foundation |
| **XDR** | — | External Data Representation (system-independent data exchange) |
| **NFS** | TCP/UDP 2049 | File system operations |

### Authentication Model

```
NFS Protocol
    ↓
No built-in authentication/authorization
    ↓
Relies on RPC protocol options
    ↓
Authorization derived from file system information
    ↓
Server translates client user info to UNIX syntax (UID/GID)
```

---

## Authentication & Security

### Default Authentication: UNIX UID/GID

| Component | Description |
|-----------|-------------|
| **UID** | User ID |
| **GID** | Group ID |
| **Group Memberships** | Additional group associations |

### The UID/GID Problem

⚠️ **Critical Security Issue:**

- Client and server do **NOT** necessarily have the same UID/GID mappings
- Server does no further verification after initial translation
- No additional checks possible on server side

**Example Problem:**
```
Client System:
  UID 1000 = "john" (regular user)

Server System:
  UID 1000 = "admin" (privileged user)

Result: John accesses files as admin on the server!
```

### Security Recommendation

> ⚠️ **NFS should only be used with UNIX UID/GID authentication in trusted networks.**

For untrusted networks, use NFSv4 with Kerberos authentication.

---

## Ports Reference

| Port | Protocol | Service |
|------|----------|---------|
| 111 | TCP/UDP | RPC Portmapper (NFSv2/v3) |
| 2049 | TCP/UDP | NFS (all versions, only port needed for NFSv4) |

**NFSv4 Simplification:**
- NFSv2/v3: Required portmapper (111) + dynamic ports
- NFSv4: Only port 2049 needed

---

## Quick Reference

```bash
# Default NFS port
TCP/UDP 2049

# RPC Portmapper (NFSv2/v3)
TCP/UDP 111

# Protocol stack
NFS → ONC-RPC/SUN-RPC → XDR
```

---

## Security Considerations

| Risk | Detail |
|------|--------|
| **UID/GID Mismatch** | Different user mappings between client/server |
| **No Server Verification** | Server trusts client-provided UID/GID |
| **Trusted Network Only** | Default auth unsuitable for untrusted networks |
| **NFSv2/v3 Exposure** | Multiple ports, no encryption |

---

## Key Takeaways

1. **NFS ≠ SMB** — Different protocols, NFS for Linux/Unix only
2. **NFSv4 is preferred** — Single port, Kerberos, stateful, ACLs
3. **UID/GID authentication is weak** — Only use in trusted networks
4. **No built-in auth** — NFS relies entirely on RPC layer
5. **Firewall-friendly** — NFSv4 only needs port 2049

---

## Default Configuration

Config file: `/etc/exports`

> Contains a table of physical filesystems accessible by NFS clients.

```bash
cat /etc/exports
```

**Example Output:**
```bash
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
```

### Export Syntax

```
/path/to/share    host(options)
```

**Components:**
1. **Folder path** — Directory to share
2. **Host/Subnet** — Who can access (hostname, IP, or subnet)
3. **Options** — Permissions and settings in parentheses

---

## NFS Export Options

| Option | Description |
|--------|-------------|
| `rw` | Read and write permissions |
| `ro` | Read only permissions |
| `sync` | Synchronous data transfer (slower, safer) |
| `async` | Asynchronous data transfer (faster, less safe) |
| `secure` | Ports above 1024 will NOT be used |
| `insecure` | Ports above 1024 WILL be used |
| `no_subtree_check` | Disables subdirectory tree checking |
| `root_squash` | Maps root (UID/GID 0) to anonymous — prevents root access on mount |

---

## Creating NFS Shares

### Example: Share to Subnet

```bash
# Add export entry
echo '/mnt/nfs  10.129.14.0/24(sync,no_subtree_check)' >> /etc/exports

# Restart NFS service
systemctl restart nfs-kernel-server

# Verify exports
exportfs
```

**Output:**
```
/mnt/nfs      	10.129.14.0/24
```

**Result:** All hosts on 10.129.14.0/24 can mount and inspect `/mnt/nfs`

---

## Dangerous Settings (Pentester's Focus)

| Option | Description | Risk |
|--------|-------------|------|
| `rw` | Read and write permissions | Data modification/exfiltration |
| `insecure` | Allows ports above 1024 | Non-root users can interact with NFS |
| `nohide` | Exports nested mounted filesystems | Exposes additional directories |
| `no_root_squash` | Root files keep UID/GID 0 | **Remote root access possible** |

### Why `insecure` is Dangerous

**Port Restriction Background:**
- Ports 1-1024 = **privileged ports** (root only)
- Ports 1025+ = **unprivileged ports** (any user)

**With `secure` (default):**
- Only root can use NFS (must bind to port < 1024)

**With `insecure`:**
- Any user can interact with NFS service
- Non-root users can mount and access shares

### Why `no_root_squash` is Dangerous

**With `root_squash` (default):**
```
Client root (UID 0) → Mapped to anonymous → Limited access
```

**With `no_root_squash`:**
```
Client root (UID 0) → Stays as UID 0 → Full root access on share
```

⚠️ **Attack Vector:** If you can mount a share with `no_root_squash`, you effectively have root access to those files!

---

## Footprinting the Service

### Key Ports

| Port | Service |
|------|---------|
| 111 | RPC Portmapper |
| 2049 | NFS |

### Basic Nmap Scan

```bash
sudo nmap 10.129.14.128 -p111,2049 -sV -sC
```

**Example Output:**
```
PORT    STATE SERVICE VERSION
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100003  3           2049/udp   nfs
|   100003  3,4         2049/tcp   nfs
|   100005  1,2,3      45837/tcp   mountd
|   100021  1,3,4      44629/tcp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/udp   nfs_acl
2049/tcp open  nfs_acl 3 (RPC #100227)
```

**Key Info from rpcinfo:**
- Running RPC services
- Service names and descriptions
- Ports in use

---

## NFS NSE Scripts

### Run All NFS Scripts

```bash
sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049
```

**Example Output:**
```
PORT     STATE SERVICE VERSION
111/tcp  open  rpcbind 2-4 (RPC #100000)
| nfs-ls: Volume /mnt/nfs
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID    GID    SIZE  TIME                 FILENAME
| rwxrwxrwx   65534  65534  4096  2021-09-19T15:28:17  .
| ??????????  ?      ?      ?     ?                    ..
| rw-r--r--   0      0      1872  2021-09-19T15:27:42  id_rsa
| rw-r--r--   0      0      348   2021-09-19T15:28:17  id_rsa.pub
| rw-r--r--   0      0      0     2021-09-19T15:22:30  nfs.share
|_
| nfs-showmount: 
|_  /mnt/nfs 10.129.14.0/24
| nfs-statfs: 
|   Filesystem  1K-blocks   Used       Available   Use%  Maxfilesize  Maxlink
|_  /mnt/nfs    30313412.0  8074868.0  20675664.0  29%   16.0T        32000
```

### NFS NSE Scripts

| Script | Description |
|--------|-------------|
| `nfs-ls` | Lists files in NFS share with permissions, UID/GID, size, timestamps |
| `nfs-showmount` | Shows available exports and allowed hosts |
| `nfs-statfs` | Shows filesystem statistics (size, used, available) |

**Critical Finding:** `id_rsa` files visible = potential SSH key exfiltration!

---

## Manual NFS Enumeration

### Show Available Shares

```bash
showmount -e 10.129.14.128
```

**Output:**
```
Export list for 10.129.14.128:
/mnt/nfs 10.129.14.0/24
```

---

## Mounting NFS Shares

### Step-by-Step Mount Process

```bash
# 1. Create mount point
mkdir target-NFS

# 2. Mount the NFS share
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock

# 3. Navigate to mount
cd target-NFS

# 4. View structure
tree .
```

**Output:**
```
.
└── mnt
    └── nfs
        ├── id_rsa
        ├── id_rsa.pub
        └── nfs.share

2 directories, 3 files
```

### Mount Options

| Option | Description |
|--------|-------------|
| `-t nfs` | Specify NFS filesystem type |
| `-o nolock` | Disable file locking (useful for older NFS) |

---

## Post-Mount Enumeration

### List Files with Ownership

```bash
ls -l mnt/nfs/
```

**Output:**
```
total 16
-rw-r--r-- 1 cry0l1t3 cry0l1t3 1872 Sep 25 00:55 cry0l1t3.priv
-rw-r--r-- 1 cry0l1t3 cry0l1t3  348 Sep 25 00:55 cry0l1t3.pub
-rw-r--r-- 1 root     root     1872 Sep 19 17:27 id_rsa
-rw-r--r-- 1 root     root      348 Sep 19 17:28 id_rsa.pub
-rw-r--r-- 1 root     root        0 Sep 19 17:22 nfs.share
```

### What to Look For

| Item | Value |
|------|-------|
| **Usernames** | `cry0l1t3`, `root` |
| **Group names** | `cry0l1t3`, `root` |
| **Sensitive files** | `id_rsa`, `.priv` (SSH private keys) |
| **Permissions** | Who can read/write |

### UID/GID Attack Vector

⚠️ **Key Technique:** If you know the UID/GID of a user on the NFS server, you can:
1. Create a matching user on your local system with the same UID/GID
2. Access/modify files as that user on the mounted share

---

## NFS Enumeration Checklist

```bash
# 1. Scan for NFS
sudo nmap -p111,2049 -sV -sC TARGET

# 2. Run NFS scripts
sudo nmap --script nfs* -p111,2049 TARGET

# 3. List available shares
showmount -e TARGET

# 4. Mount share
mkdir /tmp/nfs-mount
sudo mount -t nfs TARGET:/ /tmp/nfs-mount -o nolock

# 5. Enumerate files
ls -la /tmp/nfs-mount
tree /tmp/nfs-mount

# 6. Check ownership
ls -ln /tmp/nfs-mount  # Shows numeric UID/GID
```

---

## Attack Vectors

| Vector | Description |
|--------|-------------|
| **SSH Key Theft** | Grab `id_rsa` files for SSH access |
| **UID/GID Spoofing** | Create local user with matching UID to access files |
| **Config File Exfil** | Read sensitive configs from mounted shares |
| **no_root_squash Abuse** | Write files as root if misconfigured |
| **Credential Harvesting** | Look for passwords, keys, configs in shares |
| **SUID Shell Upload** | Upload shell with target user's SUID for privilege escalation |

---

## Privilege Escalation via NFS

### root_squash Limitation

⚠️ **Note:** If `root_squash` is set, you **cannot** edit files as root on the NFS share — root gets mapped to anonymous.

### SUID Shell Attack

**Scenario:** You have SSH access but need to read files owned by another user.

**Attack Flow:**
```
1. Mount NFS share on attack machine
2. Create/upload shell binary to NFS share
3. Set SUID bit with target user's UID
4. SSH into target system
5. Execute the SUID shell from NFS mount
6. Shell runs with target user's privileges
```

This technique allows privilege escalation by leveraging NFS write access to create SUID binaries.

---

## Unmounting NFS Shares

```bash
# Navigate out of mount point first
cd ..

# Unmount the share
sudo umount ./target-NFS
```

⚠️ **Note:** You must exit the mounted directory before unmounting.

---

## NFS Quick Reference

```bash
# Scan for NFS
sudo nmap -p111,2049 -sV -sC TARGET

# Run NFS NSE scripts
sudo nmap --script nfs* -p111,2049 TARGET

# List available shares
showmount -e TARGET

# Mount NFS share
mkdir /tmp/nfs
sudo mount -t nfs TARGET:/ /tmp/nfs -o nolock

# Enumerate mounted share
ls -la /tmp/nfs
ls -ln /tmp/nfs  # Numeric UID/GID

# Unmount when done
cd .. && sudo umount /tmp/nfs
```

---

## Key Takeaways

1. **Ports 111 + 2049** — Essential for NFS footprinting
2. **NSE scripts (`nfs*`)** — Reveal shares, files, permissions without mounting
3. **showmount -e** — Quick way to list exports
4. **UID/GID matter** — Can spoof local user to match remote for file access
5. **root_squash** — Prevents root file modification (when enabled)
6. **no_root_squash** — Dangerous! Allows root access on mount
7. **SUID escalation** — Upload SUID shell via NFS for privilege escalation
8. **SSH keys** — Common sensitive files found on NFS shares
