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

*More sections to be added (configuration, enumeration, exploitation)...*
