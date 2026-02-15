# FTP (File Transfer Protocol)

> One of the oldest protocols on the internet - runs at application layer alongside HTTP and POP.

---

## How FTP Works

### Two-Channel Architecture

| Channel | Port | Purpose |
|---------|------|---------|
| **Control** | TCP 21 | Commands & status codes |
| **Data** | TCP 20 | File transfers |

**Connection Flow:**
1. Client connects to server on **port 21** (control channel)
2. Client sends commands, server returns status codes
3. Data channel established on **port 20** for actual transfers
4. Protocol monitors for errors - can resume broken transfers

---

## Active vs Passive FTP

### Active FTP
```
Client → Server (port 21): "Connect to my port XXXX for data"
Server → Client (port XXXX): Attempts connection
```
**Problem:** If client has firewall, server can't connect back (external connections blocked)

### Passive FTP
```
Client → Server (port 21): "I need passive mode"
Server → Client: "Connect to my port YYYY for data"
Client → Server (port YYYY): Establishes data channel
```
**Solution:** Client initiates ALL connections - firewall doesn't block outbound

---

## FTP Commands & Status Codes

Common operations:
- Upload/download files
- Create/delete directories
- Delete files

Server responds with status codes:
- **1xx** - Positive preliminary
- **2xx** - Positive completion
- **3xx** - Positive intermediate
- **4xx** - Transient negative
- **5xx** - Permanent negative

📚 Full list: https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes

---

## Authentication

### Standard FTP
- Requires credentials (username/password)
- **Clear-text protocol** - can be sniffed on network

### Anonymous FTP
- No password required
- Server allows public access
- Usually restricted options (security risk)
- Common anonymous creds: `anonymous:anonymous` or `anonymous:email@address`

---

## Security Considerations

| Risk | Detail |
|------|--------|
| **Clear-text** | Credentials visible if sniffed |
| **Anonymous access** | Potential data exposure |
| **No encryption** | All data transmitted in plain text |

**Secure alternatives:** SFTP (SSH), FTPS (FTP over TLS)

---

## Quick Reference

```bash
# Default ports
Control: TCP 21
Data: TCP 20 (active) / random high port (passive)

# Common anonymous creds
anonymous:anonymous
anonymous:guest
ftp:ftp
```
