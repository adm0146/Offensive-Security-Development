# 12 — Laudanum Web Shells

## Overview

**Laudanum** is a repository of ready-made injectable files for web shells and reverse shells. It supports multiple web languages and is a staple tool for any pentest engagement.

---

## What is Laudanum?

| Feature | Description |
|---------|-------------|
| **Purpose** | Pre-built files to inject onto victims for shell access |
| **Capabilities** | Reverse shells, browser-based command execution |
| **Languages** | ASP, ASPX, JSP, PHP, and more |
| **Availability** | Built into Parrot OS and Kali by default |
| **Location** | `/usr/share/laudanum/` |

> **Other distros:** Pull from GitHub: https://github.com/jbarcia/Web-Shells/tree/master/laudanum

---

## Laudanum Directory Structure

```
/usr/share/laudanum/
├── asp/
├── aspx/
│   └── shell.aspx
├── cfm/
├── jsp/
├── php/
└── ...
```

---

## Working with Laudanum

### Important Considerations

| Step | Action |
|------|--------|
| **Copy first** | Never modify the original — copy to a working directory |
| **Edit the file** | Insert your attacking host IP address |
| **Read comments** | Each file has instructions in the comments |
| **Remove signatures** | Delete ASCII art and comments to evade AV/signatures |

> ⚠️ **For shells:** You MUST edit the file to add your IP address before uploading.

---

## Demonstration: ASPX Shell Upload

### Step 1: Copy the Shell for Modification

```bash
cp /usr/share/laudanum/aspx/shell.aspx /home/tester/demo.aspx
```

### Step 2: Edit the Allowed IPs

Open the file and find the `allowedIps` variable (around line 59):

```csharp
string[] allowedIps = new string[] {"10.10.14.12"};
```

**Changes to make:**
- Add your attacking IP to the `allowedIps` array
- Remove ASCII art and comments (often signatured by AV)

### Step 3: Upload the Shell

Use the target application's upload function:
1. Find a file upload feature (config import, profile picture, document upload)
2. Select your modified `demo.aspx` file
3. Upload and note the path where the file was saved

### Step 4: Navigate to the Shell

Browse to the uploaded shell location:

```
http://status.inlanefreight.local/files/demo.aspx
```

> **Note:** Some apps use backslashes (`\`) in paths. Your browser will normalize `\\files\demo.aspx` to `//files/demo.aspx`.

### Step 5: Execute Commands

The Laudanum ASPX shell provides:
- Command input field (`cmd /c`)
- Submit button to execute
- STDOUT output display

**Example command:**
```
systeminfo
```

Returns: hostname, OS version, system type, processor, memory, network info.

---

## Laudanum Shell Types by Language

| Language | File | Use Case |
|----------|------|----------|
| **ASPX** | `shell.aspx` | Windows IIS servers |
| **ASP** | `shell.asp` | Legacy Windows IIS |
| **PHP** | `shell.php` | Linux LAMP, Windows WAMP |
| **JSP** | `shell.jsp` | Tomcat, Java application servers |
| **CFM** | `shell.cfm` | ColdFusion servers |

---

## Operational Security Tips

| Tip | Reason |
|-----|--------|
| **Remove comments** | Comments are often signatured by AV |
| **Remove ASCII art** | Same reason — easy detection |
| **Rename the file** | `demo.aspx` is less suspicious than `shell.aspx` |
| **Whitelist your IP** | Prevents others from using your shell |
| **Clean up after** | Delete the shell when done |

---

## Potential Upload Obstacles

| Obstacle | Description |
|----------|-------------|
| **Filename randomization** | App renames uploads — harder to find your shell |
| **No public directory** | Uploads stored outside webroot |
| **Extension filtering** | App blocks `.aspx`, `.php`, etc. |
| **Content-type validation** | App checks file headers, not just extension |
| **File size limits** | Shell may exceed upload size limit |

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **Laudanum location** | `/usr/share/laudanum/` on Kali/Parrot |
| **Always copy first** | Don't modify the original files |
| **Edit before upload** | Add your IP to `allowedIps` |
| **Remove signatures** | Strip comments and ASCII art for AV evasion |
| **Navigate to shell** | Browse to the upload path to execute commands |
| **Multiple languages** | ASPX, ASP, PHP, JSP, CFM available |
