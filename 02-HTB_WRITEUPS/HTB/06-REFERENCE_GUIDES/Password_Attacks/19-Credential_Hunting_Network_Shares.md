# 🔑 Credential Hunting in Network Shares

> **Module Section:** 19 / 26 — Password Attacks

## Overview

Nearly all corporate environments include **network shares** used by employees to store and share files across teams. While essential, they can unintentionally become a **goldmine for attackers** — especially when sensitive data like plaintext credentials or configuration files are left behind.

This section covers how to hunt for credentials across network shares from both **Windows** and **Linux** systems using common tools and techniques attackers use to uncover hidden secrets.

---

## Common Credential Patterns

Before using specialized tools, understand the **patterns and file formats** that often reveal sensitive information.

### Keywords to Search For

| Type | Examples |
|------|----------|
| **Credential keywords** | `passw`, `user`, `token`, `key`, `secret` |
| **File extensions** | `.ini`, `.cfg`, `.env`, `.xlsx`, `.ps1`, `.bat` |
| **Interesting filenames** | `config`, `user`, `passw`, `cred`, `initial` |
| **Domain-specific** | `INLANEFREIGHT\` (locate creds within a domain) |

### Strategic Tips

- 🌍 **Localize keywords** — Attacking a German company? Search for `Benutzer` instead of `User`
- 🎯 **Be strategic with shares** — Scanning 10 shares with thousands of files takes significant time
- 💼 **Prioritize IT shares** over company photos or marketing shares
- 🔍 **Start simple** — Begin with command-line searches before scaling to automated tools

### Quick PowerShell Search

```powershell
Get-ChildItem -Recurse -Include *.ext \\Server\Share | Select-String -Pattern "passw"
```

---

## Hunting from Windows

### 🛠 Snaffler

A **C# program** that, when run on a domain-joined machine, automatically identifies accessible network shares and searches for interesting files.

#### Basic Usage

```cmd
c:\Users\Public>Snaffler.exe -s
```

#### Example Output Highlights

```
[Share] {Green}<\\DC01.inlanefreight.local\ADMIN$>(R) Remote Admin
[Share] {Green}<\\DC01.inlanefreight.local\IT>(R)
[Share] {Green}<\\DC01.inlanefreight.local\HR>(R)

[File] {Red}<KeepPassOrKeyInCode|R|passw?o?r?d?>\s*[^\s<]+\s*<|2.3kB>
       (\\DC01.inlanefreight.local\ADMIN$\Panther\unattend.xml)
       <AdministratorPassword>*SENSITIVE*DATA*DELETED*</AdministratorPassword>
```

#### Color Coding

| Color | Meaning |
|-------|---------|
| 🟢 **Green** | Accessible share (R = Read) |
| 🔴 **Red** | High-value finding (e.g., passwords) |
| 🟡 **Yellow** | Medium-interest file (e.g., disk images) |
| ⚫ **Black** | No access |

#### Useful Parameters

| Flag | Purpose |
|------|---------|
| `-s` | Basic share discovery and file scan |
| `-u` | Retrieve users from AD and search for references to them in files |
| `-i` | **Include** specific shares in the search |
| `-n` | Exclude specific shares |

> ⚠️ **Manual review required** — Snaffler (and all these tools) generates large output with many false positives.

---

### 🛠 PowerHuntShares

A **PowerShell script** that doesn't require a domain-joined machine. Its killer feature: generates an **HTML report** with an easy-to-review UI.

#### Report Example

Summary shows findings categorized as:
- 🔴 Critical
- 🟠 High
- 🟡 Medium
- 🟢 Low

Plus: **Interesting**, **Sensitive**, and **Secrets** file categories.

#### Basic Usage

```powershell
PS C:\Users\Public\PowerHuntShares> Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\Users\Public
```

#### What It Automates

- ✅ Determines current computer's domain
- ✅ Enumerates domain computers
- ✅ Checks ping responses
- ✅ Filters for TCP 445 open and accessible
- ✅ Enumerates SMB shares and permissions
- ✅ Identifies shares with **excessive privileges**
- ✅ Identifies **high-risk** shares
- ✅ Enumerates common share owners, names, directory listings
- ✅ Generates last-written and last-accessed timelines
- ✅ Produces HTML summary + detailed CSV files

> ⏱ Can take **hours** to run in large environments.

---

## Hunting from Linux

### 🛠 MANSPIDER

Scan SMB shares **remotely from Linux** — no domain-joined computer needed. Best run via the **official Docker container** to avoid dependency issues.

#### Basic Content Search

```bash
docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider \
  10.129.234.121 -c 'passw' -u 'mendres' -p 'Inlanefreight2025!'
```

#### Key Output

```
[+] Skipping files larger than 10.00MB
[+] Using 5 threads
[+] Searching by file content: "passw"
[+] Matching files will be downloaded to /root/.manspider/loot
[+] 10.129.234.121: Successful login as "mendres"
```

#### Key Options

| Flag | Purpose |
|------|---------|
| `-c` | Content pattern to search for |
| `-u` | Username |
| `-p` | Password |
| `-v` | Volume mount for loot storage |

> 📥 **Matching files are automatically downloaded** to the loot directory for offline review.

---

### 🛠 NetExec (`nxc`)

In addition to its many other uses, NetExec can **spider network shares** using the `--spider` option.

#### Basic Usage

```bash
nxc smb 10.129.234.121 -u mendres -p 'Inlanefreight2025!' \
    --spider IT --content --pattern "passw"
```

#### Example Output

```
SMB  10.129.234.121  445  DC01  [*] Windows 10 / Server 2019 Build 17763 x64
SMB  10.129.234.121  445  DC01  [+] inlanefreight.local\mendres:Inlanefreight2025!
SMB  10.129.234.121  445  DC01  [*] Started spidering
SMB  10.129.234.121  445  DC01  [*] Spidering .
```

#### Key Options

| Flag | Purpose |
|------|---------|
| `--spider <share>` | Specify share to spider |
| `--content` | Search file contents (not just names) |
| `--pattern <str>` | Pattern to search for |

---

## Tool Comparison

| Tool | Platform | Domain-Joined? | Output Format | Best For |
|------|----------|----------------|---------------|----------|
| **Snaffler** | Windows | ✅ Required | Console (colored) | Thorough scans with classification rules |
| **PowerHuntShares** | Windows | ❌ Not required | HTML + CSV | Management-friendly reports |
| **MANSPIDER** | Linux | ❌ Not required | Downloaded loot | Remote credential hunting |
| **NetExec** | Linux | ❌ Not required | Console | Quick pattern-based searches |

---

## Common High-Value Finds

| File | Why It Matters |
|------|----------------|
| `unattend.xml` | Contains `AdministratorPassword` (sometimes Base64-encoded) |
| `sysprep.inf` / `sysprep.xml` | Autoinstall configs with creds |
| `web.config` | Connection strings, credentials |
| `.ps1` / `.bat` scripts | Hardcoded credentials |
| `*.kdbx` | KeePass databases |
| `Groups.xml` (SYSVOL) | GPP passwords (cpassword) |
| `.env` / `.ini` / `.cfg` | Application config + secrets |

---

## Key Takeaways

1. **Network shares are credential goldmines** — left-behind configs, scripts, and unattend files contain plaintext secrets
2. **Start simple** with command-line searches before launching automated tools
3. **Be strategic about shares** — target IT/admin shares first
4. **Localize keywords** to the target's language
5. **Manual review is essential** — all tools produce false positives
6. **Snaffler** = best on-system Windows tool; **PowerHuntShares** = best report UI
7. **MANSPIDER** = best for remote Linux-based hunting with auto-download of loot
8. **NetExec** = fast, pattern-based, integrates with existing AD workflows
9. Always check **ADMIN$** and **C$** shares for `Panther\unattend.xml` and SYSVOL for GPP files

---

## Exercise

> Use credentials `mendres:Inlanefreight2025!` to connect via RDP or WinRM. Snaffler and PowerHuntShares are pre-loaded in `C:\Users\Public`.

### Exercise Answers

*Add exercise answers here as you complete them*

---

## References

- [Snaffler GitHub](https://github.com/SnaffCon/Snaffler)
- [PowerHuntShares GitHub](https://github.com/NetSPI/PowerHuntShares)
- [MANSPIDER GitHub](https://github.com/blacklanternsecurity/MANSPIDER)
- [NetExec Wiki — Spider Module](https://www.netexec.wiki/smb-protocol/spidering-shares)
