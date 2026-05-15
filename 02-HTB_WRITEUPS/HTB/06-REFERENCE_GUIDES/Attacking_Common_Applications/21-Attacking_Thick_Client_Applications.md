# Section 21 — Attacking Thick Client Applications

**Thick client:** installed locally, processes data client-side, stores data locally. Communicates directly with a DB (two-tier) or via an app server over HTTP/HTTPS (three-tier).

**Not in scope here:** XSS, CSRF, Clickjacking — those are web-only.

**Attack surface:**
- Hardcoded credentials / sensitive strings in the binary
- Insecure local file/registry storage
- DLL hijacking
- SQL injection (if talking to a DB directly)
- Buffer overflow
- Improper error handling

---

## Architecture

| Type | Path | Security |
|------|------|----------|
| Two-tier | App → DB (direct) | Lower — attacker can hit DB directly |
| Three-tier | App → App server → DB | Higher — DB not directly reachable |

---

## Methodology

### 1 — Information Gathering
- Identify: architecture type, language/framework (.NET, Java, C++), entry points, user inputs
- Tools: **CFF Explorer**, **Detect It Easy** (detect language/packer), **Process Monitor**, **Strings**

### 2 — Static Analysis
Reverse the binary to find hardcoded creds, tokens, API keys, connection strings.

| Tool | Use |
|------|-----|
| dnSpy | Decompile .NET (EXE, DLL) back to C# |
| de4dot | Deobfuscate .NET assemblies before loading in dnSpy |
| JADX | Decompile Android/Java (JAR, APK) |
| Ghidra / IDA | Disassemble native binaries (C/C++) |
| Radare2 / x64dbg / OllyDbg | Dynamic analysis + memory inspection |

### 3 — Dynamic Analysis
- Run the app, watch what files/registry keys it touches — **ProcMon64**
- Inspect memory at runtime — **x64dbg**, dump interesting regions
- Capture network traffic — **Wireshark**, **Burp Suite** (proxy HTTPS)

### 4 — Network / Server-Side
Three-tier apps talk HTTP/HTTPS — intercept with Burp, test for standard web vulns (SQLi, IDOR, command injection) against the app server.

---

## Extracting Hardcoded Credentials — Full Walkthrough

### Scenario
During a pentest, found `Restart-OracleService.exe` on an SMB NETLOGON share. Runs silently — extract the hidden credentials from its source.

### Step 1 — Observe file behavior with ProcMon64
Run the EXE and filter in ProcMon64 for the process name.

```
ProcMon64 → Filter → Process Name → Restart-OracleService.exe
```
> Watch for CreateFile events to `%TEMP%`. The process drops a `.bat` and a `.tmp` file and immediately deletes them.

### Step 2 — Prevent temp file deletion
To capture the dropped file before it's deleted, remove delete permissions from the Temp folder:

```
Right-click C:\Users\<username>\AppData\Local\Temp
→ Properties → Security → Advanced → [your user] → Edit
→ Show advanced permissions
→ Uncheck "Delete subfolders and files" and "Delete"
→ OK → Apply → OK
```
> Revoking delete permission prevents the process from cleaning up its temp files. The file names are random (e.g., `6F39.bat`) — check the `\Temp\2` subfolder after re-running the EXE.

### Step 3 — Re-run EXE and recover the .bat

```cmd
.\Restart-OracleService.exe
dir C:\Users\<username>\AppData\Local\Temp\2
```
> Look for a `.bat` file. It contains the real payload.

**Alternative to denying delete perms — PowerShell capture loop:**
Instead of editing folder ACLs, race the deletion with a tight copy loop in a second window before running the EXE:

```powershell
while($true){ Copy-Item "$env:LOCALAPPDATA\Temp\*\*\*.bat" C:\Apps\captured.bat -ErrorAction SilentlyContinue }
```
> Spins forever copying any `.bat` that appears under the random `Temp\<hex>\<hex>\` path to a safe location. Start this first, then double-click the EXE — the loop grabs the file in the millisecond it exists before the parent deletes it. Useful when you can't modify folder permissions (e.g., locked-down host).

### Step 4 — Inspect the .bat

The batch file:
1. Checks `%username%` against a hardcoded allowlist
2. Writes base64 data line-by-line to `c:\programdata\oracle.txt`
3. Runs a PowerShell one-liner (`monta.ps1`) that decodes oracle.txt → `restart-service.exe`
4. Executes `restart-service.exe`, then **deletes everything**

**Verified `.bat` content (PivotAPI / this lab):**

```batch
@echo off
if %username% == cybervaca goto correcto
if %username% == frankytech goto correcto
if %username% == ev4si0n goto correcto
goto error
:correcto
echo TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAA > c:\programdata\oracle.txt
echo <...base64 appended line-by-line...> >> c:\programdata\oracle.txt
echo $salida = $null; $fichero = (Get-Content C:\ProgramData\oracle.txt) ; foreach ($linea in $fichero) {$salida += $linea.Replace(" ","")} ; [System.IO.File]::WriteAllBytes("C:\ProgramData\restart-service.exe",([System.Convert]::FromBase64String($salida))) > c:\programdata\monta.ps1
powershell.exe -exec bypass -file c:\programdata\monta.ps1
```
> The `%username%` allowlist (`cybervaca`, `frankytech`, `ev4si0n`) is why the EXE "does nothing" under any other account — the payload only unpacks for whitelisted users. `monta.ps1` is written *by* the bat: it concatenates every line of `oracle.txt`, strips spaces, base64-decodes the blob, and `WriteAllBytes` it to `restart-service.exe` (the real inner tool). Run the EXE as `cybervaca` (your RDP user is on the list) or the chain aborts at `:error`.

### Step 5 — Recover the decoded EXE

Edit the `.bat` — remove all `del` lines at the bottom, then run it:

```batch
REM Remove these lines from the .bat before running:
del c:\programdata\monta.ps1
del c:\programdata\oracle.txt
del c:\programdata\restart-service.exe
```

After running the modified bat, you'll have:
```
c:\programdata\oracle.txt          ← base64 blob
c:\programdata\monta.ps1           ← PS decoder script
c:\programdata\restart-service.exe ← the actual .NET binary
```

Or run monta.ps1 manually if oracle.txt is present:
```powershell
powershell.exe -exec bypass -file c:\programdata\monta.ps1
```
> monta.ps1 reads oracle.txt, strips spaces, base64-decodes it, and writes the result as `restart-service.exe`. The `WriteAllBytes` call produces the final binary.

### Step 6 — Find the .NET assembly in memory with x64dbg

Open x64dbg → **Options → Preferences** → uncheck everything except **Exit Breakpoint** → **File → Open → restart-service.exe**

> Unchecking other breakpoints skips DLL loading pauses and lands you at the app's exit point — faster analysis.

Once loaded: **right-click in CPU view → Follow in Memory Map**

Look for a region with:
- Size: `0x3000`
- Type: `MAP`
- Protection: `-RW--`

Double-click it — confirm the `MZ` magic bytes in the ASCII column.

> `MZ` = DOS/PE executable header. Memory-mapped `.exe` inside the parent process — this is the inner payload dropped at runtime.

**Dump it:** right-click the region → **Dump Memory to File** → save as `inner.bin`

### Step 7 — Confirm it's .NET

```powershell
C:\TOOLS\Strings\strings64.exe .\inner.bin | findstr /i ".net"
# → .NETFramework,Version=v4.0 confirms it's a .NET assembly
```

### Step 8 — Deobfuscate with de4dot

Drag `inner.bin` onto `de4dot.exe` (or run from CLI):
```cmd
de4dot.exe inner.bin
# Output: inner-cleaned.bin
```
> de4dot deobfuscates .NET assemblies, renames mangled symbols back to readable names, and strips most protection schemes. Do this before dnSpy or you'll see garbage identifiers.

### Step 9 — Decompile with dnSpy

Drag `inner-cleaned.bin` onto `dnSpy.exe`. Browse the class tree and read the source.

Look for: connection strings, `SecureString` construction, `ProcessStartInfo`/`CreateProcessWithLogonW` with hardcoded credentials, `runas`-style logic.

The binary is a custom `runas.exe` that restarts an Oracle service using hardcoded credentials written into the source. The password is **not** in plaintext in the source — it's passed through a `Decrypt()` routine. The key/seed string in this binary is **`Cr_is_a_crybaby`**.

**Recover the cleartext without breaking the crypto by hand — breakpoint after Decrypt:**

```
dnSpy → find the Decrypt() call site → click the line AFTER it → F9 (set breakpoint)
→ Debug → Start Without Debugging is wrong; use Debug → Debug an Assembly (F5)
→ when it breaks, hover/right-click the decrypted variable → Show in Memory Window
```
> Setting the breakpoint *after* `Decrypt()` lets the program do the decryption for you; you just read the result out of memory. This beats reversing the algorithm by hand — standard trick for any "encrypted string in a .NET binary" challenge. The decrypted value is the service password.

### Step 9b — Fast path: API Monitor (skip x64dbg/de4dot/dnSpy entirely)

`restart-service.exe` ultimately calls the Win32 API `CreateProcessWithLogonW` to launch the Oracle restart **as another user** — that API takes the username and password as plaintext arguments. Watching the call is far faster than static analysis:

```
1. Open API Monitor (64-bit)
2. API Filter → search "CreateProcessWithLogonW" → tick it (under Security/Logon)
3. File → Run → browse to restart-service.exe (run as cybervaca) → Run
4. In the capture, click the CreateProcessWithLogonW row → Parameters pane
   → lpUsername and lpPassword show the credentials in cleartext
```
> `CreateProcessWithLogonW(lpUsername, lpDomain, lpPassword, ...)` is the "run this as that user" syscall — the credentials *must* be in memory as plaintext at call time, so an API monitor reveals them with zero reversing. This was 0xdf's actual solve and is the fastest route under exam time pressure. Equivalent filters: `CreateProcessAsUserW`, `LogonUserW`.

### ✅ Recovered credentials (this lab / PivotAPI)

```
Username: svc_oracle
Password: #oracle_s3rV1c3!2010
```
**Submit:** `svc_oracle:#oracle_s3rV1c3!2010`

> On the full PivotAPI machine these Oracle creds were later rotated to `svc_mssql:#mssql_s3rV1c3!2020` (Oracle→MSSQL migration referenced in mailbox emails) — only relevant for the box, **not** for the Academy question, which expects the hardcoded source value above.

---

## Exam Notes

- Thick clients often **drop files to `%TEMP%` and delete them immediately** — deny delete permissions before running to capture them
- `.bat` files writing base64 in chunks then decoding via PowerShell = common obfuscation pattern; decode oracle.txt manually if needed
- `MZ` in a memory map = embedded PE; always dump and analyze
- **de4dot before dnSpy** — obfuscated .NET is unreadable without it
- Two-tier apps (direct DB connection) often have connection strings hardcoded in the binary or config files
- Static strings can be found with `strings64.exe`, `Strings` from Sysinternals, or `grep` on the decoded binary
- **`CreateProcessWithLogonW` / `CreateProcessAsUserW` / `LogonUserW` take plaintext creds** — an API monitor on these is the single fastest way to pull hardcoded credentials out of a "run as another user" binary; try it *before* committing to x64dbg/de4dot/dnSpy
- Encrypted string in a .NET binary? **Don't reverse the algorithm — breakpoint right after the `Decrypt()` call and read memory.** Find the key/seed string first (here: `Cr_is_a_crybaby`)
- `%username%` allowlist inside a dropped `.bat` = the binary is account-gated; run it as a whitelisted user (`cybervaca`/`frankytech`/`ev4si0n`) or nothing unpacks
- This lab's answer: **`svc_oracle:#oracle_s3rV1c3!2010`** (PivotAPI box rotates it to `svc_mssql:#mssql_s3rV1c3!2020`)

---

## Lab Walkthrough (RDP: cybervaca / &aue%C)}6g-d{w)

**Goal:** Extract hardcoded credentials from `C:\Apps\Restart-OracleService.exe`

**Full static route:**
```
1. RDP in as cybervaca   (cybervaca / &aue%C)}6g-d{w)
2. Copy Restart-OracleService.exe to a working dir (e.g., C:\Apps\)
3. Run ProcMon64, filter on process name Restart-OracleService.exe
4. Execute the EXE — observe temp file creation in AppData\Local\Temp\<hex>\<hex>\
5. Deny delete permission on the Temp folder  (OR start the PowerShell capture loop)
6. Re-run the EXE — capture the .bat file
7. Edit the .bat — remove all del lines at the bottom
8. Double-click the modified .bat to run it
9. Recover c:\programdata\restart-service.exe
10. Open x64dbg → load restart-service.exe with only Exit Breakpoint enabled
11. Follow in Memory Map → find MAP/-RW-- region with MZ bytes
12. Dump Memory to File → inner.bin
13. Run de4dot on inner.bin → inner-cleaned.bin
14. Open inner-cleaned.bin in dnSpy → find Decrypt() (key "Cr_is_a_crybaby")
    → breakpoint after the call → Show in Memory → read the password
```

**Fast route (exam time pressure — recommended):**
```
1. RDP in as cybervaca, copy the EXE local
2. ProcMon + PowerShell capture loop → grab the .bat → strip del lines → run it
3. Get c:\programdata\restart-service.exe
4. API Monitor → filter CreateProcessWithLogonW → run restart-service.exe
5. Read lpUsername / lpPassword straight from the call parameters
```

> ✅ **Answer:** `svc_oracle:#oracle_s3rV1c3!2010` — recovered from the `CreateProcessWithLogonW` call (or the `Decrypt()` output in dnSpy). The binary is a wrapper that restarts the Oracle service by launching it as `svc_oracle` with embedded credentials.
