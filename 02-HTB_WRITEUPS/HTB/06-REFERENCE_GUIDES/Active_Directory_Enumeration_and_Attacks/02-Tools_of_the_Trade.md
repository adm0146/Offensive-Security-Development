# Section 02 — Tools of the Trade

> No lab questions. Tool reference by attack phase.

**Tool locations:** Windows = `C:\Tools\` | Linux = `/opt/` or PATH

---

## QUICK REFERENCE — Tool by Phase

| Phase | Tools |
|-------|-------|
| **Unauthenticated recon** | `enum4linux`, `smbmap`, `rpcclient`, `kerbrute`, `responder -A` |
| **Authenticated enumeration** | `PowerView`, `bloodhound-python`, `ldapsearch`, `windapsearch`, `nxc` |
| **Credential attacks** | `GetNPUsers.py`, `GetUserSPNs.py`, `kerbrute`, `DomainPasswordSpray.ps1`, `hashcat` |
| **Lateral movement** | `psexec.py`, `wmiexec.py`, `evil-winrm`, `nxc -x` |
| **Credential extraction** | `mimikatz`, `secretsdump.py` |
| **Kerberos abuse** | `Rubeus`, `ticketer.py`, `gettgtpkinit.py` |
| **Domain takeover** | `secretsdump.py` (DCSync), `noPac.py`, `PetitPotam.py` + `ntlmrelayx.py` |

---

## Enumeration Tools

| Tool | Platform | Use |
|------|----------|-----|
| `PowerView` / `SharpView` | Windows | AD situational awareness — users, groups, ACLs, SPNs |
| `BloodHound` + `SharpHound` | Windows | Visual attack path mapping |
| `bloodhound-python` | Linux | BloodHound collection without domain-joined host |
| `ldapsearch` | Linux | Raw LDAP queries |
| `windapsearch` | Linux | Automated LDAP enumeration |
| `enum4linux` / `enum4linux-ng` | Linux | SMB/NetBIOS/LDAP enumeration, NULL sessions |
| `smbmap` | Linux | SMB share enumeration |
| `rpcclient` | Linux | RPC-based AD enumeration |
| `adidnsdump` | Linux | Dump DNS records from domain |
| `Snaffler` | Windows | Find credentials in accessible file shares |
| `AD Explorer` | Windows | GUI AD viewer — take offline snapshots |
| `PingCastle` | Windows | AD security audit and risk scoring |
| `lookupsid.py` | Linux | SID brute-force user/group enumeration (Impacket) |
| `setspn.exe` | Windows | Read/modify SPNs (built-in) |

---

## Credential Attack Tools

| Tool | Platform | Use |
|------|----------|-----|
| `Kerbrute` | Linux/Windows | Username enum + password spray via Kerberos |
| `DomainPasswordSpray.ps1` | Windows | Password spray — auto-builds list, respects lockout |
| `Responder` | Linux | Poison LLMNR/NBT-NS → capture NTLMv2 |
| `Inveigh` / `InveighZero` | Windows | Responder equivalent for Windows |
| `GetNPUsers.py` | Linux | AS-REP roasting (Impacket) |
| `GetUserSPNs.py` | Linux | Kerberoasting (Impacket) |
| `gpp-decrypt` | Linux | Decrypt cpassword from GPP XML |
| `Hashcat` | Linux | Offline hash cracking |
| `LAPSToolkit` | Windows | Enumerate and read LAPS passwords |

---

## Lateral Movement Tools

| Tool | Platform | Use |
|------|----------|-----|
| `psexec.py` | Linux | SYSTEM shell via SMB (noisy) |
| `wmiexec.py` | Linux | Command exec via WMI (stealthier) |
| `evil-winrm` | Linux | WinRM shell with pass-the-hash |
| `smbserver.py` | Linux | Host SMB share for file transfers |
| `mssqlclient.py` | Linux | Interact with MSSQL databases |
| `nxc` | Linux | Swiss army knife — SMB/LDAP/WinRM/MSSQL |
| `Mimikatz` | Windows | Dump creds, PTH, PTT, DCSync |
| `secretsdump.py` | Linux | Remote SAM/LSA/NTDS dump + DCSync |
| `Rubeus` | Windows | Kerberos ticket abuse |

---

## Kerberos / Exploit Tools

| Tool | Platform | Use |
|------|----------|-----|
| `ticketer.py` | Linux | Forge Golden/Silver tickets |
| `gettgtpkinit.py` | Linux | PKINIT — get TGT from certificate |
| `getnthash.py` | Linux | Get NT hash from TGT via U2U |
| `noPac.py` | Linux | CVE-2021-42278/42287 — impersonate DA from user |
| `CVE-2021-1675.py` | Linux | PrintNightmare RCE |
| `PetitPotam.py` | Linux | Coerce DC auth via MS-EFSRPC |
| `ntlmrelayx.py` | Linux | NTLM relay attacks |
