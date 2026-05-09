# 02 — Tools of the Trade

> No lab questions. Tool reference organized by function.

**Tool locations:**
- Windows attack host (MS01): `C:\Tools\`
- Linux attack host (ATTACK01): `/opt/` or in PATH

---

## Enumeration

| Tool | Platform | Use |
|------|----------|-----|
| `PowerView` / `SharpView` | Windows | AD situational awareness — users, groups, ACLs, SPNs, find Kerberoastable accounts |
| `BloodHound` + `SharpHound` | Windows | Visual attack path mapping; SharpHound collects, BloodHound graphs |
| `BloodHound.py` | Linux | BloodHound collection without domain-joined host |
| `ldapsearch` | Linux | Raw LDAP queries |
| `windapsearch` | Linux | Automated LDAP enumeration — users, groups, computers |
| `enum4linux` / `enum4linux-ng` | Linux | SMB/NetBIOS/LDAP enumeration, NULL sessions |
| `smbmap` | Linux | SMB share enumeration across domain |
| `rpcclient` | Linux | RPC-based AD enumeration (users, groups, password policy) |
| `rpcinfo` | Linux | Query RPC services on a remote host |
| `rpcdump.py` | Linux | RPC endpoint mapper (Impacket) |
| `adidnsdump` | Linux | Dump DNS records from domain (like DNS zone transfer) |
| `Snaffler` | Windows | Find credentials and sensitive data in accessible file shares |
| `AD Explorer` | Windows | GUI AD viewer/editor; take offline snapshots for analysis |
| `PingCastle` | Windows | AD security audit — risk assessment and maturity scoring |
| `Group3r` | Windows | Audit GPO misconfigurations |
| `ADRecon` | Windows | Extract AD data to Excel for analysis |
| `setspn.exe` | Windows | Read/modify SPNs (built-in) |
| `lookupsid.py` | Linux | SID brute-force — enumerate users/groups (Impacket) |

---

## Credential Attacks

| Tool | Platform | Use |
|------|----------|-----|
| `Kerbrute` | Linux/Windows | Username enumeration + password spraying via Kerberos |
| `DomainPasswordSpray.ps1` | Windows | Password spray against all domain users (respects lockout policy) |
| `Responder` | Linux | Poison LLMNR/NBT-NS/MDNS → capture NetNTLMv2 hashes |
| `Inveigh.ps1` / `InveighZero` | Windows | Responder equivalent for Windows |
| `GetNPUsers.py` | Linux | AS-REP roasting — get hashes for accounts without pre-auth (Impacket) |
| `GetUserSPNs.py` | Linux | Kerberoasting — get TGS hashes for SPN accounts (Impacket) |
| `gpp-decrypt` | Linux | Decrypt cpassword from Group Policy Preferences XML |
| `Hashcat` | Linux | Offline hash cracking |
| `LAPSToolkit` | Windows | Enumerate/abuse LAPS — find computers with LAPS and read passwords |

---

## Lateral Movement & Execution

| Tool | Platform | Use |
|------|----------|-----|
| `psexec.py` | Linux | Semi-interactive shell via SMB (Impacket) |
| `wmiexec.py` | Linux | Command execution over WMI (Impacket) |
| `evil-winrm` | Linux | WinRM shell, pass-the-hash support |
| `smbserver.py` | Linux | Host SMB share for file transfers (Impacket) |
| `mssqlclient.py` | Linux | Interact with MSSQL databases (Impacket) |
| `nxc` (netexec) | Linux | SMB/LDAP/WinRM/MSSQL spray, exec, enum |
| `Mimikatz` | Windows | Dump credentials, pass-the-hash, pass-the-ticket, DCSync |
| `secretsdump.py` | Linux | Remote SAM/LSA/NTDS dump, DCSync (Impacket) |
| `Rubeus` | Windows | Kerberos ticket abuse — roasting, pass-the-ticket, overpass-the-hash |

---

## Kerberos Ticket Attacks

| Tool | Platform | Use |
|------|----------|-----|
| `ticketer.py` | Linux | Forge Golden/Silver tickets (Impacket) |
| `gettgtpkinit.py` | Linux | PKINIT — get TGT from certificate (PKINITtools) |
| `getnthash.py` | Linux | Get NT hash from TGT via U2U (PKINITtools) |
| `raiseChild.py` | Linux | Automated child→parent domain privilege escalation (Impacket) |

---

## Exploits

| Tool | Platform | CVE | Use |
|------|----------|-----|-----|
| `noPac.py` | Linux | CVE-2021-42278 + CVE-2021-42287 | Impersonate DA from standard user |
| `CVE-2021-1675.py` | Linux | CVE-2021-1675 | PrintNightmare — RCE via Print Spooler |
| `PetitPotam.py` | Linux | CVE-2021-36942 | Coerce Windows hosts to authenticate via MS-EFSRPC |
| `ntlmrelayx.py` | Linux | N/A | NTLM relay attacks (Impacket) |

---

## Quick Reference — Attack Phase to Tool

| Phase | Tools |
|-------|-------|
| **Unauthenticated recon** | `enum4linux`, `smbmap`, `rpcclient`, `kerbrute`, `responder` |
| **Authenticated enumeration** | `PowerView`, `bloodhound-python`, `ldapsearch`, `windapsearch`, `nxc` |
| **Credential attacks** | `GetNPUsers.py`, `GetUserSPNs.py`, `kerbrute`, `DomainPasswordSpray.ps1`, `hashcat` |
| **Lateral movement** | `psexec.py`, `wmiexec.py`, `evil-winrm`, `nxc -x` |
| **Credential extraction** | `mimikatz`, `secretsdump.py`, `lsassy` |
| **Kerberos abuse** | `Rubeus`, `ticketer.py`, `gettgtpkinit.py` |
| **Domain takeover** | `secretsdump.py` (DCSync), `noPac.py`, `PetitPotam.py` + `ntlmrelayx.py` |

---

## References

- Previous: [01-Introduction.md](01-Introduction.md)
- Next: [03-Enumeration_from_Linux.md](03-Enumeration_from_Linux.md)
