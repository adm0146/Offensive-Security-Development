# Section 24 — Kerberos "Double Hop" Problem

> No lab questions. Concept + two workarounds for when WinRM blocks lateral movement.

---

## QUICK REFERENCE

```powershell
# Check if you have the double hop problem
klist
# Only 1 ticket cached (HTTP/WinRM service ticket) = double hop problem
# 4+ tickets cached (TGT present) = no problem, creds in memory

# Workaround 1 — PSCredential (works from evil-winrm)
$SecPassword = ConvertTo-SecureString 'PASSWORD' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\user', $SecPassword)
Get-DomainUser -spn -Credential $Cred | select samaccountname

# Workaround 2 — Register PSSession config (requires GUI/RDP, NOT evil-winrm)
# Run from attack host or jump box (not from evil-winrm shell):
Register-PSSessionConfiguration -Name mysess -RunAsCredential DOMAIN\user
Restart-Service WinRM   # kicks you out — reconnect with new config
Enter-PSSession -ComputerName TARGET -Credential DOMAIN\user -ConfigurationName mysess
# Now klist shows TGT — no double hop, PowerView works without -Credential
```

---

## What is the Double Hop Problem?

**The scenario:** Attack Host → Host A (WinRM) → Host B (DC/file share)

When you connect to Host A via WinRM/evil-winrm, Kerberos issues a **TGS ticket** for the WinRM service on Host A. Your **TGT is not forwarded** to Host A. When you try to reach Host B from Host A, there's no TGT in the session to prove your identity — access denied.

**Contrast with SMB/PSExec:** Password-based auth stores the NTLM hash in memory. Hash gets reused automatically for second-hop connections — no double hop issue.

**Contrast with RDP:** Full interactive login caches the TGT in memory. `klist` shows 4+ tickets including `krbtgt/DOMAIN`. Second-hop connections work fine.

```
WinRM session  → klist shows:  1 ticket (HTTP/WinRM service only)  → double hop blocked
RDP session    → klist shows:  4 tickets (TGT + CIFS + etc.)       → double hop works
```

---

## How to Identify It

```powershell
# Run this from inside your WinRM session
klist

# Double hop problem present — only WinRM service ticket:
#   Server: HTTP/ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL
#   Cache Flags: 0x8 -> ASC

# No problem (RDP/interactive session) — TGT present:
#   Server: krbtgt/INLANEFREIGHT.LOCAL
#   Cache Flags: 0x1 -> PRIMARY
```

**Symptom when it hits you:**
```
Exception calling "FindAll" with "0" argument(s): "An operations error occurred."
```
This error from PowerView = you hit the double hop wall. Your creds can't reach the DC.

---

## Workaround 1 — PSCredential Object

**Works with:** evil-winrm, Enter-PSSession, any WinRM session  
**Requirement:** You know the plaintext password  
**Downside:** Must pass `-Credential $Cred` to every single command

```powershell
# Inside your evil-winrm or WinRM session:
$SecPassword = ConvertTo-SecureString 'PASSWORD' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\backupadm', $SecPassword)

# Now pass -Credential $Cred to every PowerView command
Get-DomainUser -spn -Credential $Cred | select samaccountname
Get-DomainObjectACL -ResolveGUIDs -Identity * -Credential $Cred | ? {$_.SecurityIdentifier -eq $sid}
```
- Creates a credential object in memory that you manually pass with each request
- Forces Kerberos to authenticate to the DC using those creds on each call
- Tedious but works reliably from any WinRM session including evil-winrm

---

## Workaround 2 — Register PSSession Configuration

**Works with:** Enter-PSSession from Windows attack host or jump box, RDP  
**Does NOT work with:** evil-winrm (can't get credential popup, RunAs requires elevated PS)  
**Advantage:** Set it up once — then run all commands without `-Credential` flag

```powershell
# Step 1 — From your Windows attack host (NOT inside evil-winrm), register a named config
Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential INLANEFREIGHT\backupadm
# Enter password when prompted

# Step 2 — Restart WinRM to apply (kicks out current sessions)
Restart-Service WinRM

# Step 3 — Connect using the named config
Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName backupadmsess

# Step 4 — Verify TGT is now cached
klist
# Should show: Server: krbtgt/INLANEFREIGHT.LOCAL — TGT is present

# Step 5 — PowerView works without -Credential now
Get-DomainUser -spn | select samaccountname
```
- `Register-PSSessionConfiguration` creates a session endpoint that impersonates the specified user
- The local machine forwards credentials on behalf of the user — TGT gets cached on the remote host
- Eliminates double hop for the entire session — no per-command credential flag needed

---

## Which Workaround to Use

| Situation | Use |
|-----------|-----|
| Came in via evil-winrm | Workaround 1 (PSCredential) — pass `-Credential $Cred` to every command |
| Have GUI/RDP access to a Windows attack host | Workaround 2 (Register-PSSessionConfiguration) — cleaner |
| Testing from Linux with Enter-PSSession | Workaround 1 — PSSession config has issues on Linux Kerberos |
| Unconstrained delegation on target host | Neither needed — TGT forwarded automatically |

---

## Why RDP Doesn't Have This Problem

RDP = interactive logon. Windows caches the full TGT in LSASS memory. Every outbound connection from that session can use the cached TGT to request new TGS tickets for other resources. This is why `klist` shows 4 tickets after RDP vs 1 after WinRM.

---

## Exam Notes

- Double hop = WinRM session only gets TGS (service ticket), TGT never forwarded
- Symptom: PowerView "An operations error occurred" when querying DC from WinRM shell
- `klist` = instant diagnosis — 1 ticket = double hop problem, TGT present = no problem
- Workaround 1 (PSCredential) = always works, requires plaintext password, must pass to every command
- Workaround 2 (Register-PSSessionConfiguration) = cleaner, requires GUI access, won't work from evil-winrm
- Unconstrained delegation on target = no double hop (TGT forwarded) — but if you're there, you've already won
- Other methods exist (CredSSP, port forwarding, process injection) but PSCredential covers most exam scenarios
