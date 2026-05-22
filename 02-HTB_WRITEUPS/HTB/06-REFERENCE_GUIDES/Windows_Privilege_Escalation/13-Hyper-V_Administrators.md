# Section 13 — Hyper-V Administrators

> **Lab: no** — concepts only. Two attack paths: VM cloning for DC takeover, and hard link abuse for SYSTEM.

**Core principle:** Hyper-V Administrators have full control over all virtual machines. If a Domain Controller is virtualized (very common), this group effectively equals Domain Admin — they can clone the DC, mount the disk offline, and extract all domain hashes. A second, more niche attack abuses how `vmms.exe` restores file permissions as SYSTEM to escalate locally via hard links.

---

## Attack path 1: Virtualized Domain Controller (primary threat)

```
Hyper-V Administrators membership
│
├── Clone the live Domain Controller VM
│   └── Mount the .vhdx virtual disk offline
│       └── Extract NTDS.dit + SYSTEM hive
│           └── secretsdump.py -ntds NTDS.dit -system SYSTEM LOCAL
│               └── Full domain hash dump — every user, every account
│
└── Result: equivalent to Domain Admin
    ├── Pass-the-Hash as any user
    ├── DCSync without needing network access
    └── Golden ticket creation
```

> **Why this matters:** Many organizations virtualize DCs on Hyper-V. IT staff granted "Hyper-V admin" for VM management can silently compromise the entire domain without ever touching the DC directly.

### How to extract hashes from an offline DC disk

```bash
# After mounting the cloned .vhdx and copying out the files:
secretsdump.py -ntds /path/to/NTDS.dit -system /path/to/SYSTEM LOCAL
```
> Runs Impacket's secretsdump against the offline database files. No network access or DC authentication needed — just the raw files from the virtual disk.

---

## Attack path 2: Hard link abuse via vmms.exe (local SYSTEM escalation)

This path works when you're a Hyper-V Admin on a **non-DC** host and want local SYSTEM.

### How it works

```
1. Hyper-V Administrators member deletes a .vhdx file belonging to a VM
2. vmms.exe (Virtual Machine Management Service) tries to restore
   original file permissions on the now-deleted .vhdx path
3. vmms.exe does this as NT AUTHORITY\SYSTEM without impersonating the user
4. Attacker creates a native hard link: deleted .vhdx path → protected SYSTEM file
5. vmms.exe grants attacker full permissions on the hard-linked target
6. Attacker now owns a SYSTEM-protected file
```

### Exploitation via Mozilla Maintenance Service

Firefox installs `Mozilla Maintenance Service` which runs as SYSTEM and is startable by unprivileged users — a perfect target.

**Step 1: Use the hard link exploit to gain full permissions on the service binary**

Target file:
```
C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```
> Run a modified NT hard link PoC script to redirect the vmms.exe permission restore to this file. After execution, your user has full control over the binary.

**Step 2: Take ownership**

```cmd
takeown /F "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```
> Formally takes ownership of the file so you can replace it. This works because the hard link exploit already granted you full permissions.

**Step 3: Replace with malicious binary**

Replace `maintenanceservice.exe` with a payload (reverse shell, msfvenom exe, or a binary that adds you to local admins).

**Step 4: Start the service**

```cmd
sc.exe start MozillaMaintenance
```
> The service runs as SYSTEM and executes your malicious binary. Use `sc.exe` not `sc` in PowerShell.

---

## Prerequisites and limitations

| Requirement | Details |
|-------------|---------|
| Hyper-V Administrators membership | Required for both attack paths |
| Virtualized DC (path 1) | DC must be a Hyper-V VM on a host you control |
| Vulnerable OS (path 2) | CVE-2018-0952 or CVE-2019-0841, OR a SYSTEM service startable by unprivileged users |
| **Patched after March 2020** | Hard link behavior was fixed in March 2020 security updates — path 2 no longer works on patched systems |

---

## Attack decision tree

```
Hyper-V Administrators member
│
├── Is a Domain Controller virtualized on this Hyper-V host?
│   ├── YES → Clone DC → mount .vhdx → extract NTDS.dit → full domain compromise
│   └── NO ↓
│
├── Is the OS unpatched (pre-March 2020)?
│   ├── YES → Hard link abuse via vmms.exe
│   │   └── Find a SYSTEM service startable by low-priv users
│   │       ├── Mozilla Maintenance Service (Firefox installed)
│   │       ├── Google Update Service
│   │       └── Any third-party service running as SYSTEM
│   └── NO → Hard link vector is patched
│       └── Look for other escalation paths (different group membership, misconfigs)
│
└── CVE-2018-0952 or CVE-2019-0841 present?
    ├── YES → Exploit directly for SYSTEM
    └── NO → Hard link path requires alternative SYSTEM service
```

---

## Key takeaways

- **Hyper-V Admins on a virtualized DC = Domain Admin.** This is the most impactful path — no exploits needed, just VM management features working as designed.
- **Always check if DCs are virtualized during AD enumeration.** If you land on a Hyper-V host, check what VMs it runs.
- **The hard link attack (path 2) is patched since March 2020.** Still worth knowing for legacy environments, but don't rely on it for modern targets.
- **The hard link technique needs a SYSTEM service startable by unprivileged users.** Mozilla Maintenance Service is the classic example, but any similarly configured service works.
- **Use `sc.exe` not `sc` in PowerShell** when starting services.
