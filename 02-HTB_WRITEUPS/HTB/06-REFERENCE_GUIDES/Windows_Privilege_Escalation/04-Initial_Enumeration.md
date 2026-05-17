# Section 4 — Initial Enumeration

> **Lab: yes** — 5 questions against the same target (ACADEMY-WINLPE-SRV01).

**Core principle:** After landing on a Windows host, gather system info, user/group context, network listeners, and installed software *before* attempting any exploit. This phase tells you what you're working with and where the quick wins might be.

---

## Privilege escalation targets (in order of value)

| Target | Why |
|--------|-----|
| `NT AUTHORITY\SYSTEM` (LocalSystem) | More privileges than local admin, runs most services |
| Built-in `Administrator` | Full local control — often reused across hosts (gold image) |
| Any local Administrators group member | Same effective privileges as built-in admin |
| Domain user in local Admins | Bridges local → AD escalation |
| Domain Admin in local Admins | Full AD compromise from one host |

---

## System information

### Running processes & services

```cmd
tasklist /svc
```
> Maps PIDs to services. Look for: non-standard services (FileZilla, SQL, custom apps), services running as SYSTEM, and AV/EDR processes (MsMpEng.exe = Defender).

**What to spot:**
- Third-party services → version check → public exploits or misconfigs
- `lsass.exe` PID → needed for memory dumps later
- AV processes → know what you're up against

### Environment variables

```cmd
set
```
> Key things to check:
> - **PATH** — custom entries (Python, Java, app dirs)? If a writable dir is in PATH *before* System32, DLL hijacking is possible.
> - **HOMEDRIVE** — network share? Navigate it for password files, IT docs.
> - **USERPROFILE** — check `AppData\Microsoft\Windows\Start Menu\Programs\Startup` for persistence opportunities.
> - **LOGONSERVER** — confirms domain membership and which DC authenticated you.

### Detailed system info

```cmd
systeminfo
```
> Extract: OS version, build number, hotfixes installed, boot time, domain/workgroup, NIC info. Feed into WES-NG on your attacker box for exploit suggestions.

**Patch level indicators:**
- Few hotfixes + old boot time (>6 months) = likely unpatched = kernel exploits viable
- `Hyper-V Requirements: A hypervisor has been detected` = VM (no hardware access)

### Patches / hotfixes

```cmd
wmic qfe
```
```powershell
Get-HotFix | ft -AutoSize
```
> Cross-reference KB numbers with known exploits. Google "KB[number] exploit" or feed `systeminfo` output to WES-NG.

### Installed programs

```cmd
wmic product get name
```
```powershell
Get-WmiObject -Class Win32_Product | select Name, Version
```
> Look for: FileZilla, PuTTY, KeePass, browsers, SQL Server, Java, VNC — all have stored credential extraction paths. Run LaZagne against anything that stores creds.

---

## Network information

### Active connections & listening ports

```cmd
netstat -ano
```
> Maps ports to PIDs. Look for:
> - Services only listening on `127.0.0.1` (local-only = can't reach from outside, but exploitable now that you're on the host)
> - Non-standard ports (8080, 8443, 1433, 3306, etc.)
> - Cross-reference PID with `tasklist /svc` to identify the service

---

## User & group enumeration

### Who's logged in?

```cmd
query user
```
> Shows active/idle sessions. Important for: knowing if you'll be detected (active admin session), identifying targets for token impersonation.

### Current user context

```cmd
echo %USERNAME%
whoami /priv
whoami /groups
```
> **`whoami /priv`** — the most important single check. Look for:
> - `SeImpersonatePrivilege` → Potato attacks → SYSTEM
> - `SeBackupPrivilege` → read any file (SAM, NTDS.dit)
> - `SeDebugPrivilege` → inject into any process
> - `SeLoadDriverPrivilege` → load vulnerable kernel driver
> - `SeTakeOwnershipPrivilege` → own any object
>
> **`whoami /groups`** — check for privileged group membership (Backup Operators, DnsAdmins, etc.) and mandatory integrity level (Medium = standard user, High = admin).

### All users

```cmd
net user
```
> Look for: admin-sounding accounts (`bob_adm`, `svc_sql`, `helpdesk`), then check for credential reuse or group memberships.

### All groups

```cmd
net localgroup
```
> Non-default groups reveal the host's role (IIS = web server, SQL = database, Hyper-V = virtualization host).

### Group membership details

```cmd
net localgroup administrators
net localgroup "Backup Operators"
net localgroup "Remote Desktop Users"
net localgroup "Remote Management Users"
```
> Check who's in privileged groups. Non-admin users in Backup Operators or similar = privesc path.

### Password policy

```cmd
net accounts
```
> `Lockout threshold: Never` = safe to brute-force local accounts. `Minimum password length: 0` = weak passwords likely exist.

---

## Quick-reference enumeration block (copy-paste)

```cmd
:: System
systeminfo
tasklist /svc
set
wmic qfe
wmic product get name

:: Network
ipconfig /all
netstat -ano
arp -a
route print

:: Users & groups
echo %USERNAME%
whoami /priv
whoami /groups
query user
net user
net localgroup
net localgroup administrators
net localgroup "Backup Operators"
net accounts
```

---

## Lab walkthrough

**Target:** `10.129.43.43` (ACADEMY-WINLPE-SRV01)
**Creds:** `htb-student` / `HTB_@cademy_stdnt!`

### Question 1 — What non-default privilege does the htb-student user have?

```cmd
whoami /priv
```
> Default low-priv users only have `SeChangeNotifyPrivilege` and `SeIncreaseWorkingSetPrivilege`. Anything else listed is the answer (e.g., `SeShutdownPrivilege`, `SeImpersonatePrivilege`, etc.).

### Question 2 — Who is a member of the Backup Operators group?

```cmd
net localgroup "Backup Operators"
```

### Question 3 — What service is listening on port 8080 (service name not the executable)?

```cmd
netstat -ano | findstr 8080
```
> Note the PID, then:
```cmd
tasklist /svc /fi "PID eq <PID>"
```
> The service name column is the answer (not the .exe name).

### Question 4 — What user is logged in to the target host?

```cmd
query user
```

### Question 5 — What type of session does this user have?

```cmd
query user
```
> The SESSIONNAME column shows the session type (e.g., `rdp-tcp#X` = RDP, `console` = local console session).

---

## Lab observations & attack chain (WINLPE-SRV01)

**What we found:**
| Finding | Value | Significance |
|---------|-------|--------------|
| Non-default privilege | `SeTakeOwnershipPrivilege` | Can take ownership of ANY object (files, registry keys, AD objects) — leads to reading protected files or modifying service configs |
| Backup Operators member | `sarah` | If we can get sarah's creds, she can read ANY file on the system (SAM, NTDS.dit) via backup semantics |
| Service on port 8080 | `Tomcat8` (PID 2120) | Tomcat = potential WAR file deployment if we find manager creds, or check what user it runs as |
| Logged-in user | `sccm_svc` | Service account logged in at console — likely has SeImpersonate, may have cached creds |
| Session type | `console` | sccm_svc is at the physical/VM console, not RDP — this is a persistent service logon |

**Attack chain — multiple paths identified:**

```
Initial Enumeration findings:
│
├── Path 1: SeTakeOwnershipPrivilege (htb-student)
│   └── Take ownership of sensitive file/registry key
│       └── Read SAM hive or service account passwords
│           └── Escalate to admin/SYSTEM
│
├── Path 2: Credential hunting → sarah (Backup Operators)
│   └── Find sarah's password (reuse, config files, shares)
│       └── Use backup semantics to read SAM/SYSTEM hives
│           └── Extract local admin hash → full compromise
│
├── Path 3: Tomcat8 on 8080
│   └── Find Tomcat manager credentials (tomcat-users.xml)
│       └── Deploy WAR reverse shell
│           └── Shell as Tomcat service user (check privs)
│
└── Path 4: sccm_svc (console session)
    └── If we escalate, harvest this account's token/creds
        └── SCCM service accounts often have domain-wide access
            └── Lateral movement across managed systems
```

**Cross-section connections:**
- `SeTakeOwnershipPrivilege` → detailed exploitation in Windows User Privileges section
- `Backup Operators` (sarah) → detailed exploitation in Windows Group Privileges section
- `Tomcat8` → check SeImpersonate (Section 5, service accounts)
- `sccm_svc` at console → token impersonation target after privesc

---

## Key takeaways

- **`whoami /priv` is the Windows equivalent of `sudo -l`.** It's the single fastest indicator of whether you have an easy privesc path.
- **Cross-reference netstat PIDs with tasklist.** A service listening internally on a high port is invisible from outside — you can only exploit it from the host.
- **Environment variables leak info.** PATH hijacking, network home drives, and roaming profiles are all attack vectors hidden in `set` output.
- **Patch level = exploit surface.** Few KBs + old boot time = kernel exploits on the table. Many recent KBs = focus on misconfigs instead.
- **Users in privileged groups ≠ admin accounts.** A standard user in Backup Operators has dangerous capabilities that most people overlook.
