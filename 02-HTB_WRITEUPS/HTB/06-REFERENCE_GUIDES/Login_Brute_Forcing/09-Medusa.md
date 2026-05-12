# Section 9 — Medusa

> Reference only. No lab.

---

## What Is Medusa?

Fast, massively parallel, modular login brute-forcer. Alternative to Hydra — same job, different syntax. Pre-installed on Kali.

```bash
medusa -h    # verify installed
```

---

## Syntax

```bash
medusa [target_options] [credential_options] -M MODULE [module_options]
```

---

## Key Flags

| Flag | Purpose | Example |
|------|---------|---------|
| `-h HOST` | Single target | `-h 192.168.1.10` |
| `-H FILE` | Target list | `-H targets.txt` |
| `-u USERNAME` | Single username | `-u admin` |
| `-U FILE` | Username list | `-U usernames.txt` |
| `-p PASSWORD` | Single password | `-p password123` |
| `-P FILE` | Password list | `-P passwords.txt` |
| `-M MODULE` | Module to use | `-M ssh` |
| `-m "OPTIONS"` | Module-specific options | `-m "POST /login"` |
| `-t TASKS` | Parallel threads | `-t 10` |
| `-f` | Stop on first valid login (current host) | `-f` |
| `-F` | Stop on first valid login (any host) | `-F` |
| `-n PORT` | Non-default port | `-n 2222` |
| `-v LEVEL` | Verbosity 0–6 | `-v 4` |
| `-e ns` | Try empty password (`n`) and user=pass (`s`) | `-e ns` |

---

## Supported Modules

| Module | Protocol | Example |
|--------|----------|---------|
| `ssh` | SSH | `medusa -M ssh -h TARGET -U users.txt -P pass.txt` |
| `ftp` | FTP | `medusa -M ftp -h TARGET -u admin -P pass.txt` |
| `rdp` | RDP | `medusa -M rdp -h TARGET -u admin -P pass.txt` |
| `http` | HTTP Basic Auth | `medusa -M http -h TARGET -U users.txt -P pass.txt -m GET` |
| `web-form` | Web login form | `medusa -M web-form -h TARGET -U users.txt -P pass.txt -m "FORM:username=^USER^&password=^PASS^:F=Invalid"` |
| `mysql` | MySQL | `medusa -M mysql -h TARGET -u root -P pass.txt` |
| `imap` | IMAP | `medusa -M imap -h mail.server -U users.txt -P pass.txt` |
| `pop3` | POP3 | `medusa -M pop3 -h mail.server -U users.txt -P pass.txt` |
| `telnet` | Telnet | `medusa -M telnet -h TARGET -u admin -P pass.txt` |
| `vnc` | VNC (no username) | `medusa -M vnc -h TARGET -P pass.txt` |
| `svn` | Subversion | `medusa -M svn -h TARGET -u admin -P pass.txt` |

---

## Command Examples

### SSH brute force
```bash
medusa -h 192.168.0.100 -U usernames.txt -P passwords.txt -M ssh -f
```

### Multiple web servers (Basic Auth)
```bash
medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET -F
```

### Check empty passwords and user=pass
```bash
medusa -h 10.0.0.5 -U usernames.txt -e ns -M ssh -f
```

### Web login form
```bash
medusa -M web-form -h TARGET -U users.txt -P pass.txt \
  -m "FORM:username=^USER^&password=^PASS^:F=Invalid credentials" -f
```

---

## Hydra vs Medusa

| Feature | Hydra | Medusa |
|---------|-------|--------|
| Speed | Fast | Fast (parallel by design) |
| Web form syntax | `http-post-form "path:params:condition"` | `-m "FORM:params:condition"` |
| Multi-host | `-M targets.txt` | `-H targets.txt` |
| Stop on success | `-f` | `-f` (host) / `-F` (any host) |
| Empty/default cred check | Manual | Built-in `-e ns` |

> **Preference:** Hydra is more commonly used in this module. Medusa is a drop-in alternative — same concepts, slightly different syntax.

---

## Exam Notes

- `-e ns` is a quick win before running a full wordlist — always check empty passwords and user=pass first
- `-F` stops the entire attack when *any* host succeeds — use `-f` if you want to keep going on other hosts
- Web form module syntax mirrors Hydra but uses `-m "FORM:..."` instead of the inline string format
- Both tools are available on Kali — if one hangs or misbehaves, swap to the other
