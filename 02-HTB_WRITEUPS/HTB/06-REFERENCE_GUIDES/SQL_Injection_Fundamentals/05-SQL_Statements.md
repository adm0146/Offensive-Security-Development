# Section 5 — SQL Statements

---

## INSERT — Add Records

```sql
-- Insert into all columns (must match order)
INSERT INTO logins VALUES(1, 'admin', 'p@ssw0rd', '2020-07-02');

-- Insert into specific columns (skip AUTO_INCREMENT and DEFAULT columns)
INSERT INTO logins(username, password) VALUES('administrator', 'adm1n_p@ss');

-- Insert multiple records at once
INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');
```

> Skipping a `NOT NULL` column that has no default value will cause an error.

---

## SELECT — Retrieve Records

```sql
-- All columns, all rows
SELECT * FROM logins;

-- Specific columns only
SELECT username, password FROM logins;

-- With condition
SELECT * FROM logins WHERE id = 1;
```

---

## DROP — Delete Tables/Databases

```sql
DROP TABLE logins;       -- permanently deletes the table, no confirmation
DROP DATABASE users;
```

> `DROP` is **irreversible** — there is no confirmation prompt and no undo.

---

## ALTER — Modify Table Structure

```sql
ALTER TABLE logins ADD newColumn INT;                        -- add column
ALTER TABLE logins RENAME COLUMN newColumn TO newerColumn;  -- rename column
ALTER TABLE logins MODIFY newerColumn DATE;                  -- change data type
ALTER TABLE logins DROP newerColumn;                         -- remove column
```

---

## UPDATE — Modify Records

```sql
UPDATE logins SET password = 'change_password' WHERE id > 1;
```

> Always include a `WHERE` clause with `UPDATE`. Without it, every single row in the table gets changed.

---

## Lab — Query the employees Database

**Objective:** Find the department number for the 'Development' department.

```bash
mysql -u root -ppassword -h TARGET_IP -P TARGET_PORT --skip-ssl \
  -e "USE employees; SELECT * FROM departments WHERE dept_name = 'Development';"
```
> Queries the `departments` table for a specific department name. `-e` runs the SQL and exits. Two statements are chained: `USE` selects the database, `SELECT` retrieves the matching row. Replace `TARGET_IP` and `TARGET_PORT` with your target's values.

**Result:**
```
dept_no | dept_name
d005    | Development
```

**Q1 Answer:** `d005`

---

## Exam Notes

- `SELECT *` is used constantly in SQLi — it dumps everything from a table
- `WHERE` conditions control which rows are affected by `UPDATE`/`SELECT`/`DELETE`
- `DROP` is destructive and permanent — relevant when you have write access via SQLi
- Column order matters for `INSERT INTO table VALUES(...)` — use named columns to be safe
