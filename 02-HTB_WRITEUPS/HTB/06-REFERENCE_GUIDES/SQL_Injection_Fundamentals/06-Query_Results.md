# Section 6 — Query Results

---

## ORDER BY — Sort Results

```sql
-- Sort ascending (default)
SELECT * FROM logins ORDER BY password;

-- Sort descending
SELECT * FROM logins ORDER BY password DESC;

-- Multi-column sort (secondary sort breaks ties in first column)
SELECT * FROM logins ORDER BY password DESC, id ASC;
```

> Default sort is `ASC`. Multi-column sort is useful when multiple rows share the same value in the first sort column.

---

## LIMIT — Control Result Count

```sql
-- Return first 2 rows
SELECT * FROM logins LIMIT 2;

-- Return 2 rows starting at offset 1 (skips first row, 0-indexed)
SELECT * FROM logins LIMIT 1, 2;
```

> `LIMIT offset, count` — offset is 0-indexed. `LIMIT 1, 2` skips the first record and returns the next two.

---

## WHERE — Filter Rows

```sql
-- Numeric comparison
SELECT * FROM logins WHERE id > 1;

-- String match (exact, case-insensitive in MySQL by default)
SELECT * FROM logins WHERE username = 'admin';
```

> Strings and dates need quotes (`'` or `"`). Numbers do not.

---

## LIKE — Pattern Matching

```sql
-- % matches zero or more characters (prefix wildcard)
SELECT * FROM logins WHERE username LIKE 'admin%';   -- admin, administrator, etc.

-- _ matches exactly one character
SELECT * FROM logins WHERE username LIKE '___';       -- exactly 3-char names (e.g. tom)
```

| Wildcard | Matches |
|----------|---------|
| `%` | Zero or more characters |
| `_` | Exactly one character |

> `LIKE` is key in SQLi — used in `WHERE` clauses that can be manipulated via injection. `%` is the go-to wildcard for dumping broad result sets.

---

## Combining Conditions

```sql
-- AND — both conditions must be true
SELECT * FROM employees WHERE first_name LIKE 'Bar%' AND hire_date = '1990-01-01';
```

---

## Lab — Query the employees Database

**Objective:** Find the last name of the employee whose first name starts with "Bar" AND was hired on 1990-01-01.

**Reasoning:**
- Filter on `first_name` using `LIKE 'Bar%'` — wildcard matches any name beginning with "Bar"
- Filter on `hire_date` with exact match `= '1990-01-01'` — date strings need quotes
- `AND` combines both conditions — both must be true to return a row

```bash
mysql -u root -ppassword -h TARGET_IP -P TARGET_PORT --skip-ssl \
  -e "USE employees; SELECT * FROM employees WHERE first_name LIKE 'Bar%' AND hire_date = '1990-01-01';"
```

**Result:**
```
emp_no | first_name | last_name | hire_date
10227  | Barton     | Mitchem   | 1990-01-01
```

**Q1 Answer:** `Mitchem`

---

## Exam Notes

- `ORDER BY` can sort on any column — useful in SQLi to infer column count and data types
- `LIMIT offset, count` lets you page through results — critical for data exfiltration in blind SQLi
- `WHERE` with `LIKE` and `%` is commonly injected to match any value (e.g. `' OR username LIKE '%`)
- `AND` / `OR` logic in `WHERE` clauses is the foundation of boolean-based injection
