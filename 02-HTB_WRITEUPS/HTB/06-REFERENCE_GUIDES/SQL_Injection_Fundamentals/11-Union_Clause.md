# Section 11 — Union Clause

---

## How UNION Works

`UNION` stacks the rows from a second `SELECT` on top of the first and returns them as one combined table.

```sql
SELECT * FROM ports UNION SELECT * FROM ships;
-- Returns all rows from both tables stacked together
```

**Two rules that must be met:**
1. Both `SELECT` statements must return the **same number of columns**
2. The **data types** of matching columns must be compatible

---

## Padding Columns for Mismatched Tables

When the injected table has fewer columns than the original query, fill the gaps with literals:

```sql
-- Original query returns 4 columns, but you only want 1 from passwords:
UNION SELECT username, 2, 3, 4 FROM passwords-- -
```

- Numbers (`1`, `2`, `3`...) or `NULL` work as padding — they match any numeric/string column
- Use `NULL` for maximum compatibility (fits all data types)
- The padding values appear in the output — tracking their positions reveals which column renders on screen

---

## UNION Injection Pattern

```sql
-- Original query:
SELECT * FROM products WHERE product_id = 'user_input'

-- Injected:
SELECT * FROM products WHERE product_id = '1' UNION SELECT username, password FROM passwords-- '
```

The second `SELECT` can read from any table you choose — including the built-in `information_schema` database that holds metadata about every table and column on the server.

---

## Lab — UNION of employees and departments

**Objective:** Find the total record count when all rows from `employees` and `departments` are combined with UNION.

**Reasoning:**
- `employees` has 6 columns; `departments` has 2 — must pad departments with 4 junk values
- Wrap the UNION in a subquery and use `COUNT(*)` to get a single number
- Data type compatibility: `dept_no` (char) and `dept_name` (varchar) go in the first two positions; numbers fill the remaining 4

```bash
mysql -u root -ppassword -h TARGET_IP -P TARGET_PORT --skip-ssl \
  -e "USE employees;
      SELECT COUNT(*) FROM (
        SELECT * FROM employees
        UNION
        SELECT dept_no, dept_name, 3, 4, 5, 6 FROM departments
      ) AS combined_result;"
```
> Counts total rows across both tables combined via UNION. The `departments` table has only 2 columns, so literals `3, 4, 5, 6` pad it to match `employees`'s 6 columns. The outer `SELECT COUNT(*)` wraps the UNION in a subquery to return a single number. Replace `TARGET_IP` and `TARGET_PORT` with your target's values.

**employees columns (6):** `emp_no, birth_date, first_name, last_name, gender, hire_date`  
**departments columns (2):** `dept_no, dept_name` → padded to 6 with `3, 4, 5, 6`

**Result:**
```
COUNT(*)
663
```

**Q1 Answer:** `663`

---

## Exam Notes

- Column count must match exactly — one mismatch → `ERROR 1222: different number of columns`
- Use `NULL` as padding in real injections — it fits all column types without causing type mismatch errors
- UNION is In-Band — output appears directly in the response; you need a column that renders on the page
- The next step after confirming UNION works: determine which column positions are visible in the output (covered in Section 12)
- `information_schema.tables` and `information_schema.columns` are the key targets for enumerating the whole database schema via UNION
