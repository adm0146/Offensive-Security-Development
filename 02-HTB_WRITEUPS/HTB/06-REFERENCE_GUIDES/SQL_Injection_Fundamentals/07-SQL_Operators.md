# Section 7 — SQL Operators

---

## Logical Operators

| Operator | Symbol | Returns true when... |
|----------|--------|----------------------|
| `AND` | `&&` | Both conditions are true |
| `OR` | `\|\|` | At least one condition is true |
| `NOT` | `!` | Condition is false (inverts result) |

```sql
-- AND — both must be true
SELECT * FROM logins WHERE username != 'john' AND id > 1;

-- NOT — excludes a match
SELECT * FROM logins WHERE username != 'john';

-- OR — either condition satisfied
SELECT COUNT(*) FROM titles WHERE emp_no > 10000 OR title NOT LIKE '%engineer%';
```

> In MySQL, `1` = true, `0` = false. Any non-zero value is truthy.

---

## Operator Precedence (high → low)

| Priority | Operators |
|----------|-----------|
| 1 | `*` `/` `%` |
| 2 | `+` `-` |
| 3 | `=` `>` `<` `<=` `>=` `!=` `LIKE` |
| 4 | `NOT` (`!`) |
| 5 | `AND` (`&&`) |
| 6 | `OR` (`\|\|`) |

**Example — precedence in action:**
```sql
SELECT * FROM logins WHERE username != 'tom' AND id > 3 - 2;
-- Step 1: 3 - 2 = 1  (subtraction first)
-- Step 2: username != 'tom' AND id > 1  (comparisons, then AND)
```

> `AND` binds tighter than `OR` — `A OR B AND C` is evaluated as `A OR (B AND C)`. Use parentheses to force order when mixing them.

---

## SQLi Relevance

- `OR 1=1` is the classic injection — `OR` with an always-true condition makes the whole `WHERE` clause true, returning all rows
- `AND 1=2` forces false — used to suppress normal results in UNION injection setup
- `NOT LIKE '%pattern%'` inverts a pattern match — useful for filtering out noise when enumerating

---

## Lab — Query the titles Table

**Objective:** Count records where `emp_no > 10000` OR title does NOT contain 'engineer'.

**Reasoning:**
- `emp_no > 10000` — numeric comparison, no quotes needed
- `NOT LIKE '%engineer%'` — `%` wildcards on both sides match any position; `NOT` inverts to find non-engineer titles
- `OR` — returns rows satisfying either condition (much broader than AND)
- `COUNT(*)` — returns total matching row count, not the rows themselves

```bash
mysql -u root -ppassword -h TARGET_IP -P TARGET_PORT --skip-ssl \
  -e "USE employees; SELECT COUNT(*) FROM titles WHERE emp_no > 10000 OR title NOT LIKE '%engineer%';"
```

**Result:**
```
COUNT(*)
654
```

**Q1 Answer:** `654`

---

## Exam Notes

- `OR` in a `WHERE` clause is the backbone of auth bypass SQLi (`' OR 1=1 --`)
- `AND` with a false condition (`AND 1=2`) zeroes out the original query — used to isolate UNION results
- Operator precedence matters when injecting — `OR` has lower precedence than `AND`, so `A AND B OR C` = `(A AND B) OR C`
- `NOT LIKE` with `%` wildcards negates pattern matching — useful in enumeration queries
