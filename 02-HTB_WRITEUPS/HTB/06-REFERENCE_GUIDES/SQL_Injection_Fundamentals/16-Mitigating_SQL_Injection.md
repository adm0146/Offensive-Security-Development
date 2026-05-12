# Section 16 — Mitigating SQL Injection

> Theory only. No lab.

---

## 1 — Input Sanitization

Escape special characters before embedding user input in a query:

```php
// Vulnerable
$username = $_POST['username'];
$query = "SELECT * FROM logins WHERE username='$username'";

// Fixed — mysqli_real_escape_string() escapes ' and "
$username = mysqli_real_escape_string($conn, $_POST['username']);
$query = "SELECT * FROM logins WHERE username='$username'";
```

| DB | Escape function |
|----|----------------|
| MySQL/MariaDB | `mysqli_real_escape_string()` |
| PostgreSQL | `pg_escape_string()` |

> Escaping makes injected quotes literal characters — they can no longer break out of the string context.

---

## 2 — Input Validation (Allowlisting)

Reject anything that doesn't match expected format before it ever reaches the query:

```php
$pattern = "/^[A-Za-z\s]+$/";   // only letters and spaces
$code = $_GET["port_code"];

if (!preg_match($pattern, $code)) {
    die("Invalid input!");
}
// $code is now safe to use
```

> Allowlist (only permit known-good characters) is stronger than denylist (block known-bad). `'`, `"`, `-`, `;` in a denylist can be bypassed with encoding — an allowlist rejects everything not explicitly permitted.

---

## 3 — Parameterized Queries (Prepared Statements)

The gold standard — user input is **never interpreted as SQL**:

```php
// Vulnerable — string concatenation
$query = "SELECT * FROM logins WHERE username='$username' AND password='$password'";

// Fixed — placeholders bound separately from query structure
$query = "SELECT * FROM logins WHERE username=? AND password=?";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, 'ss', $username, $password);   // 'ss' = two strings
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
```

- The `?` placeholders are filled after query parsing — the DB engine never sees user input as SQL syntax
- Works the same in Python (psycopg2), Java (PreparedStatement), C# (SqlCommand with Parameters), etc.

---

## 4 — Least-Privilege DB Users

Never run web apps as root or a DBA. Create a dedicated user with only the permissions the app needs:

```sql
CREATE USER 'reader'@'localhost';
GRANT SELECT ON ilfreight.ports TO 'reader'@'localhost' IDENTIFIED BY 'p@ssw0Rd!!';
```

Result: even if injection succeeds, the attacker can only `SELECT` from `ports`. No `FILE`, no `DROP`, no cross-database reads.

---

## 5 — Web Application Firewall (WAF)

Blocks requests containing known SQLi patterns before they reach the app:

| Type | Examples |
|------|---------|
| Open-source | ModSecurity (Apache/Nginx) |
| Cloud/Premium | Cloudflare, AWS WAF, Imperva |

Default rules block strings like `INFORMATION_SCHEMA`, `UNION SELECT`, `OR 1=1`, etc.

> WAF is a last line of defense — it can be bypassed (obfuscation, encoding, fragmentation). Fix the code first; WAF is a supplement, not a replacement.

---

## Defense Priority

| Layer | Stops what |
|-------|-----------|
| Parameterized queries | Injection at the query level — most effective |
| Input validation | Malformed/unexpected input before it reaches the DB |
| Input sanitization | Escapes special chars — weaker than parameterized |
| Least privilege | Limits blast radius if injection succeeds |
| WAF | Catches common patterns — bypassable, last resort |

---

## Exam Notes

- On the CPTS exam, understanding mitigations is tested conceptually — know which defense stops which attack
- Parameterized queries are the only defense that fully prevents injection regardless of input content
- `mysqli_real_escape_string()` can be bypassed in edge cases (charset attacks, numeric contexts) — don't rely on it alone
- A read-only DB user stops file read/write, data exfil from other tables, and DROP attacks — even if injection is present
