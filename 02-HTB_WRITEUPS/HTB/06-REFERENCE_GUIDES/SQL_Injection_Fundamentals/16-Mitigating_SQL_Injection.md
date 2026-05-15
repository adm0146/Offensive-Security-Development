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

> An allowlist (only permit known-good characters) is stronger than a denylist (block known-bad). Characters like `'`, `"`, `-`, and `;` in a denylist can be bypassed with encoding or alternate representations. An allowlist rejects everything that isn't explicitly approved.

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

- The `?` placeholders are filled in after the query structure is already parsed. The database engine never treats the user's input as SQL syntax — it is always treated as data.
- The same pattern works in Python (psycopg2), Java (PreparedStatement), C# (SqlCommand with Parameters), and most other languages.

---

## 4 — Least-Privilege DB Users

Never run web apps as root or a DBA. Create a dedicated user with only the permissions the app needs:

```sql
CREATE USER 'reader'@'localhost';
GRANT SELECT ON ilfreight.ports TO 'reader'@'localhost' IDENTIFIED BY 'p@ssw0Rd!!';
```
> Creates a restricted DB user and grants only `SELECT` on a specific table. Even if SQLi succeeds against this user, the attacker cannot read other tables, write files, or execute OS commands. Replace the username, database, table, and password with your app's values.

Result: even if injection succeeds, the attacker can only `SELECT` from `ports`. No file access, no `DROP`, no reading from other databases.

---

## 5 — Web Application Firewall (WAF)

Blocks requests containing known SQLi patterns before they reach the app:

| Type | Examples |
|------|---------|
| Open-source | ModSecurity (Apache/Nginx) |
| Cloud/Premium | Cloudflare, AWS WAF, Imperva |

Default rules block strings like `INFORMATION_SCHEMA`, `UNION SELECT`, `OR 1=1`, etc.

> A WAF (Web Application Firewall) is a last line of defense. It can be bypassed with obfuscation, encoding, or fragmentation. Fix the code first. WAF is a supplement, not a replacement for proper input handling.

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
