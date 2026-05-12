# Section 3 — SQLMap Output Description

> Theory only. No lab.

---

## Key Log Messages Reference

| Message | Meaning |
|---------|---------|
| `target URL content is stable` | Responses are consistent — good baseline for diff detection |
| `GET parameter 'id' appears to be dynamic` | Parameter affects response → likely DB-linked, worth testing |
| `heuristic (basic) test shows ... might be injectable` | DBMS error triggered by invalid input — not confirmed yet, just heuristic |
| `heuristic (XSS) test shows ... might be vulnerable to XSS` | Bonus XSS probe — not sqlmap's main purpose but it checks |
| `it looks like the back-end DBMS is 'MySQL'` | Detected DBMS — say Y to skip other-DBMS payloads and save time |
| `extending provided level (1) and risk (1) values` | With confirmed DBMS, sqlmap offers to run full MySQL payload set |
| `reflective value(s) found and filtering out` | Payload appears in response — sqlmap filters it to avoid false positives |
| `appears to be injectable (with --string="luther")` | Constant string found in TRUE responses → clean boolean discrimination, low false-positive risk |
| `time-based comparison requires a larger statistical model` | Collecting baseline latency samples before timing attacks can be reliable |
| `automatically extending ranges for UNION query injection technique tests` | Another technique already found → sqlmap increases UNION check budget |
| `ORDER BY technique appears to be usable` | Can binary-search for column count instead of brute-forcing — faster UNION detection |
| `GET parameter 'id' is vulnerable. Do you want to keep testing?` | First confirmed injectable param — say N to stop here unless full audit needed |
| `sqlmap identified the following injection point(s) with a total of N HTTP(s) requests:` | Final summary — lists only provably exploitable findings |
| `fetched data logged to text files under '~/.sqlmap/output/<host>'` | Session saved — subsequent runs reuse this data to minimize requests |

---

## Important Behaviors to Know

**Static parameter** → `does not appear to be dynamic` → sqlmap won't find SQLi because the value doesn't affect output. Move on.

**`--string` anchor**: When sqlmap finds a constant string that appears in all TRUE responses and not in FALSE, it uses that as the discrimination signal. This is more reliable than fuzzy response comparison — if you see `--string="..."` in the detection message, the boolean blind result is trustworthy.

**Session files**: `~/.sqlmap/output/<host>/session.sqlite` — sqlmap reads this on re-run to skip re-detection and jump straight to exploitation. Delete it to force a fresh scan.

**UNION extension**: sqlmap caps UNION probes at 10 requests per parameter by default (expensive). Once any other technique is confirmed, it removes that cap and does a full UNION search.

---

## Exam Notes

- "reflective values found" is noise — sqlmap handles it automatically, no action needed
- When asked "skip payloads for other DBMSes?" → always Y if you already know the target DB
- When asked "keep testing others?" → N unless you're writing a full pentest report
- Session files mean re-running sqlmap on the same target is fast — it won't re-probe confirmed injection points
