# Section 1 — SQLMap Overview

> Theory only. No lab.

---

## What is SQLMap

Open-source penetration testing tool that automates detection and exploitation of SQL injection flaws. Written in Python.

```bash
# Install
sudo apt install sqlmap          # Kali — already installed
git clone https://github.com/sqlmapproject/sqlmap.git   # latest from source
python3 sqlmap.py --version
```

---

## Supported Databases

MySQL, Oracle, PostgreSQL, MSSQL, SQLite, Access, IBM DB2, Firebird, Sybase, SAP MaxDB, Informix, MariaDB, HSQLDB, CockroachDB, TiDB, MemSQL, H2, MonetDB, Apache Derby, Amazon Redshift, Vertica, Mckoi, Presto, Altibase, MimerSQL, CrateDB, Greenplum, Drizzle, Apache Ignite, Cubrid, InterSystems Cache, IRIS, eXtremeDB, FrontBase

---

## Injection Types (BEUSTQ)

| Letter | Type | Speed | Notes |
|--------|------|-------|-------|
| B | Boolean-based blind | Slow | 7+ requests/char; true/false discrimination |
| E | Error-based | Fast | Error message leaks data inline |
| U | Union query-based | Fastest | Full rows returned in direct output |
| S | Stacked queries | Variable | Multiple statements; DB/config dependent |
| T | Time-based blind | Slowest | SLEEP()/WAITFOR — 1 request/char |
| Q | Inline queries | Varies | Subquery embedded in original query |

> UNION is the fastest — entire rows returned in a single request. Always test for UNION first.
> Time-based is the last resort — use `-technique=T` only when nothing else works.

---

## Exam Notes

- Q1: Fastest SQLi type = **UNION query-based**
- When sqlmap defaults to time-based, force UNION with `--technique=U`
- The BEUSTQ letters match sqlmap's `--technique` flag values exactly
