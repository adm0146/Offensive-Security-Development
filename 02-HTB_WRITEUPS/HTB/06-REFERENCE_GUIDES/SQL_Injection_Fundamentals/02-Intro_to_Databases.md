# Section 2 — Intro to Databases

> Theory only. No lab.

---

## What is a DBMS?

A Database Management System (DBMS) hosts, manages, and provides access to databases. Web apps use them to store everything — user credentials, content, files, settings.

**Types of DBMS:**
| Type | Examples | Use Case |
|------|----------|----------|
| Relational (RDBMS) | MySQL, MSSQL, PostgreSQL, Oracle | Structured data, most web apps — **focus of this module** |
| NoSQL | MongoDB, Redis, CouchDB | Unstructured/flexible data |
| Key/Value | Redis, DynamoDB | Caching, sessions |
| Graph | Neo4j | Relationship-heavy data |

---

## Key DBMS Features

| Feature | Why It Matters for Pentesters |
|---------|-------------------------------|
| **Security** | Fine-grained user permissions — if DB user is over-privileged, SQLi impact is higher |
| **Concurrency** | Multiple users hit the DB simultaneously — injection still works under load |
| **SQL** | Standardized query language — SQLi syntax is portable across RDBMS types |

---

## Architecture (3-Tier Web App)

```
[User / Browser]          ← Tier 1: Client
        ↓
[Web App / API Server]    ← Tier 2: Middleware — builds SQL queries from user input
        ↓
[DBMS / Database]         ← Tier 3: Database — executes queries, returns data
```

**Why this matters for SQLi:**
- Tier 2 takes user input and constructs SQL queries
- If Tier 2 doesn't sanitize input, the user controls part of the query sent to Tier 3
- The DBMS just executes whatever query it receives — it doesn't know if it's malicious

---

## Exam Notes

- SQLi targets the **Tier 2 → Tier 3** boundary — the point where user input becomes a SQL query
- Over-privileged DB users (e.g., running as `root` or with `FILE` privilege) dramatically increase impact
- App server and DBMS can run on the same host — common in CTF/lab environments
