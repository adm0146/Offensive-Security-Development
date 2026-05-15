# Section 3 — Types of Databases

> Theory only. No lab.

---

## Relational Databases (RDBMS)

A Relational Database Management System (RDBMS) stores data in **tables** made of rows and columns. Tables are linked to each other through keys.

**Example structure:**
```
users table:          posts table:
id | username         id | user_id | date    | content
1  | admin            1  | 1       | 01-2024 | Hello...
2  | jsmith           2  | 2       | 01-2024 | World...
```

- `posts.user_id` links to `users.id` — no need to repeat user data in every post row
- The full set of table relationships is called the **schema**
- Common examples: **MySQL**, MSSQL, PostgreSQL, Oracle, SQLite

> **This module focuses entirely on MySQL/RDBMS SQLi.**

---

## Non-Relational Databases (NoSQL)

NoSQL databases have no tables, no fixed schema, and no SQL (Structured Query Language). They store data as key-value pairs, documents, wide columns, or graphs.

| Model | Example DB | Data Format |
|-------|-----------|-------------|
| Key-Value | Redis | `{"key": "value"}` |
| Document | **MongoDB** | JSON/BSON documents |
| Wide-Column | Cassandra | Column families |
| Graph | Neo4j | Nodes + edges |

**Example (Key-Value / JSON):**
```json
{
  "100001": {"date": "01-01-2021", "content": "Welcome..."},
  "100002": {"date": "02-01-2021", "content": "First post..."}
}
```

---

## SQLi vs NoSQL Injection

| | SQL Injection | NoSQL Injection |
|-|--------------|-----------------|
| Target | MySQL, MSSQL, PostgreSQL, Oracle | MongoDB, Redis, CouchDB |
| Syntax | SQL (`' OR 1=1--`) | Operator injection (`$where`, `$gt`, etc.) |
| This module | ✅ | ❌ (covered in a later module) |

---

## Exam Notes

- Relational = SQL = tables/keys/schema = **this module**
- Non-relational = NoSQL = MongoDB = **different injection technique**
- Knowing the DB type before attacking matters — MySQL and MSSQL syntax differ slightly
- Schema knowledge (table names, column names) is the goal of enumeration in SQLi attacks
