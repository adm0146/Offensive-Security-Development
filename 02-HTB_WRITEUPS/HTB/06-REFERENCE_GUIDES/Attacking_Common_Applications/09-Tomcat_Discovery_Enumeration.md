# Section 9 — Tomcat: Discovery & Enumeration

Apache Tomcat hosts Java-based apps (Servlets, JSP). Common on internal networks; often appears first in EyeWitness "High Value Targets." ~220k live instances. Default credentials are extremely common.

---

## Fingerprinting Tomcat

### Version signals
| Method | Command |
|--------|---------|
| Invalid URL → default error page | `curl -s http://target:8080/invalid` — shows "Apache Tomcat/X.Y.Z" |
| `/docs` page title | `curl -s http://target:8080/docs/ \| grep Tomcat` |
| `Server:` response header | `curl -I http://target:8080/` |

```bash
# Invalid page reveals version in default error page
curl -s http://target:8080/doesnotexist
# Apache Tomcat/9.0.30

# /docs page title
curl -s http://target:8080/docs/ | grep Tomcat
# <title>Apache Tomcat 9 (9.0.30) - Documentation Index</title>
```
> Fingerprints the Tomcat version via the default 404 error page and the /docs title; swap `target` and the port.

Custom error pages may suppress the version — try `/docs/` as fallback.

---

## Directory Structure

```
├── bin/                    startup scripts
├── conf/
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── tomcat-users.xml    ← credentials + roles for /manager and /host-manager
│   ├── tomcat-users.xsd
│   └── web.xml
├── lib/                    JAR files
├── logs/
├── temp/
├── webapps/                default webroot
│   ├── manager/
│   │   └── WEB-INF/web.xml
│   └── ROOT/
│       └── WEB-INF/
└── work/Catalina/localhost/
```

### Per-app structure under webapps/
```
webapps/customapp/
├── index.jsp
├── META-INF/context.xml
└── WEB-INF/
    ├── web.xml             ← deployment descriptor: routes + class mappings
    ├── jsp/admin.jsp
    ├── lib/jdbc_drivers.jar
    └── classes/AdminServlet.class
```

**WEB-INF/web.xml** = deployment descriptor. Maps URL patterns to servlet classes.  
High value in LFI attacks — reveals app routes and class paths.

---

## Key Config Files

### `tomcat-users.xml` — credentials and roles
```xml
<role rolename="manager-gui" />
<user username="tomcat" password="tomcat" roles="manager-gui" />

<role rolename="admin-gui" />
<user username="admin" password="admin" roles="manager-gui,admin-gui" />
```

| Role | Access |
|------|--------|
| `manager-gui` | HTML GUI + status pages (WAR deploy interface) |
| `manager-script` | HTTP API + status pages |
| `manager-jmx` | JMX proxy + status pages |
| `manager-status` | Status pages only |
| `admin-gui` | Host Manager GUI |

**admin user** typically has `manager-gui,admin-gui` — both manager and admin-gui access.

### `WEB-INF/web.xml` — route/class mappings
```xml
<servlet>
  <servlet-name>AdminServlet</servlet-name>
  <servlet-class>com.inlanefreight.api.AdminServlet</servlet-class>
</servlet>
<servlet-mapping>
  <servlet-name>AdminServlet</servlet-name>
  <url-pattern>/admin</url-pattern>
</servlet-mapping>
```

Java dot notation → disk path: `classes/com/inlanefreight/api/AdminServlet.class`

---

## Enumeration

### Find manager/host-manager pages
```bash
# Direct browse
curl -s http://target:8080/manager/html
curl -s http://target:8080/host-manager/html

# Gobuster
gobuster dir -u http://target:8080/ \
  -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
# Finds: /docs, /examples, /manager
```
> Locates the Tomcat manager/host-manager pages by direct request and directory brute force; swap `target`, port, and wordlist.

### Default credentials to try
```
tomcat:tomcat
admin:admin
admin:password
tomcat:s3cret
manager:manager
```

A successful login to `/manager/html` → WAR upload → RCE (see next section).

---

## Lab Walkthrough

Target: `10.129.201.58`  
Vhosts: `app-dev.inlanefreight.local`, `web01.inlanefreight.local`

### Q1 — Tomcat version at web01:8180

```bash
curl -s http://web01.inlanefreight.local:8180/docs/ | grep Tomcat
# OR
curl -s http://web01.inlanefreight.local:8180/doesnotexist
```

```bash
curl -s http://web01.inlanefreight.local:8180/docs/ | grep -i tomcat
# <title>Apache Tomcat 10 (10.0.10) - Documentation Index</title>
```

**Answer:** `10.0.10`

### Q2 — Admin user role (from config example)

From `tomcat-users.xml` example in section text:
```xml
<user username="admin" password="admin" roles="manager-gui,admin-gui" />
```

**Answer:** `manager-gui,admin-gui`

---

## Exam Notes

- Tomcat fingerprint: invalid URL → default 404 error page shows version; `/docs/` page title is fallback
- `tomcat-users.xml` is the key credential file — always target this in LFI
- `WEB-INF/web.xml` = deployment descriptor — high value in LFI, reveals app routes
- Four manager roles: `manager-gui` (HTML), `manager-script` (API), `manager-jmx` (JMX), `manager-status` (status)
- `admin-gui` = Host Manager access (different from manager-gui)
- Default creds `tomcat:tomcat` or `admin:admin` work more often than they should
- EyeWitness labels Tomcat as "High Value Target" — it's worth checking every instance
- Gobuster against Tomcat: finds `/docs`, `/examples`, `/manager`
- WAR file deploy via `/manager/html` → JSP shell → RCE (covered next section)
