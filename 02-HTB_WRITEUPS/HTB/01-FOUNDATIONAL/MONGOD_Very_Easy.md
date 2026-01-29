# MONGOD - Very Easy

**Date Completed:** January 29, 2026  
**Difficulty:** Very Easy  
**Status:** ✅ COMPLETE  
**Focus Areas:** Legacy MongoDB Exploitation & Database Enumeration

---

## Phase 1: Initial Reconnaissance

### Step 1: Full Port Scan
```
nmap-full TARGET_IP
```

**Alias Definition:**
```bash
alias nmap-full='nmap -sS -sV -p- TARGET_IP'
```

**Findings:**

| Port | Service | Version | Status |
|------|---------|---------|--------|
| 27017 | MongoDB | 3.6.8 | Open |
| (Additional port) | (Service) | (Version) | Open |

**Critical Finding:** MongoDB 3.6.8 - **Extremely old version** with known vulnerabilities and compatibility issues

---

## MongoDB Fundamentals

### What is MongoDB?
- **Type:** NoSQL database (document-oriented)
- **Data Structure:** Stores data in JSON-like documents (collections)
- **Default Port:** 27017
- **Use Case:** Flexible schema, horizontal scaling, rapid development

### MongoDB Architecture
```
MongoDB Server
├── Database 1
│   ├── Collection 1 (documents)
│   ├── Collection 2 (documents)
│   └── Collection 3 (documents)
├── Database 2
│   └── Collections...
└── Database 3
    └── Collections...
```

---

## The MongoDB Compatibility Challenge

### The Problem: Version Mismatch

**Critical Issue Encountered:**
When downloading MongoDB tools with standard package managers:
```bash
# Default installation = LATEST version (e.g., 4.x, 5.x)
# But target server is running 3.6.8
# Result: Connection FAILS due to protocol incompatibility
```

**Why This Matters:**
- MongoDB 3.6.8 uses older protocol/authentication methods
- Modern MongoDB shells cannot connect to legacy servers
- Standard `mongosh` or `mongo` clients will error out
- **Solution Required:** Download specific compatible version

### The Frustration Factor

**Real-World Consideration:**
This highlights a genuine challenge in penetration testing:
- How would a beginner know to download a specific 2+ year old version?
- Documentation isn't always clear about version compatibility
- Trial and error becomes necessary
- This is **not** a realistic beginner scenario

**Key Lesson:** Version compatibility is critical when interacting with legacy systems. Always check target version first!

---

## Phase 2: MongoDB Shell Installation & Connection

### Step 1: Download Compatible mongosh Version
```
curl -O https://downloads.mongodb.com/compass/mongosh-2.3.2-linux-x64.tgz
```

**Explanation:**
- `-O`: Save downloaded file with original filename
- URL points to: mongosh version 2.3.2 (compatible with 3.6.8)
- Format: Compressed tarball (.tgz)

**Result:** `mongosh-2.3.2-linux-x64.tgz` downloaded locally

### Step 2: Extract Tarball
```
tar xvf mongosh-2.3.2-linux-x64.tgz
```

**Flags Explained:**
- `x`: Extract archive
- `v`: Verbose output (show extraction progress)
- `f`: Specify filename

**Result:** Directory `mongosh-2.3.2-linux-x64/` created with MongoDB shell binary

### Step 3: Navigate to MongoDB Shell Binary
```
cd mongosh-2.3.2-linux-x64/bin
```

**Contents:** Binary executable `mongosh` (the MongoDB interactive shell)

### Step 4: Connect to Target MongoDB Server
```
./mongosh mongodb://TARGET_IP:27017
```

**Connection String Breakdown:**
- `./mongosh`: Execute the MongoDB shell binary
- `mongodb://`: Protocol scheme
- `TARGET_IP`: Target server IP address
- `:27017`: MongoDB default port

**Result:** Connected to target MongoDB instance with interactive shell prompt

---

## Phase 3: MongoDB Database & Collection Enumeration

### Step 1: List All Databases
```
show dbs;
```

**Note:** MongoDB commands end with semicolon (`;`) - similar to SQL/Java syntax

**Output:** Lists all databases on the server
```
admin                  [size info]
config                 [size info]
local                  [size info]
sensitive_information  [size info]
```

**Key Finding:** `sensitive_information` database detected

### Step 2: Access Target Database
```
use sensitive_information;
```

**Result:** Switched context to `sensitive_information` database

**Verification:** Prompt changes to show current database:
```
sensitive_information>
```

### Step 3: List Collections in Database
```
show collections;
```

**Output:** Shows all collections (tables) in current database
```
flag
user_data
metadata
```

**Key Finding:** `flag` collection identified as target

### Step 4: Extract Flag Document
```
db.flag.find();
```

**Breakdown:**
- `db`: Reference to current database
- `flag`: Collection name
- `.find()`: Query method to retrieve documents
- `()`: Empty parameters = return all documents

**Result:** Flag document(s) displayed with full contents

**Flag Retrieved:** ✅

---

## MongoDB Query Commands Reference

| Command | Purpose | Example |
|---------|---------|---------|
| `show dbs;` | List all databases | Shows all available databases |
| `show collections;` | List collections in current DB | Shows all collections/tables |
| `use [database];` | Switch to database | `use admin;` |
| `db.flag.find();` | Find all documents in collection | Returns all documents |
| `db.flag.findOne();` | Find first document | Returns one document |
| `db.flag.count();` | Count documents | Returns document count |
| `db.[collection].drop();` | Delete collection | DANGEROUS - irreversible |

---

## Exploitation Chain Summary

1. **Reconnaissance** → Detected MongoDB 3.6.8 on port 27017
2. **Version Compatibility Analysis** → Identified version mismatch issue
3. **Tool Download** → Downloaded compatible mongosh-2.3.2
4. **Binary Extraction** → Extracted tarball and located binary
5. **Database Connection** → Established connection to target server
6. **Database Enumeration** → Listed databases with `show dbs;`
7. **Database Selection** → Switched to `sensitive_information` database
8. **Collection Enumeration** → Listed collections with `show collections;`
9. **Document Retrieval** → Retrieved flag with `db.flag.find();`
10. **Flag Extraction** → Successfully captured flag ✅

---

## Key Techniques & Tools

| Technique | Tool/Command | Purpose |
|-----------|--------------|---------|
| Port Scanning | nmap -sS -sV -p- | Service detection and version identification |
| Version Compatibility | mongosh compatibility matrix | Identify compatible shell version |
| Tarball Download | curl -O | Remote file download |
| Archive Extraction | tar xvf | Decompress tarball |
| Database Connection | ./mongosh mongodb://IP:PORT | Connect to MongoDB server |
| Database Enumeration | show dbs; | Discover available databases |
| Database Selection | use [database]; | Switch database context |
| Collection Enumeration | show collections; | Discover available collections |
| Document Retrieval | db.[collection].find(); | Query and display documents |

---

## Critical Lessons Learned

### Technical Lessons
1. **Legacy System Challenges** - Old software versions have compatibility requirements
2. **NoSQL Databases** - MongoDB is fundamentally different from SQL databases
3. **Database Navigation** - Collection/document hierarchy differs from traditional tables
4. **Version Compatibility** - Always verify tool compatibility with target version
5. **Documentation Dependency** - Legacy systems require deeper research

### Operational Lessons
1. **Frustration is Learning** - Difficult boxes teach the most valuable lessons
2. **Problem-Solving Under Pressure** - Must research solutions independently
3. **Version Management** - Critical when dealing with older systems
4. **Tarball Extraction** - Common task in penetration testing
5. **Direct Binary Execution** - Running uninstalled tools from extracted archives

### Realistic Perspective
- **Beginner Challenge:** Version compatibility issues are NOT obvious
- **Research Required:** Had to dig into MongoDB documentation
- **Time Investment:** Worth it for learning database exploitation
- **Real-World Relevance:** Legacy systems DO exist in production environments
- **Takeaway:** Patience and documentation skills are as important as technical skills

---

## MongoDB Security Implications

**Why MongoDB 3.6.8 is Vulnerable:**
- ❌ No authentication enabled by default on localhost
- ❌ Legacy protocol without modern security features
- ❌ Known CVEs in version 3.6.8
- ❌ Exposed on network without credentials
- ❌ No encryption in transit

**Real-World Risk:**
Exposed MongoDB instances are common attack vectors for:
- Data exfiltration
- Unauthorized database modification
- Ransomware targeting NoSQL databases
- Lateral movement through database access

---

## Comparison to Previous Boxes

| Aspect | MONGOD | Previous Linux Boxes |
|--------|--------|----------------------|
| Database Type | NoSQL (MongoDB) | Web Applications |
| Port | 27017 | 80, 22, 3389 |
| Complexity | Low exploitation, High setup | Multiple vectors |
| Tools Required | Compatible mongosh | Standard Linux tools |
| Main Challenge | Version compatibility | Vulnerability identification |
| Difficulty | Very Easy (conceptually) | Very Easy to Easy |

---

## Status

✅ **BOX PWNED**
- Flag: Retrieved ✓
- MongoDB enumeration successful ✓
- Database connection established ✓

**Speed:** Very Easy classification accurate - flag retrieval straightforward once connection established

**Key Achievement:** Learned database enumeration on NoSQL systems and troubleshot version compatibility issues

---

## Important Notes

The MongoDB version compatibility issue illustrates an important pentesting reality:
- Tools and targets must be compatible
- Research and documentation skills are essential
- Legacy systems present unique challenges
- Problem-solving and persistence matter more than initial knowledge

Despite the frustration, this box taught valuable real-world skills about:
- Working with older systems
- Database enumeration techniques
- Troubleshooting tool compatibility
- Independent problem-solving

**Takeaway:** Challenging setups create the best learning experiences! 🎓
