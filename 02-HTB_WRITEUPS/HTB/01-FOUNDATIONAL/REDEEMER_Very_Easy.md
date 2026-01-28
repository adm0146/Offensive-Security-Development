# REDEEMER - Very Easy

**Date:** January 23, 2026  
**Difficulty:** Very Easy  
**Time Spent:** 25 minutes  
**Status:** ✅ PWNED

---

## Machine Overview

REDEEMER is an introductory machine focused on Redis database enumeration and exploitation. It demonstrates unauthenticated access to Redis in-memory databases, key enumeration, and data extraction through basic redis-cli commands.

---

## Key Concepts Learned

- Redis (Remote Dictionary Server) protocol fundamentals
- Port 6379 identification and Redis service detection
- In-memory database structure and concepts
- redis-cli command-line utility usage
- Database selection and switching
- Key enumeration and information gathering
- Key retrieval and data extraction
- Service version detection importance

---

## Reconnaissance

### Connection Verification
- Used ping to confirm OpenVPN connection to target
- Connection stable and responsive

### Service Enumeration
```
nmap -sV -sS -p- TARGET_IP
```

**Findings:**
- Port 6379: Redis service (redis-cli accessible)
- Version: 5.0.7
- Service: In-memory database (redis)
- No authentication required
- Clear vulnerability surface

---

## Service Information

**Redis (Remote Dictionary Server)**
- **Port:** 6379 (default)
- **Protocol:** TCP-based key-value store
- **Type:** In-memory database
- **Use Cases:** Caching, sessions, real-time data
- **Client Tool:** redis-cli (command-line interface)
- **Authentication:** Often unauthenticated in misconfigured systems
- **Data Structure:** Key-value pairs stored in databases (0-15 by default)

**Redis Architecture:**
- Multiple databases (usually 16, indexed 0-15)
- Each database stores key-value pairs
- No built-in per-key access controls
- Entire database accessible if unauthenticated

---

## Vulnerabilities Identified

### Vulnerability 1: Unauthenticated Redis Access
- **Type:** Authentication Bypass / Improper Access Control
- **Port:** 6379
- **Severity:** Critical
- **Impact:** Unauthenticated access to all databases and keys
- **Discovery Method:** Nmap service detection + redis-cli connection
- **Root Cause:** Redis running without authentication enabled
- **Exploitation:** Direct redis-cli connection without password

### Vulnerability 2: Sensitive Data in Redis Databases
- **Type:** Information Disclosure
- **Finding:** Flag and other sensitive data stored in plaintext keys
- **Location:** Database 0, key named "flag"
- **Impact:** Direct data extraction without privilege escalation

### Vulnerability 3: No Database Access Controls
- **Type:** Improper Access Control
- **Finding:** All databases accessible to any connected client
- **Impact:** Complete data exposure across all 16 databases

---

## Exploitation Chain

### Phase 1: Redis Service Connection

**Step 1: Connect to Redis service**
```
redis-cli -h TARGET_IP -p 6379
```

**Flag Explanation:**
- `-h` = Hostname/IP address of Redis server
- `-p` = Port number (default 6379)
- Connection prompt: `TARGET_IP:6379>`

### Phase 2: Database Information Gathering

**Step 1: Get general Redis information**
```
TARGET_IP:6379> info
```

**Output:** Server information, memory usage, connected clients, statistics

**Step 2: Get keyspace information**
```
TARGET_IP:6379> info keyspace
```

**Output:** Number of keys in each database
- Example: `db0:keys=4,expires=0,avg_ttl=0`
- Indicates 4 keys stored in database 0

### Phase 3: Database Selection

**Step 1: Select specific database**
```
TARGET_IP:6379> select 0
```

**Note:** Database numbers range from 0-15 (typically 16 total databases)
- Common to start with database 0
- Other databases may contain additional data

### Phase 4: Key Enumeration

**Step 1: List all keys in current database**
```
TARGET_IP:6379> keys *
```

**Output:** List of all keys
- flag
- stor
- numb
- temp

**Finding:** "flag" key immediately identifies target

### Phase 5: Data Extraction

**Step 1: Retrieve flag key value**
```
TARGET_IP:6379> GET flag
```

**Output:** Flag content displayed directly in terminal

**Flag Retrieved:** [flag content]

---

## Attack Summary

1. Verified network connectivity with ping
2. Ran nmap -sV to detect Redis service on port 6379
3. Identified Redis 5.0.7 with no authentication
4. Connected using redis-cli with -h hostname flag
5. Retrieved keyspace information with info keyspace
6. Selected database 0 with select command
7. Enumerated all keys with keys * command
8. Identified "flag" key as target
9. Retrieved flag content with GET command

---

## Key Techniques Used

- **Nmap -sV:** Service version detection
- **Nmap -sS:** TCP SYN scan
- **Nmap -p-:** Full port range scan
- **redis-cli -h:** Connect to Redis host
- **redis-cli -p:** Specify Redis port
- **info:** General server information
- **info keyspace:** Database key count information
- **select:** Switch between databases
- **keys \*:** Enumerate all keys in database
- **GET:** Retrieve key value

---

## Tools Used

- Ping (network testing)
- Nmap with -sV, -sS, -p- flags (service detection)
- redis-cli (Redis command-line client)

---

## Redis Command Reference

**Connection:**
```
redis-cli -h HOST -p PORT
```

**Information Gathering:**
```
info              # General server information
info keyspace     # Database and key count information
info memory       # Memory usage statistics
info clients      # Connected client information
```

**Database Navigation:**
```
select 0          # Select database 0
select 1          # Select database 1
dbsize            # Get number of keys in current database
```

**Key Operations:**
```
keys *            # List all keys in database
keys pattern      # List keys matching pattern
GET keyname       # Retrieve value of key
SET keyname value # Set key value (if writable)
DEL keyname       # Delete key (if writable)
TYPE keyname      # Get data type of key
TTL keyname       # Get time to live for key
```

---

## Lessons Learned

1. **Redis Default Configuration is Insecure** - Often runs unauthenticated on port 6379
2. **In-Memory Databases are Fast but Risky** - All data accessible if not protected
3. **Default Ports Matter** - Redis always on 6379 unless specifically changed
4. **Version Detection is Critical** - redis-cli connection confirms vulnerable service
5. **Keyspace Information Reveals Data** - "info keyspace" shows what's stored
6. **Key Naming is Obvious** - "flag" key immediately indicates target
7. **No Encryption by Default** - All data plaintext in memory
8. **Database Switching is Easy** - Multiple databases all accessible
9. **GET Command Extracts Data** - Direct retrieval without complex parsing

---

## Methodology Confirmation

This machine confirmed the enumeration process for database services:
- Step 1: Reconnaissance ✅ (ping, nmap -sV -sS -p-)
- Step 2: Service Identification ✅ (Redis port 6379, version 5.0.7)
- Step 3: Vulnerability Identification ✅ (unauthenticated access)
- Step 4: Connection Establishment ✅ (redis-cli -h -p)
- Step 5: Information Gathering ✅ (info keyspace, keys *)
- Step 6: Data Enumeration ✅ (key listing and identification)
- Step 7: Data Extraction ✅ (GET flag command)
- Step 8: Flag Capture ✅ (flag content retrieved)

---

## Speed Optimization

**What Worked:**
- Nmap -sV identified Redis immediately
- Default port 6379 expected and found
- redis-cli connection instant with -h -p flags
- "info keyspace" revealed database structure
- "keys \*" showed all keys without filtering
- "flag" key name obvious and direct
- GET command single-step retrieval

**Time Breakdown:**
- Reconnaissance: 3 minutes (ping, nmap)
- Service Identification: 2 minutes (redis version confirmed)
- Redis Connection: 2 minutes (redis-cli setup)
- Database Enumeration: 5 minutes (info, select, keys)
- Flag Retrieval: 3 minutes (GET flag)
- Total: 25 minutes

**Fastest Box Yet:** Speed optimization kicking in as methodology becomes automatic

---

## Comparison to Previous Boxes

| Aspect | MEOW | FAWN | DANCING | REDEEMER |
|--------|------|------|---------|----------|
| Service | Telnet | FTP | SMB | Redis |
| Port | 23 | 21 | 445 | 6379 |
| Auth Type | Default creds | Anonymous | Null auth | Unauthenticated |
| Time | <20 min | 32 min | 45 min | 25 min |
| Complexity | Minimal | Low | Low-Med | Low |
| Access Type | Shell | File transfer | Network shares | Database |
| Key Technique | Shell login | FTP get | SMB nav | Redis GET |

**Observation:** Speed improving significantly as fundamentals become second nature. REDEEMER at 25 minutes shows acceleration despite being 4th box in same day.

---

## Redis Attack Patterns

**Standard Redis Exploitation:**
1. Identify Redis on port 6379 (nmap -sV)
2. Attempt redis-cli connection without authentication
3. Use "info keyspace" to identify populated databases
4. Select database with most keys (usually db0)
5. Enumerate keys with "keys \*"
6. Search for sensitive keys: "flag", "password", "secret", "token"
7. Extract with GET command
8. If writable: SET malicious data, inject commands

---

## Real-World Context

**Why Redis Matters:**
- Ubiquitous in modern web applications
- Used for caching, sessions, real-time data
- Often misconfigured in development/staging
- No built-in authentication in older versions
- Can be entry point for data theft or system compromise
- Sometimes used as queuing system (sensitive job data)

---

## Notes

Fourth box complete! **Speed dramatically improved:**

**Day 1 Progress Summary:**
- Box 1 (MEOW): <20 min
- Box 2 (FAWN): 32 min  
- Box 3 (DANCING): 45 min
- Box 4 (REDEEMER): 25 min ← **Speed accelerating**

**Total Time:** ~2 hours for 4 boxes
**Average:** 30 minutes per box including writeup
**Trend:** Time decreasing as methodology becomes automatic

**Four completely different services mastered in one session:**
- Telnet (shell access)
- FTP (file transfer)
- SMB (network shares)
- Redis (database)

Pattern is crystal clear now: **Enumerate → Identify → Exploit → Extract = Box pwned**

**Status:** BOX PWNED ✅

---

## What's Next

- Continue Easy boxes (4 of 6-8 complete)
- Speed should remain in 20-30 minute range
- Remaining Easy boxes may combine multiple services
- Last 2-3 Easy boxes before transitioning to Medium (Feb 1-5)
- Medium machines will require privilege escalation knowledge
- Foundation phase almost complete - methodology proven solid
