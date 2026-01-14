# Race Conditions - Quick Reference Guide

**Date:** January 14, 2026  
**Source:** TryHackMe Lab Work  
**Purpose:** Quick reference for identifying, exploiting, and understanding race conditions

---

## What is a Race Condition?

A **race condition** occurs when:
- Two or more processes/threads access shared resources
- The final result depends on the timing/order of execution
- The application assumes operations happen in a specific order, but they don't

**Example:** Checking if a file exists, then reading it - another process deletes it in between.

---

## Common Race Condition Scenarios

### 1. **Time-of-Check to Time-of-Use (TOCTOU)**
```
1. Check if user has permission
2. [RACE WINDOW - attacker modifies file/data]
3. Perform action based on check
```

### 2. **File Operations Race**
```
1. Check if file exists
2. [RACE WINDOW - attacker creates/modifies file]
3. Write/read the file
```

### 3. **Database/Account Operations**
```
1. Verify account balance
2. [RACE WINDOW - attacker submits duplicate transaction]
3. Deduct money (happens twice!)
```

---

## Identifying Race Conditions

### Signs in Code:
- ❌ Separate "check" and "use" operations
- ❌ No file locking mechanisms
- ❌ Asynchronous operations without synchronization
- ❌ Weak transaction handling in databases

### Testing Approach:
1. Find an operation that takes multiple steps
2. Identify the window between steps
3. Attempt to manipulate data during that window
4. See if you can cause unexpected behavior

---

## Exploiting Race Conditions

### Method 1: Multi-threaded Attack
```bash
# Run the vulnerable operation many times simultaneously
for i in {1..100}; do
    curl http://target.com/vulnerable_endpoint &
done
wait
```

### Method 2: Time-based Exploitation
```bash
# Attempt to modify file/data immediately after check
while true; do
    # Trigger the check
    curl http://target.com/check_file
    
    # Race: Try to modify during window
    cp /tmp/malicious_file /var/www/target_file
    
    # If successful, exploit happens
done
```

### Method 3: Burp Suite Repeater (See below)

---

## Common Vulnerable Operations

### File Operations
```bash
# Vulnerable pattern:
if [ -f "$file" ]; then
    cat "$file"
fi

# Race window: Between check and read
# Attack: Attacker creates symlink pointing to sensitive file
ln -s /etc/passwd /tmp/race_target
```

### Account/Balance Operations
```
1. GET /account/balance → Returns $100
2. [RACE: Submit withdrawal twice]
3. Both withdrawals process (you withdraw $200 with only $100!)
```

### File Uploads
```
1. Upload file (temp location)
2. [RACE: Modify file while server is processing]
3. Server processes malicious version
```

---

## Race Condition Testing with Burp Suite

**See Burp_Suite_Repeater_Guide.md for detailed steps**

Quick version:
1. Capture the vulnerable request in Burp
2. Send to Repeater
3. Use "Send group (simultaneous)" to send multiple requests at exact same time
4. Watch for unexpected behavior (doubled effects, bypassed checks, etc.)

---

## Mitigation Strategies

### For Developers:
✅ Use file locking (flock, fcntl)
✅ Use atomic operations (single operation, not multiple)
✅ Use database transactions with proper isolation
✅ Implement proper synchronization (mutexes, semaphores)
✅ Use temporary files in secure directories

### Example of Safe Code:
```python
# UNSAFE:
if user.balance >= amount:
    user.balance -= amount
    user.save()

# SAFE:
with transaction.atomic():  # Database transaction
    user = User.objects.select_for_update().get(id=user_id)
    if user.balance >= amount:
        user.balance -= amount
        user.save()
```

---

## Real-World Examples

### Example 1: File Upload Race
**Vulnerable:**
```
1. Upload file to /tmp/upload_xyz
2. Scan file for malware
3. Move to /var/www/uploads/file.jpg
```
**Attack:**
```
Between steps 2-3, replace /tmp/upload_xyz with malicious script
Server moves malicious script to web-accessible directory
```

### Example 2: Account Takeover
**Vulnerable:**
```
1. Check if password reset link is valid
2. Send reset link to email
3. User clicks link, resets password
```
**Attack:**
```
Race to reset password before user email is sent
Attacker gains access with new password
```

### Example 3: Duplicate Transaction
**Vulnerable:**
```
POST /transfer_money (Account A → Account B, $50)
```
**Attack:**
```
Send same request 100 times simultaneously
All 100 requests process (transferring $5,000 instead of $50)
```

---

## Tools for Race Condition Testing

| Tool | Purpose |
|------|---------|
| **Burp Suite Repeater** | Send simultaneous requests |
| **GNU Parallel** | Execute commands in parallel |
| **Apache Bench (ab)** | Stress test with concurrent requests |
| **wrk** | HTTP benchmarking tool |
| **Python threading** | Custom exploitation scripts |

---

## Key Takeaways

✅ **Race conditions** = Timing-dependent vulnerabilities
✅ **TOCTOU** = Check-Use gap is the attack window
✅ **Exploitation** = Act during the race window
✅ **Tools** = Burp Repeater, threading, parallel execution
✅ **Defense** = Atomic operations, file locking, transactions

---

## Next Steps

- Practice with Burp Suite Repeater (see guide below)
- Identify race windows in target applications
- Time your attacks to exploit the window
- Document the vulnerability for writeups

