# Section 10 — Burp Intruder

> Burp's built-in fuzzer. Powerful but rate-limited in Community (1 req/sec) — use ffuf for speed, Intruder for precision.

---

## Lab Answer

| Question | Answer |
|----------|--------|
| Fuzz for .html files under /admin, find the flag | `HTB{burp_1n7rud3r_fuzz3r!}` |

**Flag found at:** `/admin/2010.html`

**Fast method (ffuf — same result, no rate limit):**
```bash
ffuf -u http://TARGET/admin/FUZZ.html \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  -mc 200 -s
# Found: 2010, index
# -mc 200 = only show 200 OK responses
# -s = silent mode (clean output)

curl -s http://TARGET/admin/2010.html   # read the flag
```

---

## What Burp Intruder Is For

Intruder is a web fuzzer built into Burp — it takes any request you've captured and replaces marked values with items from a wordlist. It's the GUI equivalent of ffuf/gobuster/wfuzz.

**Intruder > CLI tools when:**
- You already have a request in Burp and want to fuzz a specific parameter
- You need to fuzz multiple positions at once (Cluster Bomb / Pitchfork)
- You want fine-grained control over payload processing and encoding
- You have Burp Pro (no rate limit)

**CLI tools > Intruder Community when:**
- Speed matters (Intruder Community = 1 req/sec max)
- You're doing large directory brute-forces

---

## Intruder Setup (Step by Step)

### Step 1 — Send Request to Intruder
```
From Proxy History: right-click request → Send to Intruder
Shortcut: Ctrl+I
Go to Intruder tab: Ctrl+Shift+I
```

### Step 2 — Set Payload Positions (Positions tab)

Mark the part of the request you want to fuzz with `§` markers:
```
GET /§DIRECTORY§/ HTTP/1.1
```

Two ways to mark:
- Select the text → click **Add §** button
- Type `§` manually around the target value

**Attack Types:**
| Type | Use Case |
|------|----------|
| Sniper | One position, one wordlist — most common |
| Battering Ram | Same wordlist item in ALL positions simultaneously |
| Pitchfork | Multiple positions, one wordlist each, iterate in parallel |
| Cluster Bomb | Multiple positions, all combinations — password spraying |

### Step 3 — Configure Payloads (Payloads tab)

**Payload Type:** Simple List (most common — load a wordlist file)

```
Payload Configuration → Load → select wordlist file
```

Common wordlists:
```
/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt      # directories
/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-words.txt  # more dirs
/usr/share/wordlists/rockyou.txt                                     # passwords
```

**Payload Processing — useful rules:**
- **Skip if matches regex** `^\..*$` = skip lines starting with `.` (dot files)
- **Add suffix** `.html` = append extension to every wordlist item
- **Add prefix** `admin_` = prepend a string

**Payload Encoding:** Leave URL-encoding ON (default) — encodes special chars automatically.

### Step 4 — Settings tab

**Grep - Match** (flag responses that contain a string):
```
Enable → Clear → type "200 OK" → Add
Disable "Exclude HTTP Headers"
```
This adds a `200 OK` column to results — click it to sort hits to the top.

**Grep - Extract:** Pulls a specific part of the response body (useful for long responses).

### Step 5 — Run the Attack

Click **Start Attack** → new window shows results in real-time.

Sort by:
- **Status** column → find 200s
- **Length** column → different length = different response = possible hit
- **200 OK** column (if you set Grep - Match) → hits bubble to top

---

## Intruder vs CLI Fuzzing Tools

| | Burp Intruder Community | Burp Intruder Pro | ffuf / gobuster |
|---|---|---|---|
| Speed | 1 req/sec (throttled) | Unlimited | 1000+ req/sec |
| GUI | ✅ | ✅ | ❌ |
| Multi-position fuzzing | ✅ | ✅ | Partial |
| Payload processing rules | ✅ | ✅ | Limited |
| Cost | Free | Paid | Free |
| Best for | Learning, small wordlists | Any use | Large wordlists |

**Rule of thumb:** Use Intruder in Burp Pro or for small focused tests. Use ffuf/gobuster for anything with a large wordlist.

---

## Equivalent ffuf Commands

```bash
# Directory fuzzing:
ffuf -u http://TARGET/FUZZ -w wordlist.txt -mc 200

# File fuzzing with extension:
ffuf -u http://TARGET/FUZZ.html -w wordlist.txt -mc 200

# Fuzzing under a path:
ffuf -u http://TARGET/admin/FUZZ.html -w wordlist.txt -mc 200

# Parameter fuzzing:
ffuf -u "http://TARGET/page?FUZZ=value" -w wordlist.txt -mc 200

# POST body fuzzing:
ffuf -u http://TARGET/login -X POST -d "user=FUZZ&pass=password" -w users.txt -mc 200
```

---

## Exam Notes

- Burp Community Intruder is rate-limited — in the exam (which has Burp Pro), this limit is removed
- `Ctrl+I` = send to Intruder, `Ctrl+Shift+I` = go to Intruder tab
- Always check the **Status** and **Length** columns to identify hits — different length = different response
- Sniper attack type = one wordlist, one position — use for directory/file fuzzing
- Cluster Bomb = all combinations of multiple wordlists — use for credential brute-force (user list × password list)
- Use **Grep - Match** with "200 OK" to highlight successful hits automatically
- **Payload Processing → Skip if matches regex `^\..*$`** = skip dotfiles in wordlists (cleans up output)
- For the exam: if you need speed, use ffuf; if you need Intruder's features, use it with Pro's speed
