# Section 5 — Recursive Fuzzing

> Automate multi-level directory scanning so ffuf drills into discovered directories without manual follow-up scans.

---

## Lab Answer

| Question | Answer |
|----------|--------|
| Find a flag using recursive fuzzing | `HTB{fuzz1n6_7h3_w3b!}` |

Flag was at `/forum/flag.php` — found automatically because recursion queued `/forum/FUZZ` after discovering the `/forum` directory.

---

## The Problem Recursive Fuzzing Solves

Without recursion, you have to run ffuf again manually for every directory you find. It looks like this:
1. Fuzz root → find `/forum`
2. Manually re-run ffuf targeting `/forum/FUZZ`
3. Repeat for every new directory found

The `-recursion` flag fixes this. ffuf automatically starts a new scan inside each directory it discovers.

---

## Core Flags

```bash
ffuf -w WORDLIST:FUZZ \
  -u http://TARGET/FUZZ \
  -recursion           # enable recursive scanning
  -recursion-depth 1   # only recurse one level deep (root → subdirs, not sub-subdirs)
  -e .php              # also try each wordlist entry with .php appended
  -v                   # verbose — show full URL in output (critical when recursing)
  -ic                  # ignore wordlist comments
```
> `-recursion` tells ffuf to automatically start a new scan inside any directory it finds. Without `-recursion-depth 1`, the scan can chain indefinitely. `-v` is essential here — without it you see `flag.php` but not which directory it's in.

**`-recursion-depth 1`** is strongly recommended. Without a depth limit, ffuf chases every subdirectory forever. The scan can run for hours on targets with deep folder structures.

---

## Full Command

```bash
ffuf -w ~/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt:FUZZ \
  -u http://TARGET_IP:PORT/FUZZ \
  -recursion -recursion-depth 1 \
  -e .php \
  -v -ic \
  -t 100
```
> Full recursive scan with PHP extension testing. The `-e .php` flag doubles request count — each word is tried once bare and once with `.php`. Use `common.txt` instead of the large list when time is limited.

**Note:** `-e .php` doubles the request count. Each word is tried once plain and once with `.php` added. An 87k-word list becomes about 175k requests per directory level.

---

## How It Works

```
[1] ffuf scans: http://TARGET/FUZZ
    → finds /forum  (301) → [INFO] Adding a new job to the queue: http://TARGET/forum/FUZZ
    → finds /blog   (301) → [INFO] Adding a new job to the queue: http://TARGET/blog/FUZZ

[2] ffuf scans: http://TARGET/forum/FUZZ
    → finds /forum/flag.php  (200)  ← hit
    → finds /forum/index.php (200)

[3] ffuf scans: http://TARGET/blog/FUZZ
    → finds /blog/index.php  (200)
    → finds /blog/home.php   (200)
```

With `-recursion-depth 1`: step [2] and [3] run, but if `/forum/FUZZ` found a subdirectory like `/forum/admin`, that would NOT be queued for further scanning.

---

## Reading Recursive Output

```
[INFO] Adding a new job to the queue: http://TARGET/forum/FUZZ   ← new subdir queued

[Status: 200, Size: 1234, Words: 56, Lines: 22] | URL | http://TARGET/forum/flag.php
    * FUZZ: flag.php
```

- `[INFO] Adding a new job...` lines tell you when a new directory level starts
- `-v` is essential here — without it you'd just see `flag.php` with no path context

---

## Exam Notes

- Depth 1 covers most CTF/exam scenarios — root dirs and their immediate children
- Use `-v` always with recursion — you need the full URL to know which directory a file is in
- `-e .php` doubles request count — use `common.txt` or `raft-medium-directories.txt` instead of the big lists when time is tight
- After recursion scan, curl any interesting `.php` files directly for content
- The scan queues all discovered directories before processing them — watch for `[INFO] Adding a new job` lines to know what will be scanned next
