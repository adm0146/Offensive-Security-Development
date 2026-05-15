# Section 1 — Introduction

> Overview section. No lab. ffuf = fast web fuzzer for directories, files, vhosts, parameters, and values.

---

## What This Module Covers

| Topic | What You'll Do |
|-------|---------------|
| Directory fuzzing | Find hidden directories on a web server |
| File & extension fuzzing | Find specific files (`.php`, `.bak`, `.txt`, etc.) |
| Virtual host (vhost) fuzzing | Find subdomains/vhosts the server responds to |
| PHP parameter fuzzing | Find hidden GET/POST parameters |
| Parameter value fuzzing | Brute-force the correct value for a known parameter |

---

## Why ffuf

ffuf (Fuzz Faster U Fool) is the primary tool for this module. It sends many HTTP (Hyper Text Transfer Protocol) requests — one per wordlist entry — and shows you which ones got an interesting response back.

**ffuf vs alternatives:**

| Tool | Speed | Flexibility | Use Case |
|------|-------|-------------|----------|
| ffuf | Very fast | Highest — any part of request | This module |
| gobuster | Fast | Directories/DNS/vhosts | Quick dir scans |
| dirb | Slow | Directories only | Legacy |
| wfuzz | Fast | High | Parameter fuzzing |
| Burp Intruder | 1 req/sec (free) | Highest | GUI-based |

**Core concept:** Put the word `FUZZ` anywhere in an HTTP request. Point ffuf at a wordlist. It swaps `FUZZ` for each word and reports which ones get a different response.

---

## Exam Notes

- ffuf is the primary tool for ALL fuzzing tasks in this module
- The `FUZZ` keyword is the payload position marker — it goes wherever you want the wordlist item injected
- Response filtering is key: filter by status code (`-mc`), size (`-fs`), word count (`-fw`), or line count (`-fl`) to cut noise
- SecLists at `~/SecLists/` is the wordlist source for this module
