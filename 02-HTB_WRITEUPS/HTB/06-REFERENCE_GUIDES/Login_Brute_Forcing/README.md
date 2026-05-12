# Login Brute Forcing

Reference guides from the HTB Academy Login Brute Forcing module. Hydra, Medusa, ffuf web-login attacks, wordlist crafting, and password mutation.

---

## Reference Guides

- [00-EXAM_CHEATSHEET.md](00-EXAM_CHEATSHEET.md) — Full brute-forcing playbook: wordlist selection by service, Hydra/Medusa/ffuf command templates, troubleshooting patterns.

- [01-Introduction.md](01-Introduction.md) — Brute forcing fundamentals: types of attacks, online vs offline, lockout/rate-limit awareness.

- [02-Password_Security_Fundamentals.md](02-Password_Security_Fundamentals.md) — Password entropy, common password patterns, organizational password policies, why dictionaries beat random guessing.

- [03-Brute_Force_Attacks.md](03-Brute_Force_Attacks.md) — Pure character-space brute force: when to use, how long it takes, mask attacks.

- [04-Dictionary_Attacks.md](04-Dictionary_Attacks.md) — Wordlist-based attacks: rockyou.txt subsets, breach lists, default credentials, service-specific wordlists.

- [05-Hybrid_Attacks.md](05-Hybrid_Attacks.md) — Combining dictionaries with mutation rules: hashcat rules, prepend/append, leet substitution.

- [06-Hydra.md](06-Hydra.md) — Hydra installation, syntax, common modules (ssh, ftp, smb, rdp), output parsing, parallel attack tuning.

- [07-Basic_HTTP_Authentication.md](07-Basic_HTTP_Authentication.md) — Cracking HTTP Basic auth: Hydra `http-get`/`http-post`, base64 inspection, 401 vs 403 responses.

- [08-Login_Forms.md](08-Login_Forms.md) — Web form brute forcing: `http-post-form` syntax, identifying success/failure strings, CSRF token handling.

- [09-Medusa.md](09-Medusa.md) — Medusa as Hydra alternative: when to use, performance comparison, module differences.

- [10-Web_Services.md](10-Web_Services.md) — Brute forcing API endpoints, JSON login forms, custom HTTP verbs.

- [11-Custom_Wordlists.md](11-Custom_Wordlists.md) — Building targeted wordlists: CeWL crawling, username-anarchy, cupp, password mutation with hashcat rules.

- [12-Skills_Assessment_Part1.md](12-Skills_Assessment_Part1.md) — Skills assessment part 1: enumeration → username harvest.

- [13-Skills_Assessment_Part2.md](13-Skills_Assessment_Part2.md) — Skills assessment part 2: targeted spray → admin login → flag.
