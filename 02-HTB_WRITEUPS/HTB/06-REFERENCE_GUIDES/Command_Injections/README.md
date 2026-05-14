# Command Injections

Reference guides from the HTB Academy Command Injections module. OS command injection detection, operator selection, filter bypass (chars, words, advanced obfuscation), automated evasion tools, prevention.

---

## Reference Guides

- [00-EXAM_CHEATSHEET.md](00-EXAM_CHEATSHEET.md) — Full playbook: operator behavior table, web shells per language, bypass-by-what's-blocked matrix, universal base64 payload, env var tricks, char shifting, blind injection, automated tools, prevention, decision tree.

- [01-Intro_to_Command_Injections.md](01-Intro_to_Command_Injections.md) — What command injection is, sink functions per language, indirect sinks, why it's still common.

- [02-Detection.md](02-Detection.md) — Spotting injection sinks, operator table, detection workflow, recognizing WAF vs app-level errors.

- [03-Injecting_Commands.md](03-Injecting_Commands.md) — Building payloads, bypassing front-end (HTML5 `pattern=`), URL encoding the chars.

- [04-Other_Injection_Operators.md](04-Other_Injection_Operators.md) — Operator comparison (`;`/`\n`/`&`/`\|`/`&&`/`\|\|`/`$()`/backtick), output behaviors, when each applies.

- [05-Identifying_Filters.md](05-Identifying_Filters.md) — App-level vs WAF detection, payload reduction to isolate filter, two-dimension test matrix.

- [06-Bypassing_Space_Filters.md](06-Bypassing_Space_Filters.md) — `${IFS}`, brace expansion `{cmd,arg}`, tab `%09`, redirect `<`, empty-var trick.

- [07-Bypassing_Other_Blacklisted_Characters.md](07-Bypassing_Other_Blacklisted_Characters.md) — Env var substring (`${PATH:0:1}` for `/`), Windows `%VAR:~start,length%`, character shifting with `tr`.

- [08-Bypassing_Blacklisted_Commands.md](08-Bypassing_Blacklisted_Commands.md) — Quote obfuscation (`c'a't`), backslash (`w\ho\am\i`), positional params (`who$@ami`), variable concatenation, wildcards.

- [09-Advanced_Command_Obfuscation.md](09-Advanced_Command_Obfuscation.md) — Case manipulation (`tr "[A-Z]" "[a-z]"`), reversed commands (`rev<<<`), base64 encoding (`bash<<<$(base64 -d<<<...)`), hex encoding via xxd.

- [10-Evasion_Tools.md](10-Evasion_Tools.md) — Bashfuscator (Linux), Invoke-DOSfuscation (Windows/PowerShell), tool flags + workflow.

- [11-Command_Injection_Prevention.md](11-Command_Injection_Prevention.md) — Argv array invocation, input validation (`filter_var`), sanitization (`preg_replace`), server hardening (`disable_functions`, `open_basedir`), WAF.

- [12-Skills_Assessment.md](12-Skills_Assessment.md) — Tiny File Manager 2.4.6 with guest creds — exploited via command injection in `to=` param of move operation with combined `;c'a't${IFS}${PATH:0:1}flag.txt` bypass chain.
