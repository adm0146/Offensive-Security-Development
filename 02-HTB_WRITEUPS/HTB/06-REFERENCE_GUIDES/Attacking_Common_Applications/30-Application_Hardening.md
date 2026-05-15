# Section 30 — Application Hardening

> **No lab / no questions.** Defensive theory section before the three skills assessments (31–33). Value here is for **report remediation sections** and the **Documentation & Reporting** module — so this guide maps each control back to the attack from §3–§29 it actually defeats.

---

## Step 0 — Application inventory (you can't protect what you don't know exists)

First control for any org: an accurate inventory of internal *and* external-facing apps.
- Blue teams can use **Nmap + EyeWitness** (same recon we use offensively) to build it.
- Surfaces **shadow IT**, deprecated apps, and trial→free downgrades that silently drop auth (e.g. **Splunk** free edition no longer enforcing login — see §13/§14).

> Pentest tie-in: this is why our first move every assessment is broad discovery + EyeWitness. The defensive and offensive first step are identical — the org that runs it first wins.

---

## General hardening → attack it stops

| Control | Stops (from this module) |
|---|---|
| **Strong/changed default creds; disable default admin; mandatory 2FA for admins** | Tomcat Manager default creds (§9/§10), Nagios `nagiosadmin:PASSW0RD`, WebSphere `system:manager`, Splunk/PRTG defaults, brute-force (§ Login BF) |
| **Access controls — admin/login not internet-facing; IP allow-list; file/deploy perms** | Tomcat `/manager` WAR deploy RCE, Jenkins script console, ColdFusion admin (§24), WebLogic console (§29) |
| **Disable unsafe features** (WP PHP editor, etc.) | WordPress theme/plugin-editor → RCE (§4), built-in-functionality RCE generally |
| **Regular patching** | All version-gated CVEs: ColdFusion §24, WebLogic §29, Drupal/Joomla, FCKeditor, CVE-2020-14882 |
| **Backups to a secondary location** | Fast recovery after webshell/ransomware; doesn't prevent, limits impact |
| **Security monitoring / WAF** | Detects/slows tilde-enum (§25), SQLi/LDAPi (§26), upload brute-force; *layer not silver bullet* |
| **LDAP/AD SSO integration** | Fewer standalone passwords/service accounts to leak (§28 connection-string creds), central password policy + auditing |

> The recurring theme of §3–§29: **default password + exposed built-in functionality = RCE.** Hardening is mostly "change defaults, restrict who can reach the admin surface, patch, and watch."

---

## Application-specific hardening

| App | Category | Measure |
|-----|----------|---------|
| WordPress | Monitoring | WordFence (blocking, country block, 2FA, monitoring) |
| Joomla | Access control | AdminExile — secret key on admin URL (`/administrator?secretkey`) |
| Drupal | Access control | Disable / hide / move the admin login page |
| Tomcat | Access control | `/manager` + `/host-manager` → **localhost only**; if external: IP allow-list, strong pw, non-standard username |
| Jenkins | Access control | Matrix Authorization Strategy plugin (granular perms) |
| Splunk | Updates/licensing | Change default pw; license properly so auth stays enforced |
| PRTG | Secure auth | Stay current; change default PRTG password |
| osTicket | Access control | Restrict from internet where possible |
| GitLab | Secure auth | Sign-up restrictions: admin approval, domain allow/deny lists |

---

## Exam / Report Notes

- **Remediation writing:** don't just say "weak password" — pair finding → control → business reason. E.g. *"Tomcat Manager exposed with default creds → restrict to localhost + IP allow-list + strong non-default username; rationale: prevents unauthenticated WAR-deploy RCE."*
- **Least privilege + reduce internet exposure** are the two highest-leverage recommendations across nearly every app in this module — lead with them.
- **Inventory + regular reassessment** is a *process* recommendation (mindset shift), not a config change — call these out separately in reports; they prevent recurrence.
- Trial→free auth-drop (Splunk) and shadow IT are classic findings an inventory exposes — mention proactively.
- This section commonly yields **knowledge-recall questions** in the assessment-style modules (which plugin hardens Joomla admin? → AdminExile; Tomcat manager → localhost-only). Static facts — answer from the table, no box needed (cf. §22 static-vs-runtime rule).

---

## Conclusion (module framing)

Apps are the bulk of the external attack surface and are routinely overlooked. The module's through-line: **discover → footprint version → known-CVE/built-in-functionality → pivot creds elsewhere.** Orgs patch well but miss weak Tomcat Manager creds or a default-cred printer leaking LDAP creds for an internal foothold. The next three sections (31–33) are skills assessments testing exactly this discovery→exploitation pipeline.

> No answer to submit for §30. Proceed to §31 (Skills Assessment I).
