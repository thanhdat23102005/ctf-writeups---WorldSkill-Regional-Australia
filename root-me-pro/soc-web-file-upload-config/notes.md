# SOC Web - File upload - Config (Root-Me Pro)

Platform instance: OpenSearch Dashboards (osd-name: soc-dashboards) at
https://soc.challenges.root-me.pro/?token=<jwt>

Auth: token in query param sets session cookies (security_authentication*),
redirects to /app/data-explorer/discover.

No browser extension available this session -> drove the OSD REST API directly
with curl + the Dev Tools console proxy: `/api/console/proxy?path=<index>/_search&method=POST`.

Index patterns (via /api/saved_objects/_find?type=index-pattern):
- index-80261c659cc3-apache  (apache access logs, field `log` = raw combined log line, parsed fields: clientip, verb, request, response, bytes, agent, @timestamp)
- index-80261c659cc3-audit

## Step 1 - find attacker's first request

Aggregated apache index on `clientip.keyword` (terms agg, size 20):
- 106.33.14.71 -> 4801 hits  <-- massive outlier (the "fuzzing spike")
- everyone else -> 150-171 hits (normal background/bot traffic)

Sorted all hits from 106.33.14.71 by @timestamp asc, first hit:

  2025-09-08T13:08:03.522502Z
  106.33.14.71 - - [08/Sep/2025:15:08:03 +0200] "GET /phpinfo.php HTTP/1.1" 200 73738 "-" "curl/7.88.1"

Note: manual `curl/7.88.1` UA probing /phpinfo.php directly, before switching to a
spoofed Firefox UA and starting the fuzzing spree seconds later (/. bash_history,
/.bashrc, etc. -> looks like config/dotfile fuzzing, matches challenge title
"File upload - Config").

**request column value / flag: /phpinfo.php**

## Step 2 - fuzzing start time

Chronological listing of attacker (106.33.14.71) requests shows manual recon
(curl -> phpinfo.php, then browser UA -> /phpinfo.php, then /) ending at 13:09:20,
then a burst of alphabetically-ordered dotfile/config paths (/.bash_history,
/.bashrc, /.cache, /.config, ...) starting at 13:09:32.401452Z, spaced ~12ms apart
-> automated fuzzer (wordlist tool, not a human) kicks off here.

**Fuzzing began: 13:09:32.401 (UTC)**

## Step 3 - first uploaded file content

Apache audit index (index-80261c659cc3-audit) has full request bodies. Filtered
on transaction.remote_address = 106.33.14.71 AND request_line starts with POST,
sorted asc. All uploads POST JSON to "/" with shape:
  {"files":[{"name":..,"type":..,"data":<base64>}],"name":..,"description":..}

First upload @ 2025-09-08T13:12:45.743250Z:
  name: this-is-a-test.md, type: text/markdown
  base64: SGV5IHRoaXMgaXMgYSAxMDAlIG5vcm1hbCB0ZXh0IGZpbGUgOikKCkRvbid0IG1pbmQsIGknbSByZWFsbHkgbm90IGEgaGFja2VyLgo=
  decoded:
    Hey this is a 100% normal text file :)

    Don't mind, i'm really not a hacker.

Subsequent uploads (all shell.php / shell.php8 / shell.jpg / case+traversal
variants, same PHP webshell with ls/cat/cmd GET params) confirm this first
"harmless" .md upload was a test of the upload feature itself before the real
attack (extension filter bypass -> RCE via uploaded PHP webshell).

**Answer (first line of first uploaded file): Hey this is a 100% normal text file :)**

## Step 4 - file that unlocked /admin

Upload @ 2025-09-08T13:27:10.360582Z, POST / body:
  {"files":[{"name":"../../admin/.htaccess","type":"","data":"QXV0aFR5cGUgTm9uZQpSZXF1aXJlIGFsbCBncmFudGVkCg=="}],"name":"Hellohtaccess","description":"yehaa"}
  decoded data: "AuthType None\nRequire all granted\n"

Confirmed effect in apache index: GET /admin was 401 at 13:27:01, then right after
this upload: GET /admin -> 301 @ 13:27:14.899, GET /admin/ -> 200 @ 13:27:14.938.

Path traversal via the "name" field (../../) writes the .htaccess into the
protected admin/ dir, overriding its auth requirement (Apache 2.4 "Require all
granted"). Earlier attempt at 13:26:50 uploaded "../../.htaccess" (webroot, not
admin) - didn't fix the 401, hence the retry targeting admin/ specifically.

**Answer (name field): ../../admin/.htaccess**

## Step 5 - time admin access succeeded

Audit index, attacker's two /admin requests around the .htaccess upload:
  GET /admin  -> transaction.time 08/Sep/2025:15:27:14.898736 +0200 (this one 301-redirects)
  GET /admin/ -> transaction.time 08/Sep/2025:15:27:14.938041 +0200 (this one is the 200 OK)

transaction.time is local time with +0200 offset; UTC = local - 2h, keep the
6-digit microseconds as-is.

**Answer: 13:27:14.938041**
