# WSTG CONF — Configuration & Deployment Management

OWASP WSTG v4.2. Tests WSTG-CONF-01 → 11.

- [CONF-01 Network Infrastructure Config](#wstg-conf-01)
- [CONF-02 Application Platform Config](#wstg-conf-02)
- [CONF-03 File Extensions Handling](#wstg-conf-03)
- [CONF-04 Old/Backup/Unreferenced Files](#wstg-conf-04)
- [CONF-05 Admin Interfaces](#wstg-conf-05)
- [CONF-06 HTTP Methods](#wstg-conf-06)
- [CONF-07 HSTS](#wstg-conf-07)
- [CONF-08 RIA Cross Domain Policy](#wstg-conf-08)
- [CONF-09 File Permission](#wstg-conf-09)
- [CONF-10 Subdomain Takeover](#wstg-conf-10)
- [CONF-11 Cloud Storage](#wstg-conf-11)

---

## WSTG-CONF-01

**Test Network Infrastructure Configuration**

Goal: one vuln anywhere in shared infra (web server, back-end DB, auth server, reverse proxy) can compromise every app on it. Map architecture (see INFO-10), then review each element's config + known vulns; ensure no unmaintained software or default settings/credentials.

**Steps:**
1. Determine infra elements + how they interact with app.
2. Review each for known vulns.
3. Review admin tools used to maintain them.
4. Review auth systems: fit app needs, not manipulable by external users.
5. Keep required app ports list under change control.

**Known server vulns:**
- Blind remote testing hard; automated tools unpredictable, DoS tests may be impossible in prod.
- Version-based scanners → false positives (vendors back-port patches without version bump: Debian, Red Hat, SuSE) + false negatives (version hidden). Only see exposed elements, not auth back ends/DBs/reverse proxies.
- Some vendors fix silently, no public advisory → scanners weak on lesser-known products.
- Best: internal info (versions, patches) → match vendor advisories, test real effect, account for IDS/IPS. Flag unsupported versions: no patches ever, upgrade may need downtime/re-coding.

**Admin tools:** web admin UIs (iPlanet), text config (Apache), OS GUI (IIS); file maintenance via FTP, WebDAV, NFS, CIFS; in-app admin interfaces. For each: find access controls + weaknesses, change default credentials. Outsourced content management often exposes admin interfaces to Internet → test them.

**Refs:** vuln DBs: Bugtraq, X-Force, NIST NVD.

---

## WSTG-CONF-02

**Test Application Platform Configuration**

Goal: remove defaults/known files, no debug code/extensions in prod, review logging.

**Black-box:**
- **Sample/known files:** default samples often vulnerable — CVE-1999-0449 (IIS Exair DoS), CAN-2002-1744 (IIS 5.0 CodeBrws.asp traversal), CAN-2002-1630 (Oracle 9iAS sendmail.jsp), CAN-2003-1172 (Cocoon view-source traversal). CGI scanners check known lists; only full content review is sure.
- **Comments:** spider site, store all content, grep HTML comments for internal info / commented-out code.
- **Baseline tools:** CIS-CAT Lite, Microsoft Attack Surface Analyzer, NIST National Checklist Program.

**Gray-box config review:**
- Enable only needed modules (e.g. IIS ISAPI extensions).
- Custom 40x/50x pages; no app errors/code leaked.
- Run server with minimal OS privileges.
- Log legit access + errors.
- Handle overload/DoS; performance-tuned.
- IIS: only admins + `NT SERVICE\WMSvc` access `applicationHost.config`, `redirection.config`, `administration.config` (not `Network Service`, `IIS_IUSRS`, `IUSR`, app pool identities). Never share them on network; with Shared Configuration export `applicationHost.config` elsewhere.
- `machine.config` + root `web.config` world-readable → no admin-only secrets; encrypt worker-process-only data.
- Shared config: read-only identity for web server; separate publishing identity; strong password on exported keys; restrict share (firewall + IPsec) — compromise = read/write all IIS config, traffic redirect, code in worker processes.

**Logging checklist:**
1. Sensitive info in logs?
2. Stored on dedicated server?
3. Can log usage cause DoS?
4. Rotation + retention sufficient?
5. Reviewed? Detect targeted attacks?
6. Backups preserved?
7. Data validated (length, chars) before logging?

**Sensitive info:** GET form data lands in logs (credentials, bank details); logs obtainable via admin UIs, server vulns, Apache `server-status` misconfig. Watch for: debug info, stack traces, usernames, component names, internal IPs, personal data, business data, source code, session IDs, access tokens, PII, passwords, DB connection strings, encryption keys, card/bank data, data above log system's classification, commercially sensitive or illegal-to-collect data, data user opted out of. Personal data in logs may trigger data-protection obligations.

**Location:** local logs wiped on compromise ("log zapper" in rootkits) → ship to separate server (also eases aggregation/analysis).

**Storage:** log flood can fill disk → OS/app fail. Put logs (`/var`, `/opt`, `/usr/local`; e.g. `/var/log/apache`) on dedicated partition; monitor growth. Test (dangerous in prod): sustained requests, large `QUERY_STRING` values.

**Rotation:** retention per policy; compress rotated logs; rotated perms ≥ live (server can't modify); size-based rotation not forceable by attacker.

**Access control:** no end user/unauthenticated access; web admins shouldn't see raw logs (separation of duty); log viewers' ACL separate from app roles.

**Review:** many 40x from one source → CGI scanner; 50x → attacker hitting failures (e.g. early SQLi). Don't generate log stats on the logging server.

**Refs:** Apache Security (Ristic); Lotus Security Handbook (IBM Redbooks); Security Best Practices for IIS 8; CIS Microsoft IIS Benchmarks; NSA iPlanet guide; IBM WebSphere V5.0 Security; OWASP Logging Cheat Sheet; NIST SP 800-92; PCI DSS v3.2.1 Req 10 / PA-DSS v3.2 Req 4; CERT Securing Public Web Servers; IISLockdown.exe.

---

## WSTG-CONF-03

**Test File Extensions Handling for Sensitive Information**

Goal: learn which extensions are executed vs served as `text/plain` (reveals tech, e.g. `.pl` → Perl, though renamable); find raw data/credential files; check upload filter bypasses.

**Forced browsing:** request various extensions per directory, esp. script-exec dirs. Load-balanced → test every server (IIS + Apache mix may behave asymmetrically).

Example — `connection.inc` served raw:

```
<?
mysql_connect("127.0.0.1", "root", "password")
or die("Could not connect");
?>
```

| Never serve | Check intended + non-sensitive |
|---|---|
| `.asa`, `.inc`, `.config` | archives (`.zip`, `.tar`, `.gz`, `.tgz`, `.rar`), `.java`, `.txt`, `.pdf`, Office (`.docx`, `.rtf`, `.xlsx`, `.pptx`), backups (`.bak`, `.old`, `~`) |

More extensions: FILExt. Find files via scanners, spider/mirror, manual inspection, search engines (INFO-01); see CONF-04.

**Upload — Windows 8.3 bypass:**
1. `file.phtml` processed as PHP.
2. `FILE~1.PHT` served, not processed by PHP ISAPI handler.
3. `shell.phPWND` uploadable.
4. `SHELL~1.PHP` expanded by OS, processed by PHP ISAPI handler.

**Gray-box:** check server configs for extension handling; heterogeneous load balancing differences.

**Tools:** Nessus, Nikto, wget, curl, web mirroring tools.

---

## WSTG-CONF-04

**Review Old Backup and Unreferenced Files for Sensitive Information**

Goal: find forgotten files — renamed old versions, include files, archives, editor backups (`file~`), manual copies (`file.old`), FS snapshots — that leak source, credentials, admin functions.

Why: `login.asp.old` served as text → source disclosed (logic, paths, clear-text credentials).

**Threats:**
- Include/config files with DB creds, hidden content refs, absolute paths.
- Unlinked admin pages reachable by anyone.
- Old versions keep fixed vulns (`viewdoc.old.jsp` traversal fixed in `viewdoc.jsp`; `/.snapshot/monthly.1/view.php`).
- `viewdoc.bak` → source of `viewdoc.jsp`.
- Archives (`myservlets.jar.old`) → whole app, decompilable.
- "Copy of " files (Windows) keep extension → no source leak, but obsolete logic may error verbosely.
- Log files (session IDs, URL params, URLs); ftp logs (admin activity).

**Black-box:**

*Naming inference:* `viewuser.asp` → try `edituser.asp`, `adduser.asp`, `deleteuser.asp`; `/app/user` → `/app/admin`, `/app/manager`.

*Clues in content:*

```
<!-- <A HREF="uploadfile.jsp">Upload a document to the server</A> -->
<!-- Link removed while bugs in uploadfile.jsp are fixed
-->

var adminUser=false;
if (adminUser) menu.add (new menuItem ("Maintain users", "/admin/useradmin.jsp"));

<form action="forgotPassword.jsp" method="post">
<input type="hidden" name="userID" value="123">
<!-- <input type="submit" value="Forgot Password"> -->
</form>
```

`/robots.txt`:

```
User-agent: *
Disallow: /Admin
Disallow: /uploads
Disallow: /backup
Disallow: /~jbloggs
Disallow: /include
```

*Blind guessing* (wordlist on stdin; HEAD faster than GET):

```
#!/bin/bash
server=example.org
port=80
while read url
do
echo -ne "$url\t"
echo -e "GET /$url HTTP/1.0\nHost: $server\n" | netcat $server $port | head -1
done | tee outputfile
```

Interesting codes: 200 (unless custom 404), 301, 302, 401, 403, 500. Run on webroot + every found dir. Improve: append known extensions (jsp, aspx, html); derive wordlists from found filenames; try `~ bak txt src dev old inc orig copy tmp swp` before/after/instead of real extension.

*Server vulns/misconfig:* directory listing; Apache `?M=D` listing; IIS script source disclosure; IIS WebDAV listing.

*Public info:* search engine archives + caches (`site:www.example.com`, see INFO-01); third-party sites linking bespoke functionality.

*Filename filter bypass* — Windows 8.3 (`c:\\program files` → `C:\\PROGRA\~1`): drop incompatible chars, spaces → `_`, first 6 chars of basename + `~<digit>` (scheme changes after 3 collisions), extension truncated to 3, uppercase.

**Gray-box:** scan served dirs for backup-like names (predictable → scriptable); scheduled job + periodic manual checks.

**Remediation:**
- Policy: no in-place editing on prod; no leftover archives from admin work.
- Config management to prevent obsolete files.
- Keep data/log/config outside web tree.
- Block snapshot dirs:

```
<Location ~ ".snapshot">
Order deny,allow
Deny from all
</Location>
```

**Tools:** Nessus, Nikto2; spiders: wget, Wget for Windows, Sam Spade, Spike proxy, Xenu, curl.

---

## WSTG-CONF-05

**Enumerate Infrastructure and Application Admin Interfaces**

Goal: find hidden admin interfaces (account provisioning, layout, data, config) + check unauthorized/standard user access.

**Black-box vectors:**
- Dir/file enumeration: `/admin`, `/administrator`, Google dorks, brute force.
- Comments/links in client source.
- Server/app docs for default config paths + default passwords.
- Public info (e.g. WordPress default admin).
- Alternate ports (Tomcat admin often 8080).
- Parameter tampering:

```
<input type="hidden" name="admin" value="no">
Cookie: session_cookie; useradmin=0
```

Found → try auth bypass, then brute force (beware lockout). Related: authz bypass, IDOR tests.

**Gray-box:** verify admin pages restricted (IP filtering etc.), no default creds, clear user/admin separation in authz model + shared UI.

**Default paths:**

| Platform | Paths |
|---|---|
| WebSphere | `/admin`, `/admin-authz.xml`, `/admin.conf`, `/admin.passwd`, `/admin/*`, `/admin/logon.jsp`, `/admin/secure/logon.jsp` |
| PHP | `/phpinfo`, `/phpmyadmin/`, `/phpMyAdmin/`, `/mysqladmin/`, `/MySQLadmin`, `/MySQLAdmin`, `/login.php`, `/logon.php`, `/xmlrpc.php`, `/dbadmin` |
| FrontPage | `/admin.dll`, `/admin.exe`, `/administrators.pwd`, `/author.dll`, `/author.exe`, `/author.log`, `/authors.pwd`, `/cgi-bin` |
| WebLogic | `/AdminCaptureRootCA`, `/AdminClients`, `/AdminConnections`, `/AdminEvents`, `/AdminJDBC`, `/AdminLicense`, `/AdminMain`, `/AdminProps`, `/AdminRealm`, `/AdminThreads` |
| WordPress | `wp-admin/`, `wp-admin/about.php`, `wp-admin/admin-ajax.php`, `wp-admin/admin-db.php`, `wp-admin/admin-footer.php`, `wp-admin/admin-functions.php`, `wp-admin/admin-header.php` |

**Tools:** OWASP ZAP Forced Browse (DirBuster successor), THC-HYDRA, netsparker dictionary.

**Refs:** Cirt default password list; FuzzDB admin paths; common admin/debug parameters.

---

## WSTG-CONF-06

**Test HTTP Methods**

Goal: enumerate methods (RFC 7231: GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE), test access control bypass, XST, method overriding. Most apps need only GET + POST; REST endpoints should accept only what they need.

**Discover:** OPTIONS, then verify by sending each method.

```
nmap -p 443 --script http-methods --script-args http-methods.url-path='/index.php' localhost
```

**PUT:** capture request in proxy, change to PUT; 2XX/3XX + GET confirms file → vulnerable (RCE, defacement, DoS). Try other paths if base rejects. Remove any uploaded web shell after PoC.

```
PUT /test.html HTTP/1.1
Host: testing-website
<html>
HTTP PUT Method is Enabled
</html>
```

**Access control bypass:** on page that redirects to login for GET, try HEAD, POST, PUT and made-up methods (BILBAO, FOOBAR, CATS). `200 OK` non-login page → bypass.

```
$ ncat www.example.com 80
HEAD /admin HTTP/1.1
Host: www.example.com
HTTP/1.1 200 OK
...
Set-Cookie: adminOnlyCookie1=...; expires=Tue, 18-Aug-2009 22:44:31 GMT; domain=www.example.com
```

Exploit blind:

```
HEAD /admin/createUser.php?member=myAdmin
PUT /admin/changePw.php?member=myAdmin&passwd=foo123&confirm=foo123
CATS /admin/groupEdit.php?group=Admins&member=myAdmin&action=add
```

**XST:** TRACE reflects request → can leak `HttpOnly` cookies/auth headers (Grossman 2003; old browsers via XHR, modern only with Flash-like tech).

```
$ ncat www.victim.com 80
TRACE / HTTP/1.1
Host: www.victim.com
Random: Header
HTTP/1.1 200 OK
Random: Header
...
```

Reflected in HTML context → `Attack: <script>prompt()</script>` header.

**Method override:** headers `X-HTTP-Method`, `X-HTTP-Method-Override`, `X-Method-Override` tunnel blocked verbs past proxies/firewalls. If `405 Method Not Allowed` becomes 200 with header → supported.

```
$ ncat www.example.com 80
DELETE /resource.html HTTP/1.1
Host: www.example.com
HTTP/1.1 405 Method Not Allowed
Allow: GET,HEAD,POST,OPTIONS

$ ncat www.example.com 80
DELETE /resource.html HTTP/1.1
Host: www.example.com
X-HTTP-Method: DELETE
HTTP/1.1 200 OK
```

**Remediation:** allow only required methods/headers, correctly configured; no workarounds bypassing user-agent/framework/server controls.

**Tools:** Ncat, cURL, nmap http-methods NSE, w3af htaccess_methods.

**Refs:** RFC 2109/2965; HTACCESS: BILBAO Method Exposed; Amit Klein XS(T) variants; Fortify Misused HTTP Method Override; CAPEC-107.

---

## WSTG-CONF-07

**Test HTTP Strict Transport Security**

Goal: verify `Strict-Transport-Security` header → browser forces HTTPS, no cert-error override. Mitigates sniffing, MITM via untrusted certs, mistyped/linked `http://`.

| Directive | Meaning |
|---|---|
| `max-age` | seconds to auto-upgrade HTTP → HTTPS |
| `includeSubDomains` | all subdomains HTTPS |
| `preload` | unofficial; on browser preload list (hstspreload.org) |

```
$ curl -s -D- https://owasp.org | grep -i strict
Strict-Transport-Security: max-age=31536000
```

**Refs:** OWASP HSTS; OWASP Appsec Tutorial Ep. 4; HSTS spec.

---

## WSTG-CONF-08

**Test RIA Cross Domain Policy**

Goal: review `crossdomain.xml` (Adobe; Java, Flash, Reader) + `clientaccesspolicy.xml` (Silverlight; uses `crossdomain.xml` only if it allows any domain). Master policy at root; client checks it first. Permissions: accepted policy files, sockets, headers, HTTP/HTTPS access, crypto-credential access.

**Abuse:** overly permissive policy; server responses or uploaded files treated as policy → defeat CSRF protections, read cross-origin-protected data.

Overly permissive:

```
<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM
"http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
<site-control permitted-cross-domain-policies="all"/>
<allow-access-from domain="*" secure="false"/>
<allow-http-request-headers-from domain="*" headers="*" secure="false"/>
</cross-domain-policy>
```

**Test:** fetch both files from root + every folder (e.g. `http://www.owasp.org/crossdomain.xml`). Check least privilege (domains, ports, protocols); scrutinize `*`. Output: policy files found + weak settings.

**Tools:** Nikto, OWASP ZAP, W3af.

**Refs:** Adobe cross-domain policy spec + Flash usage recommendations; Oracle Cross-Domain XML Support; MSDN Silverlight cross-domain + network restrictions; Esser "Poking new holes with Flash Crossdomain Policy Files"; Grossman "Crossdomain.xml Invites Cross-site Mayhem"; UCSD Flash crossdomain analysis.

---

## WSTG-CONF-09

**Test File Permission**

Goal: find over-broad permissions (world-readable config with API tokens, executables runnable by anyone).

```
$ namei -l /PathToCheck/
```

Check: web, config, sensitive (keys, passwords, encrypted data), logs, executables (scripts, EXE, JAR, class, PHP, ASP), DB, temp, upload files/dirs.

**Remediation:** least-privilege file/dir permissions.

**Tools:** AccessEnum, AccessChk (Windows); `ls`, `namei` (Linux).

**Refs:** CWE-732.

---

## WSTG-CONF-10

**Test for Subdomain Takeover**

Goal: find DNS records (`A`, `CNAME`, `MX`, `NS`, `TXT`) pointing to inactive external services whose provider doesn't verify ownership → attacker claims subdomain (malicious content, phishing, cookie/credential theft). `NS` takeover = worst: whole DNS zone.

**Scenarios:**
- GitHub: `coderepo.victim.com` left in DNS after leaving GitHub → attacker claims via GitHub Pages.
- Expired domain: `www.victim.com` CNAME → `victimotherdomain.com` expires → registrant controls `www.victim.com`.

**Black-box:** enumerate DNS (dictionary, brute force, OSINT). Suspicious `dig` responses: `NXDOMAIN`, `SERVFAIL`, `REFUSED`, no servers reachable.

*A/CNAME:*

```
$ ./dnsrecon.py -d victim.com
...
A subdomain.victim.com 192.30.252.153
CNAME subdomain1.victim.com fictioussubdomain.victim.com

$ dig CNAME fictioussubdomain.victim.com
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 42950

$ whois 192.30.252.153 | grep "OrgName"
OrgName: GitHub, Inc.
```

GitHub "404 - File not found" on subdomain → vulnerable; claim via GitHub Pages.

*NS:*

```
$ dig ns victim.com +short
ns1.victim.com
nameserver.expireddomain.com
```

Nameserver domain available at registrar → vulnerable. Watch `SERVFAIL`/`REFUSED`.

**Gray-box:** same, using zone file.

**Remediation:** remove dangling records; monitor continuously.

**Tools:** dig, recon-ng, theHarvester, Sublist3r, dnsrecon, OWASP Amass.

**Refs:** HackerOne Guide To Subdomain Takeovers; Subdomain Takeover: Basics / Going beyond CNAME; Frans Rosén AppSec EU 2017.

---

## WSTG-CONF-11

**Test Cloud Storage**

Goal: verify storage access control (e.g. S3 buckets private by default, but bucket/object ACLs can be made public → unauthorized read/upload/modify).

**Test** unauthorized read + upload:

```
curl -X GET https://<cloud-storage-service>/<object>
curl -X PUT -d 'test' 'https://<cloud-storage-service>/test.txt'
```

**S3 URL formats:**

| Style | Regional | Legacy global |
|---|---|---|
| Virtual hosted | `https://bucket-name.s3.Region.amazonaws.com/key-name` | `https://bucket-name.s3.amazonaws.com` |
| Path | `https://s3.Region.amazonaws.com/bucket-name/key-name` | `https://s3.amazonaws.com/bucket-name` |

Find bucket URLs: black-box via HTTP responses (e.g. `<img src="https://my-bucket.s3.us-west-2.amazonaws.com/puppy.png">`); gray-box via AWS console, docs, source.

**AWS CLI:**

```
aws s3 ls s3://<bucket-name>
aws s3 cp arbitrary-file s3://bucket-name/path-to-save
aws s3 rm s3://bucket-name/object-to-remove
```

Upload denied → `An error occurred (AccessDenied) when calling the PutObject operation: Access Denied`.

**Tools:** AWS CLI.

**Refs:** Working with Amazon S3 Buckets; flAWS 2.
