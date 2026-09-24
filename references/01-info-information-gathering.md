# WSTG INFO — Information Gathering

OWASP WSTG v4.2. Tests WSTG-INFO-01 → 10.

- [INFO-01 Search Engine Recon](#wstg-info-01)
- [INFO-02 Fingerprint Web Server](#wstg-info-02)
- [INFO-03 Webserver Metafiles](#wstg-info-03)
- [INFO-04 Enumerate Applications](#wstg-info-04)
- [INFO-05 Webpage Content Leakage](#wstg-info-05)
- [INFO-06 Entry Points](#wstg-info-06)
- [INFO-07 Execution Paths](#wstg-info-07)
- [INFO-08 Fingerprint Framework](#wstg-info-08)
- [INFO-09 Fingerprint App](#wstg-info-09) (merged into 08)
- [INFO-10 Map Architecture](#wstg-info-10)

---

## WSTG-INFO-01

**Conduct Search Engine Discovery Reconnaissance for Information Leakage**

Goal: find sensitive design/config info exposed directly (org site) or indirectly (forums, newsgroups, tender sites, third parties). Stale robots.txt / missing noindex → unintended content indexed.

**Look for:** network diagrams/configs; archived admin posts/emails; logon procedures, username formats; usernames/passwords/private keys; third-party/cloud config files; revealing error messages; dev/test/UAT/staging sites.

**Engines** (use several, results differ): Baidu, Bing, binsearch.info (Usenet), Common Crawl, DuckDuckGo, Google, Wayback Machine, Startpage, Shodan (devices/services). DuckDuckGo/Startpage leak less about tester.

**Operators** (`operator:query`):

| Op | Effect |
|---|---|
| `site:` | limit to domain |
| `inurl:` | keyword in URL |
| `intitle:` | keyword in title |
| `intext:` / `inbody:` | keyword in body |
| `filetype:` | file type (png, php…) |
| `cache:` | cached copy (changed/removed content) |

```
site:owasp.org
cache:owasp.org
```

**Dorking:** chain operators. Google Hacking Database categories: Footholds, Files w/ usernames, Sensitive Directories, Web Server Detection, Vulnerable Files, Vulnerable Servers, Error Messages, Files w/ juicy info, Files w/ passwords, Sensitive Online Shopping Info. Bing/Shodan dorks: Bishop Fox Google Hacking Diggity Project.

**Remediation:** weigh sensitivity before posting; re-review posted info periodically.

---

## WSTG-INFO-02

**Fingerprint Web Server**

Goal: ID server type/version → find known vulns in unpatched versions. Method: elicit response, compare to known-response DB.

**Banner grabbing** (telnet for HTTP, openssl for TLS):

```
HTTP/1.1 200 OK
Date: Thu, 05 Sep 2019 17:42:39 GMT
Server: Apache/2.4.41 (Unix)
```

Other banners: `Server: nginx/1.17.3`, `Server: lighttpd/1.4.54`. Obfuscated: `Server: Website.com`.

**Header order** (guess when Server obscured; not definitive):

| Server | Order |
|---|---|
| Apache | Date, Server, Last-Modified, ETag, Accept-Ranges, Content-Length, Connection, Content-Type |
| nginx | Server, Date, Content-Type, … |
| lighttpd | Content-Type, Accept-Ranges, ETag, Last-Modified, Content-Length, Connection, Date, Server |

**Malformed requests:** default error pages differ, fingerprint even w/ obscured headers.

```
GET / SANTA CLAUS/1.1
```

| Server | Response |
|---|---|
| Apache | `400 Bad Request`, "Your browser sent a request that this server could not understand." |
| nginx | `404 Not Found` page, footer `<hr><center>nginx/1.17.3</center>` |
| lighttpd | `HTTP/1.0 400`, XHTML 1.0 Transitional error page |

**Tools:** Netcraft (online), Nikto, Nmap (Zenmap GUI). Faster + bigger signature DBs than manual.

**Remediation:** not a vuln itself, aids exploitation. Obscure Server header (Apache `mod_headers`); hardened reverse proxy in front; patch.

---

## WSTG-INFO-03

**Review Webserver Metafiles for Information Leakage**

Goal: find hidden paths/functionality + tech/OSINT info via metadata files. ZAP/Burp spiders parse these automatically; also findable via `inurl:` dorks.

**robots.txt** (web root). Robots Exclusion Protocol, advisory only, crawlers may ignore.

```
$ curl -O -Ss http://www.google.com/robots.txt && head -n5 robots.txt
User-agent: *
Disallow: /search
Allow: /search/about
```

`User-agent: *` = all bots (`Googlebot`, `bingbot` = specific). `Disallow` paths = interesting targets.

**Robots META:** `<META NAME="ROBOTS" ...>` in HEAD; absent → `INDEX,FOLLOW`; `NOINDEX`/`NOFOLLOW`. Regex-search pages, compare against robots.txt Disallow.

**Misc META:** `og:*`, `twitter:*`, `fb:app_id`, `application-name`, `theme-color` → tech ID, extra paths, social accounts.

**sitemap.xml:** maps site fast. Index points to nested sitemaps:

```
$ wget --no-verbose https://www.google.com/sitemap.xml && head -n8 sitemap.xml
<sitemapindex xmlns="http://www.google.com/schemas/sitemap/0.84">
<sitemap><loc>https://www.google.com/gmail/sitemap.xml</loc></sitemap>
```

**security.txt:** `/security.txt` or `/.well-known/security.txt`. Fields `Contact`, `Encryption`, `Canonical`, `Policy` → paths, OSINT, bug bounty, social engineering.

**humans.txt:** lists people behind site, often career info.

**Other `.well-known/`:** build list from RFCs/drafts, feed to fuzzer.

**Tools:** browser view-source/DevTools, curl, wget, Burp Suite, ZAP.

---

## WSTG-INFO-04

**Enumerate Applications on Webserver**

Goal: find ALL apps reachable on in-scope targets. Scope often just IPs or incomplete IP+DNS pairs; one IP may host many apps. Hidden/"internal" apps often outdated or misconfigured.

**Three reasons apps hide:**

1. **Non-base URL:** `http://www.example.com/url1`, `/url2`, root blank.
2. **Non-standard port:** `http://www.example.com:20000/`.
3. **Virtual hosts:** one IP → `www.`, `helpdesk.`, `webmail.example.com` via HTTP/1.1 `Host`.

**1 — Non-standard URLs:** directory browsing on misconfigured servers; search `site:www.example.com`; guess common paths (`/webmail`, `webmail.`, `mail.`, hidden Tomcat admin); dictionary scans; vuln scanners.

**2 — Non-standard ports:** full TCP scan w/ service detection.

```
nmap -Pn -sT -sV -p0-65535 192.168.1.100
```

| Port | Service | Note |
|---|---|---|
| 22 | ssh OpenSSH 3.5p1 | |
| 80 | Apache httpd 2.0.40 | |
| 443 | ssl | confirm HTTPS by browsing |
| 901 | Samba SWAT | web admin |
| 1241 | ssl, Nessus | not real HTTPS |
| 3690 | unknown | |
| 8000 | http-alt? | confirm manually |
| 8080 | Tomcat/Coyote | |

Confirm unknown port:

```
$ telnet 192.168.1.100 8000
GET / HTTP/1.0

HTTP/1.0 200 OK
Server: MX4J-HTTPD/1.0
```

Nessus scans all ports, flags known admin interfaces (e.g. Tomcat).

**3 — Virtual hosts:**

- **Zone transfer** (usually refused, still try):
  ```
  $ host -t ns www.owasp.org
  owasp.org name server ns1.secure.net.
  $ host -l www.owasp.org ns1.secure.net
  Host www.owasp.org not found: 5(REFUSED)
  ```
  No name for IP → try name servers of known related domain.
- **Inverse query:** PTR lookup on IP.
- **Web DNS search:** Netcraft Search DNS.
- **Reverse-IP services** (use several): Domain Tools Reverse IP, Bing `ip:x.x.x.x`, `http://whois.webhosting.info/x.x.x.x`, DNSstuff, Net Square.
- **Googling:** search newly found domains for more names/URLs.

**Tools:** nslookup, dig, host; search engines; Nmap; Nessus; Nikto.

---

## WSTG-INFO-05

**Review Webpage Content for Information Leakage**

Goal: find leaks in HTML comments/metadata, front-end JS, exposed source maps.

**HTML comments** (`<!--`): SQL, creds, internal IPs, debug info.

```
<!-- Query: SELECT id, name FROM app.users WHERE active='1' -->
<!-- Use the DB administrator password for testing: f@keP@a$$w0rD -->
```

**DOCTYPE:** check version + DTD (`strict.dtd`, `loose.dtd`, `frameset.dtd`).

**META tags** (profiling, not direct vectors): `Author`, `Refresh`, `keywords`, `robots` (`none` = noindex+nofollow). PICS/POWDER = content metadata frameworks.

**JavaScript:** inline `<script>` + external `.js` (`src` attr). Look for API keys, internal IPs, hidden routes, creds.

```
var conString = "tcp://postgres:1234@localhost/postgres";
{"GOOGLE_MAP_API_KEY":"AIzaSy...", "RECAPTCHA_KEY":"6LcP..."}
"BASE_BACKOFFICE_API":"https://10.10.10.2/api", "ADMIN_PAGE":"/hidden_administrator"
```

Found API key → check restrictions (service, IP, referrer, app). Maps-only key w/o IP restriction still abusable at owner's cost (KeyHacks, Google Maps API Scanner).

**Source maps:** loaded w/ DevTools, or append `.map`: `/static/js/main.chunk.js` → `/static/js/main.chunk.js.map`. Leak original source + server paths:

```
"sources": ["/home/sysadmin/cashsystem/src/actions/index.js", ...]
```

**Tools:** wget, curl, browser view-source, Burp Suite, Waybackurls, Google Maps API Scanner.

---

## WSTG-INFO-06

**Identify Application Entry Points**

Goal: map all injection/entry points via request/response analysis before testing.

Walk app through intercepting proxy; log to spreadsheet: page + proxy request #, params, method, auth state, TLS, multi-step flow, WebSockets, notes.

**Requests:**
- GET vs POST (+ PUT/DELETE, rarer but often vulnerable).
- All POST body params, esp. hidden fields (price, qty, state).
- All query string params; separators `&`, `~`, `:`, custom encodings. ID every param incl. encoded/encrypted.
- Custom headers (e.g. `debug: false`).

**Responses:**
- New/modified cookies (`Set-Cookie`).
- 3xx, 403, 500 on normal requests.
- Telling headers (e.g. `Server: BIG-IP` → load balancer; may need repeated requests to hit weak node).

**Examples:**

```
GET /shoppingApp/buyme.asp?CUSTOMERID=100&ITEM=z101a&PRICE=62.50&IP=x.x.x.x HTTP/1.1
Cookie: SESSIONID=Z29vZCBqb2I...
```
→ CUSTOMERID, ITEM, PRICE, IP, cookie.

```
POST /KevinNotSoGoodApp/authenticate.asp?service=login HTTP/1.1
Cookie: SESSIONID=dGhpcyBp...;CustomCookie=00my00trusted00ip00is00x.x.x.x00

user=admin&pass=pass123&debug=true&fromtrustIP=true
```
→ body params + `CustomCookie`.

**Gray-box:** ask devs about non-HTTP inputs (SNMP traps, syslog, SMTP, SOAP) + expected formats.

**OWASP Attack Surface Detector (ASD):** static analysis of source → endpoints, params, types, unlinked endpoints; diffs versions. ZAP/Burp plugins + CLI.

```
java -jar attack-surface-detector-cli-1.3.5.jar <source-code-path> [-json]
```

Output lists method, path, params (name, paramType, dataType), source file + lines. RailsGoat example: 40 endpoints, 36 params. `-json` export imports into ZAP/Burp (useful when client gives JSON instead of source).

**Tools:** ZAP, Burp Suite, Fiddler. Ref: RFC 2616.

---

## WSTG-INFO-07

**Map Execution Paths Through Application**

Goal: map app + main workflows. Full black-box coverage infeasible → document paths found/tested.

**Coverage approaches:**
- **Path:** every path + combinatorial/boundary values. Thorough, grows exponentially.
- **Data flow (taint):** trace user input through app.
- **Race:** concurrent instances on same data.

Agree approach w/ owner; ask which functions worry them most. Track in spreadsheet: spidered URLs, decision points, screenshots.

Gray/white-box → much easier coverage. Many DAST tools use server-side agents to track coverage.

**Spidering (ZAP):** Spider, AJAX Spider, OpenAPI support.

**Tools:** ZAP, spreadsheets, diagramming software.

---

## WSTG-INFO-08

**Fingerprint Web Application Framework**

Goal: ID framework/CMS (WordPress, phpBB, MediaWiki…) → known vulns, faster testing. More markers = better accuracy.

**Where to look:** HTTP headers, cookies, HTML source, files/folders, file extensions, error messages.

**Headers:** `X-Powered-By` easy but spoofable/removable. Check all headers:

```
$ nc 127.0.0.1 80
HEAD / HTTP/1.0

Server: nginx/1.4.1
X-Powered-By: PHP/5.4.16-1~dotdeb.1
X-Generator: Swiftlet
```

`X-Generator` reveals real framework behind PHP. Spoof example: `X-Powered-By: Blood, sweat and tears`.

**Cookies:** more reliable, renamed less often than headers (e.g. CakePHP `Configure::write('Session.cookie', 'CAKEPHP');`).

**HTML source:** framework comments, CSS/JS paths, script vars, footer credits. Check `<head>`, `<meta>`, page bottom.

**Files/folders (dirbusting):** brute-force known paths (Burp Intruder + wordlist, FuzzDB). WordPress: `/wp-includes/` 403, `/wp-admin/` 302 → `wp-login.php`, `/wp-content/` 200. Plugin CHANGELOGs leak versions (e.g. Drupal Botcha). Check robots.txt first. Open-source target → install locally to learn layout.

**Extensions:** `.php` PHP, `.aspx` ASP.NET, `.jsp` Java.

**Errors:** paths leak stack (e.g. `wp-content/.../functions.php` → WordPress/PHP).

### Common Identifiers

**Cookies:**

| Framework | Cookie |
|---|---|
| Zope | zope3 |
| CakePHP | cakephp |
| Kohana | kohanasession |
| Laravel | laravel_session |
| phpBB | phpbb3_ |
| WordPress | wp-settings |
| 1C-Bitrix | BITRIX_ |
| AMPcms | AMP |
| Django CMS | django |
| DotNetNuke | DotNetNukeAnonymous |
| e107 | e107_tz |
| EPiServer | EPiTrace, EPiServer |
| Graffiti CMS | graffitibot |
| Hotaru CMS | hotaru_mobile |
| ImpressCMS | ICMSession |
| Indico | MAKACSESSION |
| InstantCMS | InstantCMS[logdate] |
| Kentico CMS | CMSPreferredCulture |
| MODx | SN4[12symb] |
| TYPO3 | fe_typo_user |
| Dynamicweb | Dynamicweb |
| LEPTON | lep[some_numeric_value]+sessionid |
| Wix | Domain=.wix.com |
| VIVVO | VivvoSessionId |

**HTML source:**

| App | Marker |
|---|---|
| WordPress | `<meta name="generator" content="WordPress 3.9.2" />` |
| phpBB | `<body id="phpbb"` |
| MediaWiki | `<meta name="generator" content="MediaWiki 1.21.9" />` |
| Joomla | `<meta name="generator" content="Joomla! - Open Source Content Management" />` |
| Drupal | `<meta name="Generator" content="Drupal 7 (http://drupal.org)" />` |
| DotNetNuke | `DNN Platform - http://www.dnnsoftware.com` |

General: `%framework_name%`, "powered by", "built upon", "running".

| Framework | Specific marker |
|---|---|
| Adobe ColdFusion | `<!-- START headerTags.cfm` |
| ASP.NET | `__VIEWSTATE` |
| ZK | `<!-- ZK` |
| Business Catalyst | `<!-- BC_OBNW -->` |
| Indexhibit | `ndxz-studio` |

**Remediation:** renaming cookies, rewriting paths, stripping headers = obscurity only, slows basic attackers. Prioritize patching + maintenance.

**Tools:**
- **WhatWeb** (https://github.com/urbanadventurer/WhatWeb, Ruby, in Kali): strings, regex, GHDB, MD5, URL, HTML tag patterns, custom passive/aggressive plugins.
- **Wappalyzer** (https://www.wappalyzer.com/): browser extension, regex on loaded page, occasional false positives.

Refs: Saumil Shah "An Introduction to HTTP fingerprinting"; Anant Shrivastava "Web Application Finger Printing".

---

## WSTG-INFO-09

**Fingerprint Web Application**

Merged into WSTG-INFO-08.

---

## WSTG-INFO-10

**Map Application Architecture**

Goal: map components (reverse proxy, web server, app server, DB/LDAP, firewalls, LB) + interactions. One weak component can compromise whole infra. Easy w/ dev docs; blind test → start assuming single server, extend from evidence.

**Firewall:** scan results. Filtered ports (no reply / ICMP unreachable) → firewall; RST on closed ports → direct exposure. Then: stateful vs ACL? WAF? bypassable?

**Reverse proxy / WAF / IPS:**
- Banner reveals it.
- Different error for attack-like requests vs normal 404 → filtering layer.
- Methods listed (incl. TRACE) but fail → interception.
- Self-identifying error pages (mod_security).
- Proxy-cache: `Server` header, or cached responses faster than first request.

**Load balancer:** compare repeated responses (unsynced `Date`), injected cookies (F5 `BIGipServer*`).

**App server:** headers differ on app-served resources; telltale cookies (`JSESSIONID` = J2EE); URL rewriting for sessions.

**Backend (DB/LDAP/RADIUS):** hidden externally. Dynamic content, numeric IDs → DB likely. Confirmation usually via vuln (bad exception handling, SQLi).
