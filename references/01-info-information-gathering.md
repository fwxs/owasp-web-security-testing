# WSTG INFO — Information Gathering

OWASP Web Security Testing Guide v4.2. 10 test cases: WSTG-INFO-01, WSTG-INFO-02, WSTG-INFO-03, WSTG-INFO-04, WSTG-INFO-05, WSTG-INFO-06, WSTG-INFO-07, WSTG-INFO-08, WSTG-INFO-09, WSTG-INFO-10.

## Table of Contents

- [WSTG-INFO-01 — Conduct Search Engine Discovery Reconnaissance for Information Leakage](#wstg-info-01)
- [WSTG-INFO-02 — Fingerprint Web Server](#wstg-info-02)
- [WSTG-INFO-03 — Review Webserver Metafiles for Information Leakage](#wstg-info-03)
- [WSTG-INFO-04 — Enumerate Applications on Webserver](#wstg-info-04)
- [WSTG-INFO-05 — Review Webpage Content for Information Leakage](#wstg-info-05)
- [WSTG-INFO-06 — Identify Application Entry Points](#wstg-info-06)
- [WSTG-INFO-07 — Map Execution Paths Through Application](#wstg-info-07)
- [WSTG-INFO-08 — Fingerprint Web Application Framework](#wstg-info-08)
- [WSTG-INFO-09 — Fingerprint Web Application](#wstg-info-09)
- [WSTG-INFO-10 — Map Application Architecture](#wstg-info-10)

---

## WSTG-INFO-01

**Conduct Search Engine Discovery Reconnaissance for Information Leakage**

Summary
Search engines crawl web via robots (programs) following links or sitemaps. robots.txt lists pages engines should skip.
Testers use search engines for recon: direct (search indexes/caches) and indirect (forums, newsgroups, tender sites) methods.
Robots index content by tags (e.g. <TITLE>). Stale robots.txt or missing meta noindex tags → unintended content gets indexed. Owners fix via robots.txt, meta tags, auth, search engine removal tools.

Test Objectives
Find sensitive design/config info exposed directly (org site) or indirectly (third-party services).

How to Test
Search for:
network diagrams/configs; archived admin posts/emails; logon procedures/username formats; usernames/passwords/private keys; third-party/cloud config files; revealing error messages; dev/test/UAT/staging site versions.

Search Engines
Use multiple engines — results vary by crawl time and ranking algo. Options (alphabetical):
Baidu — top in China.
Bing — Microsoft's, #2 worldwide. Supports advanced keywords.

binsearch.info — binary Usenet newsgroup search.
Common Crawl — open web crawl data repo, anyone can access/analyze.
DuckDuckGo — privacy-focused, aggregates sources. Supports search syntax.
Google — most popular, ranking-based relevance. Supports search operators.
Internet Archive Wayback Machine — digital library of net sites/artifacts.
Startpage — Google results w/o tracking/logs. Supports search operators.
Shodan — search for internet-connected devices/services. Free + paid tiers.
DuckDuckGo/Startpage give tester more privacy (no trackers/logs) → less info leaked about tester.

Search Operators
Special keyword/syntax extending queries for precise results. Form: `operator:query`. Common ones:
site: limits search to domain.
inurl: keyword must be in URL.
intitle: keyword must be in page title.
intext: / inbody: keyword must be in page body.
filetype: matches filetype (png, php, etc).

Example — find owasp.org content indexed:

site:owasp.org


Viewing Cached Content
cache: operator shows previously-indexed content — good for content since changed/removed. Not all engines support; Google best atm.
View owasp.org cache:

cache:owasp.org


Google Hacking, or Dorking
Chaining operators + tester creativity = strong discovery technique. Works on other engines too if operators supported. Called Google hacking/Dorking.
Dork databases (e.g. Google Hacking Database) help find specific info. Categories include:
Footholds
Files containing usernames
Sensitive Directories
Web Server Detection
Vulnerable Files
Vulnerable Servers
Error Messages
Files containing juicy info
Files containing passwords
Sensitive Online Shopping Info

Other engine dork DBs (Bing, Shodan) available via resources like Bishop Fox's Google Hacking Diggity Project.

Remediation
Weigh sensitivity of design/config info before posting online.
Periodically re-check sensitivity of already-posted info.

---

## WSTG-INFO-02

**Fingerprint Web Server**

Summary
Web server fingerprinting = ID'ing server type/version target runs. Usually automated in tools, but understanding fundamentals matters — why useful, how it works.
Knowing server type helps testers find known-vuln old/unpatched versions.

Test Objectives
ID web server version/type to enable further vuln discovery.

How to Test
Techniques: banner grabbing, malformed request responses, automated scans combining tactics. All same premise: elicit response from server, compare against known-response DB, match to server type.

Banner Grabbing
Send HTTP request, examine response header. Tools: telnet (HTTP), openssl (SSL requests).
Apache response example:

HTTP/1.1 200 OK
Date: Thu, 05 Sep 2019 17:42:39 GMT
Server: Apache/2.4.41 (Unix)
Last-Modified: Thu, 05 Sep 2019 17:40:42 GMT
ETag: "75-591d1d21b6167"
Accept-Ranges: bytes
Content-Length: 117
Connection: close
Content-Type: text/html
...

nginx response:

HTTP/1.1 200 OK
Server: nginx/1.17.3
Date: Thu, 05 Sep 2019 17:50:24 GMT
Content-Type: text/html
Content-Length: 117
Last-Modified: Thu, 05 Sep 2019 17:40:42 GMT
Connection: close
ETag: "5d71489a-75"

Accept-Ranges: bytes
...

lighttpd response:

HTTP/1.0 200 OK
Content-Type: text/html
Accept-Ranges: bytes
ETag: "4192788355"
Last-Modified: Thu, 05 Sep 2019 17:40:42 GMT
Content-Length: 117
Connection: close
Date: Thu, 05 Sep 2019 17:57:57 GMT
Server: lighttpd/1.4.54

Server type/version exposed clear here. Security-conscious apps obfuscate via modified headers, e.g.:

HTTP/1.1 200 OK
Server: Website.com
Date: Thu, 05 Sep 2019 17:57:06 GMT
Content-Type: text/html; charset=utf-8
Status: 200 OK
...

Obscured server → guess type via header field order. Apache example order:
Date
Server
Last-Modified
ETag
Accept-Ranges
Content-Length
Connection
Content-Type
nginx + obscured example share order:
Server
Date
Content-Type
Testers use this to guess obscured server = nginx. Not definitive though — multiple servers share orderings, fields removable/modifiable.

Sending Malformed Requests
Servers ID'able via error responses / default error pages (if uncustomized). Trigger via malformed/incorrect requests.

Apache response to bogus method SANTA CLAUS:

GET / SANTA CLAUS/1.1

HTTP/1.1 400 Bad Request
Date: Fri, 06 Sep 2019 19:21:01 GMT
Server: Apache/2.4.41 (Unix)
Content-Length: 226
Connection: close
Content-Type: text/html; charset=iso-8859-1
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
</body></html>

nginx, same request:

GET / SANTA CLAUS/1.1

<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.17.3</center>
</body>
</html>

lighttpd, same request:

GET / SANTA CLAUS/1.1

HTTP/1.0 400 Bad Request
Content-Type: text/html
Content-Length: 345
Connection: close
Date: Sun, 08 Sep 2019 21:56:17 GMT
Server: lighttpd/1.4.54
<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
<title>400 Bad Request</title>
</head>
<body>
<h1>400 Bad Request</h1>
</body>
</html>

Default error pages differ enough between servers → effective fingerprint method even w/ obscured headers.

Using Automated Scanning Tools
Fingerprinting often built into scan tools — send probes like above plus server-specific ones. Faster + bigger response DBs than manual → more accurate.
Common scan tools w/ fingerprint functionality:
Netcraft — online scanner, incl. server ID.
Nikto — Open Source CLI scanner.
Nmap — Open Source CLI + GUI (Zenmap).

Remediation
Exposed server info itself not a vuln, but helps attackers exploit other vulns / find version-specific unpatched exploits. Precautions:
Obscure server info in headers (e.g. Apache mod_headers).
Use hardened reverse proxy as extra layer between server + internet.
Keep servers patched/updated.

---

## WSTG-INFO-03

**Review Webserver Metafiles for Information Leakage**

Summary
Covers testing metadata files for leaking app paths/functionality. Directory lists meant to dodge Spiders/Robots/Crawlers also feed Map execution paths through application. Other info gathered too: attack surface, tech details, social engineering fodder.

Test Objectives
Find hidden/obfuscated paths+functionality via metadata file analysis.
Extract/map other info for better system understanding.

How to Test
wget actions below work w/ curl too. Many DAST tools (ZAP, Burp Suite) check/parse these as part of spider/crawler. Also findable via Google Dorks / inurl: .

Robots
Spiders/Robots/Crawlers fetch page then recurse hyperlinks for more content. Behavior governed by Robots Exclusion Protocol in robots.txt at web root.
Google's robots.txt excerpt (sampled 2020 May 5):

User-agent: *
Disallow: /search
Allow: /search/about
Allow: /search/static
Allow: /search/howsearchworks
Disallow: /sdch
...

User-Agent directive = target spider/robot/crawler. E.g. User-Agent: Googlebot = Google's, User-Agent: bingbot = Microsoft's. User-Agent: * = all.
Disallow = prohibited resources. Above example blocks:

...
Disallow: /search
...
Disallow: /sdch
...

Crawlers can ignore Disallow (e.g. social network crawlers validating shared links) → robots.txt not an enforcement mechanism, just a suggestion.
Fetch robots.txt from web root. E.g. www.google.com via wget/curl:

$ curl -O -Ss http://www.google.com/robots.txt && head -n5 robots.txt
User-agent: *
Disallow: /search
Allow: /search/about
Allow: /search/static
Allow: /search/howsearchworks
...

Analyze robots.txt Using Google Webmaster Tools
Site owners use Google's "Analyze robots.txt" (part of Webmaster Tools) to check site. Steps:
1. Sign into Google Webmaster Tools.
2. Enter site URL on dashboard.
3. Pick method, follow on-screen steps.

META Tags
<META> tags sit in HEAD, should stay consistent site-wide in case crawler starts on deep link not webroot. Robots directive settable via specific META tag.
Robots META Tag
No <META NAME="ROBOTS" ... > entry → defaults INDEX,FOLLOW. Other valid entries prefixed NO... i.e. NOINDEX , NOFOLLOW .
Based on robots.txt Disallow directives, regex search for <META NAME="ROBOTS" per page, compared against robots.txt.

Miscellaneous META Information Tags
Orgs embed META tags for screen readers, social preview, search indexing etc. Useful to testers for tech ID + extra paths/functionality. Sample from www.whitehouse.gov (View Source, 2020 May 05):

...
<meta property="og:locale" content="en_US" />
<meta property="og:type" content="website" />
<meta property="og:title" content="The White House" />
<meta property="og:description" content="We, the citizens of America, are now joined in a great
national effort to rebuild our country and to restore its promise for all. - President Donald
Trump." />
<meta property="og:url" content="https://www.whitehouse.gov/" />
<meta property="og:site_name" content="The White House" />
<meta property="fb:app_id" content="1790466490985150" />
<meta property="og:image" content="https://www.whitehouse.gov/wp-content/uploads/2017/12/wh.govshare-img_03-1024x538.png" />
<meta property="og:image:secure_url" content="https://www.whitehouse.gov/wpcontent/uploads/2017/12/wh.gov-share-img_03-1024x538.png" />
<meta name="twitter:card" content="summary_large_image" />

<meta name="twitter:description" content="We, the citizens of America, are now joined in a great
national effort to rebuild our country and to restore its promise for all. - President Donald
Trump." />
<meta name="twitter:title" content="The White House" />
<meta name="twitter:site" content="@whitehouse" />
<meta name="twitter:image" content="https://www.whitehouse.gov/wp-content/uploads/2017/12/wh.govshare-img_03-1024x538.png" />
<meta name="twitter:creator" content="@whitehouse" />
...
<meta name="apple-mobile-web-app-title" content="The White House">
<meta name="application-name" content="The White House">
<meta name="msapplication-TileColor" content="#0c2644">
<meta name="theme-color" content="#f5f5f5">
...

Sitemaps
Sitemap = file listing site's pages/videos/files + relationships, for search engines to crawl smarter. Testers use sitemap.xml to map site faster.
Google primary sitemap excerpt (2020 May 05):

$ wget --no-verbose https://www.google.com/sitemap.xml && head -n8 sitemap.xml
2020-05-05 12:23:30 URL:https://www.google.com/sitemap.xml [2049] -> "sitemap.xml" [1]
<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.google.com/schemas/sitemap/0.84">
<sitemap>
<loc>https://www.google.com/gmail/sitemap.xml</loc>
</sitemap>
<sitemap>
<loc>https://www.google.com/forms/sitemaps.xml</loc>
</sitemap>
...

Following through, gmail sitemap https://www.google.com/gmail/sitemap.xml :

<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
xmlns:xhtml="http://www.w3.org/1999/xhtml">
<url>
<loc>https://www.google.com/intl/am/gmail/about/</loc>
<xhtml:link href="https://www.google.com/gmail/about/" hreflang="x-default" rel="alternate"/>
<xhtml:link href="https://www.google.com/intl/el/gmail/about/" hreflang="el" rel="alternate"/>
<xhtml:link href="https://www.google.com/intl/it/gmail/about/" hreflang="it" rel="alternate"/>
<xhtml:link href="https://www.google.com/intl/ar/gmail/about/" hreflang="ar" rel="alternate"/>
...

Security TXT
security.txt = proposed standard for sites to declare security policies + contacts. Useful for:
Finding more paths/resources for discovery/analysis.
OSINT gathering.
Bug bounty info.
Social engineering.

Lives at webroot or .well-known/ . Ex:
https://example.com/security.txt
https://example.com/.well-known/security.txt

Real example, LinkedIn (2020 May 05):

$ wget --no-verbose https://www.linkedin.com/.well-known/security.txt && cat security.txt
2020-05-07 12:56:51 URL:https://www.linkedin.com/.well-known/security.txt [333/333] ->
"security.txt" [1]
<div style="page-break-after: always;"></div>
<h1 id="conforms-to-ietf-`draft-foudil-securitytxt-07`">Conforms to IETF `draft-foudil-securitytxt07`</h1>
Contact: mailto:security@linkedin.com
Contact: https://www.linkedin.com/help/linkedin/answer/62924
Encryption: https://www.linkedin.com/help/linkedin/answer/79676
Canonical: https://www.linkedin.com/.well-known/security.txt
Policy: https://www.linkedin.com/help/linkedin/answer/62924

Humans TXT
humans.txt = initiative naming people behind a site. Text file listing contributors. See humanstxt for details. Often has career/job info too.
Google example (2020 May 05):

$ wget --no-verbose https://www.google.com/humans.txt && cat humans.txt
2020-05-07 12:57:52 URL:https://www.google.com/humans.txt [286/286] -> "humans.txt" [1]
Google is built by a large team of engineers, designers, researchers, robots, and others in many
different sites across the globe. It is updated continuously, and built with more tools and
technologies than we can shake a stick at. If you'd like to help us out, see careers.google.com.

Other .well-known Information Sources
Other RFCs/drafts suggest standardized .well-known/ files. Lists here or here.
Tester could build list from RFC/drafts, feed to crawler/fuzzer to verify existence/content.

Tools
Browser (View Source or Dev Tools functionality)
curl
wget
Burp Suite
ZAP

---

## WSTG-INFO-04

**Enumerate Applications on Webserver**

Summary
Key step in app vuln testing: find which apps live on a web server. Many apps have known vulns/attack strategies for RCE or data theft. Also many apps misconfigured/outdated — assumed "internal only, no threat." Virtual hosting breaks old 1:1 IP-to-server assumption — one IP can serve many unrelated sites/apps. Applies to hosting envs and corp envs alike.
Security pros sometimes get just IP addresses as scope (pentest-style engagement) — expected to test all web apps reachable through that target. Problem: IP hosts HTTP on port 80, but hitting it by IP alone gives "No web server configured" or similar — yet system may "hide" multiple apps under unrelated DNS names. Scope thoroughness depends on tester testing ALL apps vs only known ones.
Sometimes target list includes IP+DNS name pairs — may be incomplete, client may not even know (common in big orgs).
Other scope gaps: apps at non-obvious URLs (e.g. http://www.example.com/some-strange-URL ) unreferenced elsewhere — by misconfig or intentional (hidden admin interfaces).
Solution: web application discovery.

Test Objectives
Enumerate in-scope apps on a web server.

How to Test
Web app discovery = ID'ing apps on given infra. Infra usually given as IPs (maybe netblock), DNS names, or mix. Given before assessment starts (pentest or app-focused). Unless rules of engagement narrow scope (e.g. only http://www.example.com/ ), assessment should be comprehensive — find all apps reachable via target. Techniques below:
Some techniques apply to internet-facing servers only — DNS/reverse-IP web search + search engines. Examples use private IPs (e.g. 192.168.1.100 ) as generic placeholders unless noted.

Three factors affect app count per DNS name/IP:
1. Different Base URL
Obvious entry = www.example.com , i.e. http://www.example.com/ . But app needn't start at / .
Same name could map to three apps:
http://www.example.com/url1

http://www.example.com/url2

http://www.example.com/url3

Here http://www.example.com/ has no meaningful page — three apps hidden unless tester knows exact path (url1/url2/url3). No security reason to publish this way usually, unless owner wants controlled/informed access. Not "secret" — just undisclosed location.
2. Non-standard Ports
Apps usually on 80 (http) / 443 (https), but no rule requires it. Any TCP port possible: http[s]://www.example.com:port/ . E.g. http://www.example.com:20000/ .

3. Virtual Hosts
DNS lets one IP map to multiple names — e.g. 192.168.1.100 → www.example.com , helpdesk.example.com , webmail.example.com . Names needn't share a domain. This 1-to-N
relationship served via virtual hosts, using HTTP 1.1 Host header.
No reason to suspect other apps beyond obvious www.example.com unless helpdesk.example.com / webmail.example.com known.

Approaches to Address Issue 1 - Non-standard URLs
No sure way to find non-standard-named apps (no fixed naming convention), but techniques help:
First: misconfigured server w/ directory browsing on → apps visible. Vuln scanners help here.
Second: apps referenced by other pages may get spidered/indexed by search engines. Suspect hidden app on www.example.com → search site: www.example.com , check results for non-obvious app URL.
Third: probe likely candidate URLs. E.g. webmail front end might sit at https://www.example.com/webmail , https://webmail.example.com/ , or https://mail.example.com/ . Same for admin interfaces (e.g. hidden Tomcat admin) — unreferenced but guessable. Dictionary/intelligent-guess searching can surface results. Vuln scanners help here too.

Approaches to Address Issue 2 - Non-standard Ports

Easy to check via port scanner like nmap w/ -sV (service recognition), IDing http[s] on odd ports. Needs full 64k TCP port scan.
Example — TCP connect scan, all open ports on 192.168.1.100 , service ID (only key switches shown — nmap has many more):
nmap -Pn -sT -sV -p0-65535 192.168.1.100

Check output for http / SSL-wrapped services (confirm https via probe). Example output:

Interesting ports on 192.168.1.100:
(The 65527 ports scanned but not shown below are in state: closed)
PORT
STATE SERVICE
VERSION
22/tcp
open ssh
OpenSSH 3.5p1 (protocol 1.99)
80/tcp
open http
Apache httpd 2.0.40 ((Red Hat Linux))
443/tcp
open ssl
OpenSSL
901/tcp
open http
Samba SWAT administration server
1241/tcp open ssl
Nessus security scanner
3690/tcp open unknown
8000/tcp open http-alt?
8080/tcp open http
Apache Tomcat/Coyote JSP engine 1.1

From this:
Apache HTTP server on port 80.
Looks like HTTPS on 443 (confirm by browsing https://192.168.1.100 ).
Samba SWAT web interface on 901.
Port 1241 = SSL-wrapped Nessus daemon, not real HTTPS.
Port 3690 = unspecified (nmap gives fingerprint, omitted here, offers DB submission).
Port 8000 unspecified — maybe HTTP (common port for it). Check:

$ telnet 192.168.10.100 8000
Trying 192.168.1.100...
Connected to 192.168.1.100.
Escape character is '^]'.
GET / HTTP/1.0
HTTP/1.0 200 OK
pragma: no-cache
Content-Type: text/html
Server: MX4J-HTTPD/1.0
expires: now
Cache-Control: no-cache
<html>
...

Confirmed HTTP server. Alt: browser visit, or Perl GET / HEAD commands mimicking HTTP (HEAD may not always work).

Apache Tomcat on 8080.
Vuln scanners can do this task too — check scanner handles HTTP[S] on non-standard ports. Nessus IDs on any port (if told to scan all), plus runs known web vuln + SSL config checks. Also spots popular apps/interfaces (e.g. Tomcat admin) that'd otherwise slip by.

Approaches to Address Issue 3 - Virtual Hosts
Techniques for finding DNS names tied to IP x.y.z.t :

DNS Zone Transfers
Limited use now (zone transfers mostly refused), but worth trying. First find name servers for x.y.z.t . If symbolic name known (say www.example.com ), get name servers via nslookup , host , or dig (NS records).
No symbolic name for x.y.z.t but target has some name → try that name's name server (hoping it also serves x.y.z.t ). E.g. target = IP x.y.z.t + name mail.example.com → find name servers for example.com .
Example — name servers for www.owasp.org via host :

$ host -t ns www.owasp.org
www.owasp.org is an alias for owasp.org.
owasp.org name server ns1.secure.net.
owasp.org name server ns2.secure.net.

Request zone transfer from example.com 's name servers. Lucky case → DNS entries incl. obvious www.example.com plus hidden helpdesk.example.com , webmail.example.com (maybe more). Check all returned names relevant to target.
Zone transfer attempt for owasp.org :

$ host -l www.owasp.org ns1.secure.net
Using domain server:
Name: ns1.secure.net
Address: 192.220.124.10#53
Aliases:
Host www.owasp.org not found: 5(REFUSED)
; Transfer failed.

DNS Inverse Queries
Similar, but uses inverse (PTR) records. Instead of zone transfer, query IP w/ record type PTR. Lucky → get DNS name back. Needs IP-to-name maps to exist — not guaranteed.
Web-based DNS Searches

Like zone transfer but via web service for name-based DNS search. E.g. Netcraft Search DNS. Query names in target domain (e.g. example.com ), check relevance.
Reverse-IP Services
Like DNS inverse query but via web app instead of name server. Multiple services exist, results partial/differ — use several for coverage.
Domain Tools Reverse IP (free membership req'd)
Bing, syntax: ip:x.x.x.x
Webhosting Info, syntax: http://whois.webhosting.info/x.x.x.x
DNSstuff (multiple services)
Net Square (multi domain/IP queries, needs install)
Example query to reverse-IP service for 216.48.3.18 (www.owasp.org's IP) — revealed 3 extra non-obvious names on same IP.


Googling
After above techniques, search engines refine/extend analysis further — reveal extra symbolic names or non-obvious app URLs.
E.g. from www.owasp.org example, tester queries Google/others for info re: newly found domains webgoat.org , webscarab.com , webscarab.net .

Googling techniques covered in Testing: Spiders, Robots, and Crawlers.

Tools
DNS lookup tools: nslookup , dig , similar.
Search engines (Google, Bing, others).
Specialized DNS-related web search services: see text.

Nmap
Nessus Vulnerability Scanner
Nikto

---

## WSTG-INFO-05

**Review Webpage Content for Information Leakage**

Summary
Common/recommended for devs to add detailed comments/metadata to source. But HTML comments/metadata can leak internal info attackers shouldn't see. Review needed to catch leaks.
Modern apps lean on client-side JS (React, Angular, Vue). Same risk as HTML comments — devs hardcode sensitive stuff in JS vars front-end side: API keys (e.g. unrestricted Google Maps key), internal IPs, hidden routes (admin pages/functionality), even creds. Review needed here too.
Large apps chase front-end perf via SASS/SCSS/webpack etc — code gets minified/hard to debug, so devs ship source maps for debugging. Source map = file linking minified asset back to original source. Debate whether source maps belong in prod. Undeniable though: leftover source maps/debug files in prod make source human-readable — easier for attackers to spot vulns or scrape sensitive data. JS review should check for exposed debug files. Whether to keep them in prod = security call based on context/sensitivity.

Test Objectives
Review page comments/metadata for leaks.
Gather JS files, review code to understand app + find leaks.
Check for exposed source map / debug files.

How to Test
Review webpage comments and metadata
Devs often leave debug info in HTML comments, forget to strip for prod. Look for comments starting <!-- .
Check for comments leaking sensitive info: SQL, usernames/passwords, internal IPs, debug info.

...
<div class="table2">

<div class="col1">1</div><div class="col2">Mary</div>
<div class="col1">2</div><div class="col2">Peter</div>
<div class="col1">3</div><div class="col2">Joe</div>
<!-- Query: SELECT id, name FROM app.users WHERE active='1' -->
</div>
...

Could even find:

<!-- Use the DB administrator password for testing:

f@keP@a$$w0rD -->

Check HTML version info for valid version numbers + DTD URLs

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">

strict.dtd - default strict DTD
loose.dtd - loose DTD
frameset.dtd - DTD for frameset documents

Some META tags aren't active attack vectors but let attacker profile app:

<META name="Author" content="Andrew Muller">

Common (non-WCAG-compliant) META tag: Refresh.

<META http-equiv="Refresh" content="15;URL=https://www.owasp.org/index.html">

Common META use: keywords for search engine ranking.

<META name="keywords" lang="en-us" content="OWASP, security, sunshine, lollipops">

Most servers control search indexing via robots.txt , but META tags can too. Tag below tells robots: don't index, don't follow links on this page.

<META name="robots" content="none">

PICS + POWDER provide infra for tagging internet content w/ metadata.

Identifying JavaScript Code and Gathering JavaScript Files
Devs hardcode sensitive info in front-end JS vars often. Check HTML source, look for JS between <script> / </script> . Also ID external JS files ( .js extension, filename usually in src attr of <script> tag).

Check JS for leaks abuseable by attackers: API keys, internal IPs, sensitive routes, creds. Example:

const myS3Credentials = {
accessKeyId: config('AWSS3AccessKeyID'),
secretAcccessKey: config('AWSS3SecretAccessKey'),
};

Could even find:

var conString = "tcp://postgres:1234@localhost/postgres";

Found API key? Check if restricted per-service or by IP/referrer/app/SDK etc.
E.g. Google Maps key restricted only to Maps APIs (not IP-restricted) → attacker can still hammer unrestricted Maps APIs on app owner's dime.

<script type="application/json">
...
{"GOOGLE_MAP_API_KEY":"AIzaSyDUEBnKgwiqMNpDplT6ozE4Z0XxuAbqDi4",
"RECAPTCHA_KEY":"6LcPscEUiAAAAHOwwM3fGvIx9rsPYUq62uRhGjJ0"}
...
</script>

Sometimes JS reveals sensitive routes — links to internal/hidden admin pages.

<script type="application/json">
...
"runtimeConfig":{"BASE_URL_VOUCHER_API":"https://staging-voucher.victim.net/api",
"BASE_BACKOFFICE_API":"https://10.10.10.2/api", "ADMIN_PAGE":"/hidden_administrator"}
...
</script>

Identifying Source Map Files
Source maps usually load w/ DevTools open. Also findable by appending ".map" to each external JS file's extension. E.g.
/static/js/main.chunk.js

found



check

/static/js/main.chunk.js.map .

Black-Box Testing
Check source maps for leaks helping attacker profile app. E.g.:

{
"version": 3,
"file": "static/js/main.chunk.js",
"sources": [
"/home/sysadmin/cashsystem/src/actions/index.js",
"/home/sysadmin/cashsystem/src/actions/reportAction.js",

"/home/sysadmin/cashsystem/src/actions/cashoutAction.js",
"/home/sysadmin/cashsystem/src/actions/userAction.js",
"..."
],
"..."
}

Source maps loaded → front-end source readable, easier to debug (for attacker too).

Tools
Wget
Browser "view source" function
Eyeballs
Curl
Burp Suite
Waybackurls
Google Maps API Scanner

References
KeyHacks

Whitepapers
HTML version 4.01
XHTML
HTML version 5

---

## WSTG-INFO-06

**Identify Application Entry Points**

Summary
Enumerating app + attack surface = key precursor before real testing — shows tester weak spots. This section maps areas needing investigation post-enumeration.

Test Objectives
Find possible entry/injection points via request+response analysis.

How to Test
Before testing starts, tester needs solid grasp of app + how browser/user talk to it. Walking through app, watch all HTTP requests + every param/form field passed. Note when GET vs POST used, plus other REST methods.
To see POST body params, use intercepting proxy (see tools). Note hidden form fields in POST — often carry sensitive state (item qty, price) devs never meant visible/editable.
Useful workflow: intercepting proxy + spreadsheet. Proxy logs every request/response as tester explores. Trap requests to see exact headers/params sent + returned. Tedious on big interactive sites (e.g. banking app) but experience speeds it up.
While walking app, log interesting params in URL/custom headers/body into spreadsheet: page requested (+ proxy request # for reference), interesting params, request type (GET/POST/etc), auth status, TLS used, part of multi-step flow, WebSockets used, other notes. Once mapped, test each identified area, note results. Rest of guide covers how to test each area — but this mapping step comes first.

Points of interest across all requests/responses. Focus GET/POST (majority of traffic). Note PUT/DELETE etc — rarer but often expose vulns if allowed. Dedicated section later covers HTTP methods.

Requests
Note where GET vs POST used.

Note all POST body params.
Watch hidden POST params esp. — form submits ALL fields (incl. hidden) in body. Usually invisible without proxy/view-source. Next page/data/access level can shift based on hidden param value(s).
Note all GET params (URL query string, after ? ).
Note all query string params — pair format like foo=bar . Multiple params can chain via & , \~ , : , or other separator/encoding.
Multi-param strings/POST bodies: some/all params needed to run attacks. ID every param (even encoded/encrypted), note which app actually processes. Later guide sections cover testing them — for now just catalog.
Also watch custom headers (e.g. debug: false ).

Responses
Note new cookies set (Set-Cookie), modified, or added.
Note redirects (3xx), 400s (esp. 403 Forbidden), 500 errors on normal (unmodified) requests.
Note interesting headers. E.g. Server: BIG-IP = load balanced site. If load-balanced + one server misconfigured, tester may need multiple requests to hit vuln server, depending on balancing type.

Black-Box Testing
Testing for Application Entry Points
Two examples below.
Example 1
GET request buying item from shopping app.

GET /shoppingApp/buyme.asp?CUSTOMERID=100&ITEM=z101a&PRICE=62.50&IP=x.x.x.x HTTP/1.1
Host: x.x.x.x
Cookie: SESSIONID=Z29vZCBqb2IgcGFkYXdhIG15IHVzZXJuYW1lIGlzIGZvbyBhbmQgcGFzc3dvcmQgaXMgYmFy

Note params: CUSTOMERID, ITEM, PRICE, IP, Cookie (could be encoded params or session state).
Example 2
POST request logging into an app.

POST /KevinNotSoGoodApp/authenticate.asp?service=login HTTP/1.1
Host: x.x.x.x
Cookie: SESSIONID=dGhpcyBpcyBhIGJhZCBhcHAgdGhhdCBzZXRzIHByZWRpY3RhYmxlIGNvb2tpZXMgYW5kIG1pbmUgaXMgMT
IzNA==;CustomCookie=00my00trusted00ip00is00x.x.x.x00
user=admin&pass=pass123&debug=true&fromtrustIP=true

Note all params as before — most sit in body not URL here. Also custom header ( CustomCookie ).

Gray-Box Testing

Same as black-box + one addition. If app receives data from external sources (SNMP traps, syslog, SMTP, SOAP from other servers), meeting w/ devs can reveal any functions accepting user input + expected format. E.g. dev explains correct SOAP request format app accepts + web service location (if not already found black-box).
OWASP Attack Surface Detector
ASD tool inspects source code, finds app endpoints, accepted params, param data types. Covers unlinked endpoints spiders can't find, or unused optional params in client code. Also diffs attack surface between two app versions.
ASD available as ZAP + Burp Suite plugin, plus standalone CLI. CLI exports attack surface as JSON, usable by both plugins. Useful when source isn't given directly to pentester — e.g. customer hands over JSON output instead of source.
How to Use

CLI jar download: https://github.com/secdec/attack-surface-detector-cli/releases.
Run against target app source to ID endpoints:
java -jar attack-surface-detector-cli-1.3.5.jar <source-code-path> [flags]

Example against OWASP RailsGoat:

$ java -jar attack-surface-detector-cli-1.3.5.jar railsgoat/
Beginning endpoint detection for '<...>/railsgoat' with 1 framework types
Using framework=RAILS
[0] GET: /login (0 variants): PARAMETERS={url=name=url, paramType=QUERY_STRING, dataType=STRING};
FILE=/app/controllers/sessions_contro
ller.rb (lines '6'-'9')
[1] GET: /logout (0 variants): PARAMETERS={}; FILE=/app/controllers/sessions_controller.rb (lines
'33'-'37')
[2] POST: /forgot_password (0 variants): PARAMETERS={email=name=email, paramType=QUERY_STRING,
dataType=STRING}; FILE=/app/controllers/
password_resets_controller.rb (lines '29'-'38')
[3] GET: /password_resets (0 variants): PARAMETERS={token=name=token, paramType=QUERY_STRING,
dataType=STRING}; FILE=/app/controllers/p
assword_resets_controller.rb (lines '19'-'27')
[4] POST: /password_resets (0 variants): PARAMETERS={password=name=password, paramType=QUERY_STRING,
dataType=STRING, user=name=user, paramType=QUERY_STRING, dataType=STRING,
confirm_password=name=confirm_password, paramType=QUERY_STRING, dataType=STRING};
FILE=/app/controllers/password_resets_controller.rb (lines '5'-'17')
[5] GET: /sessions/new (0 variants): PARAMETERS={url=name=url, paramType=QUERY_STRING,
dataType=STRING}; FILE=/app/controllers/sessions_controller.rb (lines '6'-'9')
[6] POST: /sessions (0 variants): PARAMETERS={password=name=password, paramType=QUERY_STRING,
dataType=STRING, user_id=name=user_id, paramType=SESSION, dataType=STRING,
remember_me=name=remember_me, paramType=QUERY_STRING, dataType=STRING, url=name=url,
paramType=QUERY_STRING, dataType=STRING, email=name=email, paramType=QUERY_STRING, dataType=STRING};
FILE=/app/controllers/sessions_controller.rb (lines '11'-'31')
[7] DELETE: /sessions/{id} (0 variants): PARAMETERS={}; FILE=/app/controllers/sessions_controller.rb
(lines '33'-'37')
[8] GET: /users (0 variants): PARAMETERS={}; FILE=/app/controllers/api/v1/users_controller.rb (lines
'9'-'11')
[9] GET: /users/{id} (0 variants): PARAMETERS={}; FILE=/app/controllers/api/v1/users_controller.rb
(lines '13'-'15')
... snipped ...
[38] GET: /api/v1/mobile/{id} (0 variants): PARAMETERS={id=name=id, paramType=QUERY_STRING,

dataType=STRING, class=name=class, paramType=QUERY_STRING, dataType=STRING};
FILE=/app/controllers/api/v1/mobile_controller.rb (lines '8'-'13')
[39] GET: / (0 variants): PARAMETERS={url=name=url, paramType=QUERY_STRING, dataType=STRING};
FILE=/app/controllers/sessions_controller.rb (lines '6'-'9')
Generated 40 distinct endpoints with 0 variants for a total of 40 endpoints
Successfully validated serialization for these endpoints
0 endpoints were missing code start line
0 endpoints were missing code end line
0 endpoints had the same code start and end line
Generated 36 distinct parameters
Generated 36 total parameters
- 36/36 have their data type
- 0/36 have a list of accepted values
- 36/36 have their parameter type
--- QUERY_STRING: 35
--- SESSION: 1
Finished endpoint detection for '<...>/railsgoat'
----------- DONE -0 projects had duplicate endpoints
Generated 40 distinct endpoints
Generated 40 total endpoints
Generated 36 distinct parameters
Generated 36 total parameters
1/1 projects had endpoints generated
To enable logging include the -debug argument

-json flag also generates JSON output, usable by ZAP + Burp plugins. See:
Home of ASD Plugin for OWASP ZAP
Home of ASD Plugin for PortSwigger Burp

Tools
OWASP Zed Attack Proxy (ZAP)
Burp Suite
Fiddler

References
RFC 2616 - Hypertext Transfer Protocol - HTTP 1.1
OWASP Attack Surface Detector

---

## WSTG-INFO-07

**Map Execution Paths Through Application**

Summary
Before security testing starts, must understand app structure. Without it, thorough testing unlikely.

Test Objectives
Map target app, understand main workflows.

How to Test
Black-box testing can't feasibly cover entire codebase — tester has no code-path visibility, and even w/ it, testing all paths too time-costly. Fix: document code paths found + tested.
Approaches to test/measure code coverage:
Path - test each app path incl. combinatorial + boundary-value analysis per decision path. Thorough but path count grows exponentially per branch.
Data Flow (Taint Analysis) - tests variable assignment via external (usually user) interaction. Maps data flow/transform/use across app.
Race - tests concurrent instances manipulating same data.
Method tradeoff should be negotiated w/ app owner. Simpler approach: ask owner which functions/code sections worry them most + how reachable.
To show code coverage to owner: start spreadsheet, log all links found via spidering (manual or auto). Then check decision points closely, find significant code paths. Document in spreadsheet: URLs, prose, screenshots of paths found.

Code Review
Ensuring code coverage way easier w/ gray-box/white-box vs black-box. Info shared w/ tester covers minimum coverage needs.
Many modern DAST tools support web server agent (or pair w/ third-party agent) to track app coverage specifics.

Automatic Spidering
Auto spider = tool discovering new resources (URLs) on a site. Starts from seed URL list (depends how Spider launched). Many spidering tools exist; example uses Zed Attack Proxy (ZAP):


ZAP spidering options, pick per need:
Spider
AJAX Spider
OpenAPI Support

Tools
Zed Attack Proxy (ZAP)
List of spreadsheet software
Diagramming software

References
Code Coverage

---

## WSTG-INFO-08

**Fingerprint Web Application Framework**

Summary
Nothing new under sun — nearly every app idea already built. Given huge Open Source ecosystem, app security tests often hit targets fully/partly built on known apps/frameworks (WordPress, phpBB, Mediawiki etc). Knowing components under test speeds testing + cuts effort. Known apps have known headers/cookies/dir structures — enumerable for ID. Most frameworks leave markers in these spots. This is what auto tools do: check predefined locations, compare vs known-signature DB. More markers = better accuracy.

Test Objectives
Fingerprint app components.

How to Test
Black-Box Testing
Common ID locations:
HTTP headers
Cookies
HTML source code
Specific files and folders
File extensions
Error messages
HTTP Headers
Simplest ID method: X-Powered-By field in response header. netcat = simplest tool.
Example HTTP Request-Response:

$ nc 127.0.0.1 80
HEAD / HTTP/1.0
HTTP/1.1 200 OK
Server: nginx/1.0.14
[...]
X-Powered-By: Mono

X-Powered-By → framework likely Mono . Quick/simple but not 100% reliable — header easily disabled via config, or spoofed/obfuscated (see Remediation example). Above we also see specific nginx version serving content.
Same example could instead miss X-Powered-By or show:

HTTP/1.1 200 OK
Server: nginx/1.0.14
Date: Sat, 07 Sep 2013 08:19:15 GMT
Content-Type: text/html;charset=ISO-8859-1
Connection: close
Vary: Accept-Encoding
X-Powered-By: Blood, sweat and tears

Sometimes multiple headers point to a framework. Example: X-Powered-By shows PHP version, but X-Generator reveals real framework Swiftlet — expands attack vectors for tester. Inspect every header carefully for such leaks.

HTTP/1.1 200 OK
Server: nginx/1.4.1
Date: Sat, 07 Sep 2013 09:22:52 GMT
Content-Type: text/html
Connection: keep-alive
Vary: Accept-Encoding
X-Powered-By: PHP/5.4.16-1~dotdeb.1
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
X-Generator: Swiftlet

Cookies
More reliable framework ID: framework-specific cookie names.
Example HTTP-request:


CAKEPHP cookie auto-set → reveals framework. Common cookie name list in Cookies section below. Limitation: cookie names configurable. E.g. CakePHP renamable via core.php config:

/**
* The name of CakePHP's session cookie.
*
* Note the guidelines for Session names states: "The session name references
* the session id in cookies and URLs. It should contain only alphanumeric
* characters."
* @link http://php.net/session_name

*/
Configure::write('Session.cookie', 'CAKEPHP');

But cookie renames less common than header tweaks → more reliable ID method overall.
HTML Source Code
Find patterns in HTML source. Often reveals a lot — recognizes specific components. Common marker: HTML comments directly naming framework. Also: framework-specific paths (CSS/JS folder links). Also: specific script vars pointing to a framework.
Screenshot below: comment + specific paths + script vars quickly reveal ZK framework + version.


Such info often sits in <head> , <meta> tags, or page bottom. Still, scan entire response — useful for other things too (other comments, hidden fields). Some devs don't bother hiding framework info — bottom-of-page disclosure like this happens:


Specific Files and Folders
Strong ID approach: every web component has own file/folder structure on server. Sometimes visible in HTML source, sometimes not but still present server-side.
Technique: forced browsing / "dirbusting" — brute-force known folder/filenames, watch HTTP responses to map server content. Useful for finding default files to attack, and for fingerprinting. Dirbusting done multiple ways — example: WordPress target dirbusted via Burp Suite intruder + wordlist.


WordPress-specific folders ( /wp-includes/ , /wp-admin/ , /wp-content/ ) return 403 (Forbidden), 302 (redirect to wp-login.php ), 200 (OK) respectively — good WordPress indicator. Same trick works dirbusting plugin folders + versions. Screenshot below: typical Drupal plugin CHANGELOG file — reveals app used + vulnerable plugin version.


Tip: check robots.txt before dirbusting. App-specific folders + other sensitive info sometimes sit there too. Example robots.txt screenshot below.


File/folder specifics vary per app. Open Source target → worth spinning up temp install during pentest for deeper insight into infra/functionality/leftover files. Good existing file lists exist too — e.g. FuzzDB wordlists of predictable files/folders.
File Extensions
URL file extensions can hint web platform/tech.
E.g. OWASP wiki used PHP:

https://wiki.owasp.org/index.php?title=Fingerprint_Web_Application_Framework&action=edit&section=4

Common web file extensions + tech:
.php - PHP
.aspx - Microsoft ASP.NET
.jsp - Java Server Pages

Error Messages
Screenshot below: filesystem path points to WordPress ( wp-content ). Also note WordPress runs PHP ( functions.php ).


Common Identifiers
Cookies
Framework

Cookie name

Zope

zope3

CakePHP

cakephp

Kohana

kohanasession

Laravel

laravel_session

phpBB

phpbb3_

WordPress

wp-settings

1C-Bitrix

BITRIX_

AMPcms

AMP

Django CMS

django

DotNetNuke

DotNetNukeAnonymous

e107

e107_tz

EPiServer

EPiTrace, EPiServer

Graffiti CMS

graffitibot

Hotaru CMS

hotaru_mobile

ImpressCMS

ICMSession

Indico

MAKACSESSION

InstantCMS

InstantCMS[logdate]

Kentico CMS

CMSPreferredCulture

MODx

SN4[12symb]

TYPO3

fe_typo_user

Dynamicweb

Dynamicweb

LEPTON

lep[some_numeric_value]+sessionid

Wix

Domain=.wix.com

VIVVO

VivvoSessionId

HTML Source Code
Application

Keyword

WordPress

<meta name="generator" content="WordPress 3.9.2" />

phpBB

<body id="phpbb"

Mediawiki

<meta name="generator" content="MediaWiki 1.21.9" />

Joomla

<meta name="generator" content="Joomla! - Open Source Content Management" />

Drupal

<meta name="Generator" content="Drupal 7 (http://drupal.org)" />

DotNetNuke

DNN Platform - [http://www.dnnsoftware.com](http://www.dnnsoftware.com)

General Markers
%framework_name%
powered by
built upon
running

Specific Markers
Framework

Keyword

Adobe ColdFusion

<!-- START headerTags.cfm

Microsoft ASP.NET

__VIEWSTATE

ZK

<!-- ZK

Business Catalyst

<!-- BC_OBNW -->

Indexhibit

ndxz-studio

Remediation
Can rename cookies (configs), hide/change file paths (rewrites/source changes), strip known headers etc — but all "security through obscurity". Only slows basic adversaries. Better spend time on stakeholder awareness + maintenance.

Tools
General/well-known tools below. Plenty other utilities + framework-specific fingerprint tools exist too.

WhatWeb
Website: https://github.com/urbanadventurer/WhatWeb
One of best fingerprint tools going. Ships in default Kali Linux. Language: Ruby.
Match methods:
Text strings (case sensitive)
Regular expressions
Google Hack Database queries (limited keyword set)
MD5 hashes
URL recognition

HTML tag patterns
Custom ruby code for passive/aggressive ops
Sample output below:


Wappalyzer
Website: https://www.wappalyzer.com/
Most popular form: Firefox/Chrome extension. Works purely via regex matching on loaded page — no extras needed. Runs browser-side, results shown as icons. Occasional false positives, but handy for instant tech-stack sense right after page load.
Sample plugin output below.


References
Whitepapers
Saumil Shah: "An Introduction to HTTP fingerprinting"
Anant Shrivastava : "Web Application Finger Printing"

---

## WSTG-INFO-09

**Fingerprint Web Application**

Merged into: Fingerprint Web Application Framework.

---

## WSTG-INFO-10

**Map Application Architecture**

Summary
Interconnected/heterogeneous web infra can span hundreds of apps — makes config review foundational to testing + deploying each app. One vuln can undermine entire infra; even minor-looking issues can escalate into severe risk elsewhere on same infra.
Fix: in-depth config + known-issue review. Before that, must map network + app architecture — ID components, how they interact w/ app, security impact.

Test Objectives
Generate app architecture map from research.

How to Test
Map the Application Architecture
Map architecture via testing to find components building the app. Small setup (simple PHP app) = maybe one server for app + auth.
Complex setup (online bank) = multiple servers. Could incl. reverse proxy, front-end web server, app server, DB/LDAP server. Each server = different purpose, maybe segregated networks w/ firewalls between. Creates zones so web-server access ≠ auth mechanism access — compromise of one element stays isolated, doesn't cascade.
Getting architecture knowledge easy if devs hand it over (docs/interviews) — hard if blind pentest.
Blind case: tester starts assuming simple setup (single server). Then, from other test results, derives elements, questions assumption, extends map. Start w/ simple qs: "Is there a firewall protecting the web server?" Answered via network scan results — filtered ports (no response/ICMP unreachable) = firewalled; RST on all non-listening ports = direct internet connection. Push further: firewall type? Stateful or router ACL? Config? Bypassable? Full WAF?
Detect reverse proxy: via web server banner (may directly reveal it), or by comparing actual vs expected answers to requests. E.g. some reverse proxies act as IPS, blocking known attacks before reaching web server. Server normally 404s unavailable pages but returns different error for common scanner-style attacks → hints at reverse proxy / app-layer firewall filtering + swapping error pages.

Another tell: server lists available HTTP methods (incl. TRACE) but expected methods error out → something's intercepting.
Sometimes protection system self-identifies (e.g. mod_security error page).

Reverse proxies also show up as proxy-caches for backend perf. Detect via server header, or by timing requests expected to be cached — compare first request time vs later ones.
Also detectable: network load balancers. Typically balance given TCP/IP port across multiple servers via algo (round-robin, load-based, request-count etc). Detect by comparing multiple requests' results to see if they hit same or different backend servers — e.g. via Date header if server clocks unsynced. Sometimes load balancer injects distinct info into headers (e.g. F5 BIG-IP's BIGipServer -prefixed cookie).
App web servers usually easy to spot. Resource requests handled by app server itself (not web server) → response headers vary noticeably. Also: app server may set telltale cookies (e.g. JSESSIONID from J2EE servers), or auto-rewrite URLs for session tracking.
Auth backends (LDAP dirs, relational DBs, RADIUS) harder to spot externally — app hides them. DB backend presence inferable just by browsing app: heavy dynamic "on the fly" content likely DB-sourced. Sometimes request style hints at DB backend — e.g. numeric id params browsing shop articles.
Blind app test though: underlying DB knowledge usually only surfaces via a vuln (poor exception handling, SQLi susceptibility etc).