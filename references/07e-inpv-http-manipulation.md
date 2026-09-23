# WSTG INPV — HTTP Protocol Manipulation

OWASP WSTG v4.2. Input Validation subset. Tests WSTG-INPV-03, 04, 15, 16, 17.

## Table of Contents

- [INPV-03 HTTP Verb Tampering](#wstg-inpv-03)
- [INPV-04 HTTP Parameter Pollution](#wstg-inpv-04)
- [INPV-15 HTTP Splitting/Smuggling](#wstg-inpv-15)
- [INPV-16 HTTP Incoming Requests](#wstg-inpv-16)
- [INPV-17 Host Header Injection](#wstg-inpv-17)

---

## WSTG-INPV-03

**Testing for HTTP Verb Tampering**

Merged into: Test HTTP Methods.

---

## WSTG-INPV-04

**Testing for HTTP Parameter Pollution**

Goal: find inconsistent handling of duplicate same-named HTTP parameters (`?p=1&p=2`) that can be exploited to bypass filters or confuse app logic — no HTTP spec governs this, so behavior varies by stack.

Known real-world impact:
- **Filter bypass**: ModSecurity's SQLi deny-list blocked `select 1,2,3 from table`, but `?page=select 1&page=2,3 from table` slipped past the filter and was reassembled by the app layer into the full malicious string.
- **XSS via validation bypass**: Apple CUPS validated only the *second* `kerberos` parameter while rendering the *first* unsanitized: `?kerberos=onmouseover=alert(1)&kerberos=`.
- **Auth bypass**: Blogger's `add-authors.do` checked ownership on the first `blogID` but performed the action on the second: `blogID=attackerblogid&blogID=victimblogid`.

Backend parsing behavior for `?color=red&color=blue` varies:

| Stack | Result |
|---|---|
| ASP.NET/IIS, ASP/IIS | `red,blue` (comma-concatenated) |
| PHP/Apache, PHP/Zeus, IBM Lotus Domino | `blue` (last wins) |
| JSP-Servlet (Tomcat/Oracle AS/Jetty), IBM HTTP Server, mod_perl, Perl CGI, mod_wsgi | `red` (first wins) |
| Python/Zope | `['red','blue']` (list) |

Black-box — server-side: append a duplicate of a target param with a different value, e.g. `?mode=guest&search_string=kittens&search_string=puppies`, and see which value(s) the response reflects. For deeper analysis, diff three requests: baseline (`par1=val1`), tampered (`par1=HPP_TEST`), and combined (`par1=val1&par1=HPP_TEST`) — if the combined response differs from *both* singles, there's an exploitable impedance mismatch.

Black-box — client-side: inject `%26HPP_TEST` into a reflected param and look for url-decoded occurrences (`&HPP_TEST`) landing inside `href`/`src`/`data`/form-action attributes — same technique applies to XHR query strings and plugin params (e.g. Flash `flashvars`).

Tools: OWASP ZAP passive/active scanners.

Refs: Carettoni & di Paola, *HTTP Parameter Pollution*; CAPEC-460.

---

## WSTG-INPV-15

**Testing for HTTP Splitting Smuggling**

Goal: find unsanitized input reflected into a response header (splitting) or ambiguous message framing between HTTP agents (smuggling).

**HTTP Splitting** (black-box): if a param feeds directly into a response header (e.g. a redirect `Location`), inject a CRLF (`%0d%0a`) to fabricate a second full HTTP response inside the first:
```
interface=advanced%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2035%0d%0a%0d%0a<html>Sorry,%20System%20Down</html>
```
A caching proxy sitting in front sees two responses and can be tricked into caching the fabricated second one against a different URL — cache poisoning, or stored XSS against every user served from that cache. Most likely headers: `Location`, `Set-Cookie`. Complications: the forged response needs correct caching headers (e.g. future `Last-Modified`) to actually get cached; some frameworks URL-encode the path but not the query string, so a leading `?` bypasses that filtering.

Gray-box: exploitation details depend on how the target delimits messages (boundary string, packet boundary, or fixed-length chunking) — chunking may require padding so the smuggled message starts exactly on a chunk boundary; if the vulnerable param is too long for a GET, try POST instead.

**HTTP Smuggling** (gray-box only — requires knowing the intermediary chain): exploits inconsistent parsing of the same message between two agents (e.g. a WAF vs. the origin server). Classic example — IIS 5.0 truncates POST bodies over 48KB when `Content-Type` isn't `application/x-www-form-urlencoded`; a request padded to land exactly on that boundary causes the firewall and IIS to disagree on where request boundaries fall, letting a malicious request (e.g. a directory-traversal `cmd.exe` call) ride through hidden inside what the firewall thinks is just body content. Other real-world triggers: duplicate `Content-Length` headers (agents may honor the first or second inconsistently), or a `Content-Length` on a GET. Note: smuggling exploits the *infrastructure's* parsing disagreement, not an app bug — still worth flagging even though it's a harder sell to a client.

Refs: Klein, *Divide and Conquer: HTTP Response Splitting, Web Cache Poisoning Attacks, and Related Topics*; Linhart/Klein/Heled/Orrin, *HTTP Request Smuggling*.

---

## WSTG-INPV-16

**Testing for HTTP Incoming Requests**

Goal: passively monitor all HTTP traffic to/from the server — without touching client/browser proxy settings — to spot unexpected background requests.

| Method | Tools | Notes |
|---|---|---|
| Reverse proxy on the server | Fiddler (Windows), Charles (Linux) | can also edit/replay captured requests |
| Port forwarding / SOCKS proxy | Charles, port-forwarding tools | forwards client-observed traffic to the server port |
| TCP-level capture | tcpdump, Wireshark, replay via Ostinato | edit-and-replay needs a separate tool (Ostinato); HTTPS bodies need the server's private key imported into Wireshark to decrypt |

Tools: Fiddler, TCPProxy, Charles Web Debugging Proxy, WireShark, PowerEdit-Pcap, pcapteller, replayproxy, Ostinato.

---

## WSTG-INPV-17

**Testing for Host Header Injection**

Goal: confirm the `Host` header (and fallbacks like `X-Forwarded-Host`) can't be abused to redirect, poison cache, or hijack password-reset links.

Black-box — supply an attacker-controlled domain and see how it's used:
```
GET / HTTP/1.1
Host: www.attacker.com
```
Impact depends on what the app does with it:

| Behavior | Impact |
|---|---|
| App builds an absolute redirect/link from `Host` | `Location: http://www.attacker.com/login.php` — open redirect |
| No validation, dispatch to first vhost | information disclosure of internal routing |
| `X-Forwarded-Host` trusted as a bypass when `Host` is checked | same injection via a different header: `X-Forwarded-Host: www.attacker.com` reflected into page links |
| Cacheable response built from `Host` | **web cache poisoning** — a poisoned response gets served to every subsequent visitor via the shared cache, no victim interaction needed |
| Password-reset link built from `Host` | **reset-token theft** — victim clicks a reset link pointing at `www.attacker.com`, leaking their token to the attacker |

Refs: *Practical HTTP Host Header Attacks*.
