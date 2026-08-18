# WSTG INPV (Input Validation) — HTTP Protocol Manipulation

OWASP Web Security Testing Guide v4.2. Subset of the Input Validation category (HTTP verb tampering, parameter pollution, request splitting/smuggling, host header injection). 5 test cases: WSTG-INPV-03, WSTG-INPV-04, WSTG-INPV-15, WSTG-INPV-16, WSTG-INPV-17.

## Table of Contents

- [WSTG-INPV-03 — Testing for HTTP Verb Tampering](#wstg-inpv-03)
- [WSTG-INPV-04 — Testing for HTTP Parameter Pollution](#wstg-inpv-04)
- [WSTG-INPV-15 — Testing for HTTP Splitting Smuggling](#wstg-inpv-15)
- [WSTG-INPV-16 — Testing for HTTP Incoming Requests](#wstg-inpv-16)
- [WSTG-INPV-17 — Testing for Host Header Injection](#wstg-inpv-17)

---

## WSTG-INPV-03

**Testing for HTTP Verb Tampering**

This content has been merged into: Test HTTP Methods

---

## WSTG-INPV-04

**Testing for HTTP Parameter Pollution**

Summary
HTTP Parameter Pollution tests the applications response to receiving multiple HTTP parameters with the same name;
for example, if the parameter username is included in the GET or POST parameters twice.
Supplying multiple HTTP parameters with the same name may cause an application to interpret values in unanticipated
ways. By exploiting these effects, an attacker may be able to bypass input validation, trigger application errors or modify
internal variables values. As HTTP Parameter Pollution (in short HPP) affects a building block of all web technologies,
server and client-side attacks exist.
Current HTTP standards do not include guidance on how to interpret multiple input parameters with the same name.
For instance, RFC 3986 simply defines the term Query String as a series of field-value pairs and RFC 2396 defines
classes of reversed and unreserved query string characters. Without a standard in place, web application components
handle this edge case in a variety of ways (see the table below for details).
By itself, this is not necessarily an indication of vulnerability. However, if the developer is not aware of the problem, the
presence of duplicated parameters may produce an anomalous behavior in the application that can be potentially
exploited by an attacker. As often in security, unexpected behaviors are a usual source of weaknesses that could lead
to HTTP Parameter Pollution attacks in this case. To better introduce this class of vulnerabilities and the outcome of
HPP attacks, it is interesting to analyze some real-life examples that have been discovered in the past.

Input Validation and Filters Bypass
In 2009, immediately after the publication of the first research on HTTP Parameter Pollution, the technique received
attention from the security community as a possible way to bypass web application firewalls.
One of these flaws, affecting ModSecurity SQL Injection Core Rules, represents a perfect example of the impedance
mismatch between applications and filters. The ModSecurity filter would correctly apply a deny list for the following
string: select 1,2,3 from table , thus blocking this example URL from being processed by the web server:
/index.aspx?page=select 1,2,3 from table . However, by exploiting the concatenation of multiple HTTP parameters,
an attacker could cause the application server to concatenate the string after the ModSecurity filter already accepted
the input. As an example, the URL /index.aspx?page=select 1&page=2,3 from table would not trigger the
ModSecurity filter, yet the application layer would concatenate the input back into the full malicious string.
Another HPP vulnerability turned out to affect Apple Cups, the well-known printing system used by many UNIX systems.
Exploiting HPP, an attacker could easily trigger a Cross-Site Scripting vulnerability using the following URL:
http://127.0.0.1:631/admin/?kerberos=onmouseover=alert(1)&kerberos . The application validation checkpoint
could be bypassed by adding an extra kerberos argument having a valid string (e.g. empty string). As the validation
checkpoint would only consider the second occurrence, the first kerberos parameter was not properly sanitized
before being used to generate dynamic HTML content. Successful exploitation would result in JavaScript code
execution under the context of the hosting web site.

Authentication Bypass
An even more critical HPP vulnerability was discovered in Blogger, the popular blogging platform. The bug allowed
malicious users to take ownership of the victim's blog by using the following HTTP request
( https://www.blogger.com/add-authors.do ):

POST /add-authors.do HTTP/1.1
[...]
security_token=attackertoken&blogID=attackerblogidvalue&blogID=victimblogidvalue&authorsList=goldshl
ager19test%40gmail.com(attacker email)&ok=Invite

The flaw resided in the authentication mechanism used by the web application, as the security check was performed on
the first blogID parameter, whereas the actual operation used the second occurrence.

Expected Behavior by Application Server
The following table illustrates how different web technologies behave in presence of multiple occurrences of the same
HTTP parameter.
Given the URL and querystring: http://example.com/?color=red&color=blue
Web Application Server Backend

Parsing Result

Example

ASP.NET / IIS

All occurrences concatenated with a comma

color=red,blue

ASP / IIS

All occurrences concatenated with a comma

color=red,blue

PHP / Apache

Last occurrence only

color=blue

PHP / Zeus

Last occurrence only

color=blue

JSP, Servlet / Apache Tomcat

First occurrence only

color=red

JSP, Servlet / Oracle Application Server 10g

First occurrence only

color=red

JSP, Servlet / Jetty

First occurrence only

color=red

IBM Lotus Domino

Last occurrence only

color=blue

IBM HTTP Server

First occurrence only

color=red

mod_perl, libapreq2 / Apache

First occurrence only

color=red

Perl CGI / Apache

First occurrence only

color=red

mod_wsgi (Python) / Apache

First occurrence only

color=red

Python / Zope

All occurrences in List data type

color=['red','blue']

(source: Appsec EU 2009 Carettoni & Paola)

Test Objectives
Identify the backend and the parsing method used.
Assess injection points and try bypassing input filters using HPP.

How to Test
Luckily, because the assignment of HTTP parameters is typically handled via the web application server, and not the
application code itself, testing the response to parameter pollution should be standard across all pages and actions.
However, as in-depth business logic knowledge is necessary, testing HPP requires manual testing. Automatic tools can
only partially assist auditors as they tend to generate too many false positives. In addition, HPP can manifest itself in
client-side and server-side components.

Server-Side HPP

To test for HPP vulnerabilities, identify any form or action that allows user-supplied input. Query string parameters in
HTTP GET requests are easy to tweak in the navigation bar of the browser. If the form action submits data via POST, the
tester will need to use an intercepting proxy to tamper with the POST data as it is sent to the server. Having identified a
particular input parameter to test, one can edit the GET or POST data by intercepting the request, or change the query
string after the response page loads. To test for HPP vulnerabilities simply append the same parameter to the GET or
POST data but with a different value assigned.
For example: if testing the search_string parameter in the query string, the request URL would include that
parameter name and value:

http://example.com/?search_string=kittens

The particular parameter might be hidden among several other parameters, but the approach is the same; leave the
other parameters in place and append the duplicate:

http://example.com/?mode=guest&search_string=kittens&num_results=100

Append the same parameter with a different value:

http://example.com/?mode=guest&search_string=kittens&num_results=100&search_string=puppies

and submit the new request.
Analyze the response page to determine which value(s) were parsed. In the above example, the search results may
show

kittens ,

puppies ,

some

combination

of

both

( kittens,puppies

or

kittens~puppies

or

['kittens','puppies'] ), may give an empty result, or error page.

This behavior, whether using the first, last, or combination of input parameters with the same name, is very likely to be
consistent across the entire application. Whether or not this default behavior reveals a potential vulnerability depends
on the specific input validation and filtering specific to a particular application. As a general rule: if existing input
validation and other security mechanisms are sufficient on single inputs, and if the server assigns only the first or last
polluted parameters, then parameter pollution does not reveal a vulnerability. If the duplicate parameters are
concatenated, different web application components use different occurrences or testing generates an error, there is an
increased likelihood of being able to use parameter pollution to trigger security vulnerabilities.
A more in-depth analysis would require three HTTP requests for each HTTP parameter:
1. Submit an HTTP request containing the standard parameter name and value, and record the HTTP response. E.g.
page?par1=val1

2. Replace the parameter value with a tampered value, submit and record the HTTP response. E.g. page?
par1=HPP_TEST1

3. Send a new request combining step (1) and (2). Again, save the HTTP response. E.g.

page?

par1=val1&par1=HPP_TEST1

4. Compare the responses obtained during all previous steps. If the response from (3) is different from (1) and the
response from (3) is also different from (2), there is an impedance mismatch that may be eventually abused to
trigger HPP vulnerabilities.
Crafting a full exploit from a parameter pollution weakness is beyond the scope of this text. See the references for
examples and details.

Client-Side HPP

Similarly to server-side HPP, manual testing is the only reliable technique to audit web applications in order to detect
parameter pollution vulnerabilities affecting client-side components. While in the server-side variant the attacker
leverages a vulnerable web application to access protected data or to perform actions that either not permitted or not
supposed to be executed, client-side attacks aim at subverting client-side components and technologies.
To test for HPP client-side vulnerabilities, identify any form or action that allows user input and shows a result of that
input back to the user. A search page is ideal, but a login box might not work (as it might not show an invalid username
back to the user).
Similarly to server-side HPP, pollute each HTTP parameter with %26HPP_TEST and look for url-decoded occurrences of
the user-supplied payload:
&HPP_TEST
&amp;HPP_TEST

etc.
In particular, pay attention to responses having HPP vectors within data , src , href attributes or forms actions.
Again, whether or not this default behavior reveals a potential vulnerability depends on the specific input validation,
filtering and application business logic. In addition, it is important to notice that this vulnerability can also affect query
string parameters used in XMLHttpRequest (XHR), runtime attribute creation and other plugin technologies (e.g. Adobe
Flash's flashvars variables).

Tools
OWASP ZAP Passive/Active Scanners

References
Whitepapers
HTTP Parameter Pollution - Luca Carettoni, Stefano di Paola
Client-side HTTP Parameter Pollution Example (Yahoo! Classic Mail flaw) - Stefano di Paola
How to Detect HTTP Parameter Pollution Attacks - Chrysostomos Daniel
CAPEC-460: HTTP Parameter Pollution (HPP) - Evgeny Lebanidze
Automated Discovery of Parameter Pollution Vulnerabilities in Web Applications - Marco Balduzzi, Carmen
Torrano Gimenez, Davide Balzarotti, Engin Kirda

---

## WSTG-INPV-15

**Testing for HTTP Splitting Smuggling**

Summary
This section illustrates examples of attacks that leverage specific features of the HTTP protocol, either by exploiting
weaknesses of the web application or peculiarities in the way different agents interpret HTTP messages. This section
will analyze two different attacks that target specific HTTP headers:
HTTP splitting
HTTP smuggling
The first attack exploits a lack of input sanitization which allows an intruder to insert CR and LF characters into the
headers of the application response and to 'split' that answer into two different HTTP messages. The goal of the attack
can vary from a cache poisoning to cross site scripting.
In the second attack, the attacker exploits the fact that some specially crafted HTTP messages can be parsed and
interpreted in different ways depending on the agent that receives them. HTTP smuggling requires some level of
knowledge about the different agents that are handling the HTTP messages (web server, proxy, firewall) and therefore
will be included only in the gray-box testing section.

Test Objectives
Assess if the application is vulnerable to splitting, identifying what possible attacks are achievable.
Assess if the chain of communication is vulnerable to smuggling, identifying what possible attacks are achievable.

How to Test
Black-Box Testing
HTTP Splitting
Some web applications use part of the user input to generate the values of some headers of their responses. The most
straightforward example is provided by redirections in which the target URL depends on some user-submitted value.
Let's say for instance that the user is asked to choose whether they prefer a standard or advanced web interface. The
choice will be passed as a parameter that will be used in the response header to trigger the redirection to the
corresponding page.
More specifically, if the parameter 'interface' has the value 'advanced', the application will answer with the following:

HTTP/1.1 302 Moved Temporarily
Date: Sun, 03 Dec 2005 16:22:19 GMT
Location: http://victim.com/main.jsp?interface=advanced
<snip>

When receiving this message, the browser will bring the user to the page indicated in the Location header. However, if
the application does not filter the user input, it will be possible to insert in the 'interface' parameter the sequence
%0d%0a, which represents the CRLF sequence that is used to separate different lines. At this point, testers will be able
to trigger a response that will be interpreted as two different responses by anybody who happens to parse it, for
instance a web cache sitting between us and the application. This can be leveraged by an attacker to poison this web
cache so that it will provide false content in all subsequent requests.

Let's say that in the previous example the tester passes the following data as the interface parameter:
advanced%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContentType:%20text/html%0d%0aContent-Length:%2035%0d%0a%0d%0a<html>Sorry,%20System%20Down</html>

The resulting answer from the vulnerable application will therefore be the following:

HTTP/1.1 302 Moved Temporarily
Date: Sun, 03 Dec 2005 16:22:19 GMT
Location: http://victim.com/main.jsp?interface=advanced
Content-Length: 0
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 35
<html>Sorry,%20System%20Down</html>
<other data>

The web cache will see two different responses, so if the attacker sends, immediately after the first request, a second
one asking for /index.html , the web cache will match this request with the second response and cache its content, so
that all subsequent requests directed to victim.com/index.html passing through that web cache will receive the
"system down" message. In this way, an attacker would be able to effectively deface the site for all users using that web
cache (the whole Internet, if the web cache is a reverse proxy for the web application).
Alternatively, the attacker could pass to those users a JavaScript snippet that mounts a cross site scripting attack, e.g.,
to steal the cookies. Note that while the vulnerability is in the application, the target here is its users. Therefore, in order
to look for this vulnerability, the tester needs to identify all user controlled input that influences one or more headers in
the response, and check whether they can successfully inject a CR+LF sequence in it.
The headers that are the most likely candidates for this attack are:
Location
Set-Cookie

It must be noted that a successful exploitation of this vulnerability in a real world scenario can be quite complex, as
several factors must be taken into account:
1. The pen-tester must properly set the headers in the fake response for it to be successfully cached (e.g., a LastModified header with a date set in the future). They might also have to destroy previously cached versions of the
target pagers, by issuing a preliminary request with Pragma: no-cache in the request headers
2. The application, while not filtering the CR+LF sequence, might filter other characters that are needed for a
successful attack (e.g., < and > ). In this case, the tester can try to use other encodings (e.g., UTF-7)
3. Some

targets

(e.g.,

ASP)

will

URL-encode

the

path

part

of

the

Location

header

(e.g.,

www.victim.com/redirect.asp ), making a CRLF sequence useless. However, they fail to encode the query

section (e.g., ?interface=advanced), meaning that a leading question mark is enough to bypass this filtering
For a more detailed discussion about this attack and other information about possible scenarios and applications,
check the papers referenced at the bottom of this section.

Gray-Box Testing
HTTP Splitting
A successful exploitation of HTTP Splitting is greatly helped by knowing some details of the web application and of the
attack target. For instance, different targets can use different methods to decide when the first HTTP message ends and
when the second starts. Some will use the message boundaries, as in the previous example. Other targets will assume
that different messages will be carried by different packets. Others will allocate for each message a number of chunks

of predetermined length: in this case, the second message will have to start exactly at the beginning of a chunk and this
will require the tester to use padding between the two messages. This might cause some trouble when the vulnerable
parameter is to be sent in the URL, as a very long URL is likely to be truncated or filtered. A gray-box scenario can help
the attacker to find a workaround: several application servers, for instance, will allow the request to be sent using POST
instead of GET.
HTTP Smuggling
As mentioned in the introduction, HTTP Smuggling leverages the different ways that a particularly crafted HTTP
message can be parsed and interpreted by different agents (browsers, web caches, application firewalls). This
relatively new kind of attack was first discovered by Chaim Linhart, Amit Klein, Ronen Heled and Steve Orrin in 2005.
There are several possible applications and we will analyze one of the most spectacular: the bypass of an application
firewall. Refer to the original whitepaper (linked at the bottom of this page) for more detailed information and other
scenarios.
Application Firewall Bypass

There are several products that enable a system administration to detect and block a hostile web request depending on
some known malicious pattern that is embedded in the request. For example, consider the infamous, old Unicode
directory traversal attack against IIS server, in which an attacker could break out the www root by issuing a request like:
http://target/scripts/..%c1%1c../winnt/system32/cmd.exe?/c+<command_to_execute>

Of course, it is quite easy to spot and filter this attack by the presence of strings like ".." and "cmd.exe" in the URL.
However, IIS 5.0 is quite picky about POST requests whose body is up to 48K bytes and truncates all content that is
beyond this limit when the Content-Type header is different from application/x-www-form-urlencoded. The pen-tester
can leverage this by creating a very large request, structured as follows:

POST /target.asp HTTP/1.1
Host: target
Connection: Keep-Alive
Content-Length: 49225
<CRLF>
<49152 bytes of garbage>

<-- Request #1

POST /target.asp HTTP/1.0
Connection: Keep-Alive
Content-Length: 33
<CRLF>

<-- Request #2

POST /target.asp HTTP/1.0
<-- Request #3
xxxx: POST /scripts/..%c1%1c../winnt/system32/cmd.exe?/c+dir HTTP/1.0
Connection: Keep-Alive
<CRLF>

<-- Request #4

What happens here is that the Request #1 is made of 49223 bytes, which includes also the lines of Request #2 .
Therefore, a firewall (or any other agent beside IIS 5.0) will see Request #1, will fail to see Request #2 (its data will be
just part of #1), will see Request #3 and miss Request #4 (because the POST will be just part of the fake header
xxxx).
Now, what happens to IIS 5.0 ? It will stop parsing Request #1 right after the 49152 bytes of garbage (as it will have
reached the 48K=49152 bytes limit) and will therefore parse Request #2 as a new, separate request. Request #2
claims that its content is 33 bytes, which includes everything until "xxxx: ", making IIS miss Request #3 (interpreted as
part of Request #2 ) but spot Request #4 , as its POST starts right after the 33rd byte or Request #2 . It is a bit

complicated, but the point is that the attack URL will not be detected by the firewall (it will be interpreted as the body of
a previous request) but will be correctly parsed (and executed) by IIS.
While in the aforementioned case the technique exploits a bug of a web server, there are other scenarios in which we
can leverage the different ways that different HTTP-enabled devices parse messages that are not 1005 RFC compliant.
For instance, the HTTP protocol allows only one Content-Length header, but does not specify how to handle a
message that has two instances of this header. Some implementations will use the first one while others will prefer the
second, cleaning the way for HTTP Smuggling attacks. Another example is the use of the Content-Length header in a
GET message.
Note that HTTP Smuggling does *not* exploit any vulnerability in the target web application. Therefore, it might be
somewhat tricky, in a pen-test engagement, to convince the client that a countermeasure should be looked for anyway.

References
Whitepapers
Amit Klein, "Divide and Conquer: HTTP Response Splitting, Web Cache Poisoning Attacks, and Related Topics"
Amit Klein: "HTTP Message Splitting, Smuggling and Other Animals"
Amit Klein: "HTTP Request Smuggling - ERRATA (the IIS 48K buffer phenomenon)"
Amit Klein: "HTTP Response Smuggling"
Chaim Linhart, Amit Klein, Ronen Heled, Steve Orrin: "HTTP Request Smuggling"

---

## WSTG-INPV-16

**Testing for HTTP Incoming Requests**

Summary
This section describes how to monitor all incoming/outgoing HTTP requests on both client-side or server-side. The
purpose of this testing is to verify if there is unnecessary or suspicious HTTP request sending in the background.
Most of Web security testing tools (i.e. AppScan, BurpSuite, ZAP) act as HTTP Proxy. This will require changes of proxy
on client-side application or browser. The testing techniques listed below is primary focused on how we can monitor
HTTP requests without changes of client-side which will be more close to production usage scenario.

Test Objectives
Monitor all incoming and outgoing HTTP requests to the Web Server to inspect any suspicious requests.
Monitor HTTP traffic without changes of end user Browser proxy or client-side application.

How to Test
Reverse Proxy
There is situation that we would like to monitor all HTTP incoming requests on web server but we can't change
configuration on the browser or application client-side. In this scenario, we can setup a reverse proxy on web server
end to monitor all incoming/outgoing requests on web server.
For windows platform, Fiddler is recommended. It provides not only monitor but can also edit/reply the HTTP requests.
Refer to this reference for how to configure Fiddler as reverse Proxy
For Linux platform, Charles Web Debugging Proxy may be used.
The testing steps:
1. Install Fiddler or Charles on Web Server
2. Configure the Fiddler or Charles as Reverse Proxy
3. Capture the HTTP traffic
4. Inspect HTTP traffic
5. Modify HTTP requests and replay the modified requests for testing

Port Forwarding
Port forwarding is another way to allow us intercept HTTP requests without changes of client-side. You can also use
Charles as a SOCKS proxy to act as port forwarding or uses of Port Forwarding tools. It will allow us to forward all
coming client-side captured traffic to web server port.
The testing flow will be:
1. Install the Charles or port forwarding on another machine or web Server
2. Configure the Charles as Socks proxy as port forwarding.

TCP-level Network Traffic Capture

This technique monitor all the network traffic at TCP-level. TCPDump or WireShark tools can be used. However, these
tools don't allow us edit the captured traffic and send modified HTTP requests for testing. To replay the captured traffic
(PCAP) packets, Ostinato can be used.
The testing steps will be:
1. Activate TCPDump or WireShark on Web Server to capture network traffic
2. Monitor the captured files (PCAP)
3. Edit PCAP files by Ostinato tool based on need
4. Reply the HTTP requests
Fiddler or Charles are recommended since these tools can capture HTTP traffic and also easily edit/reply the modified
HTTP requests. In addition, if the web traffic is HTTPS, the wireshark will need to import the web server private key to
inspect the HTTPS message body. Otherwise, the HTTPS message body of the captured traffic will all be encrypted.

Tools
Fiddler
TCPProxy
Charles Web Debugging Proxy
WireShark
PowerEdit-Pcap
pcapteller
replayproxy
Ostinato

References
Charles Web Debugging Proxy
Fiddler
TCPDUMP
Ostinato

---

## WSTG-INPV-17

**Testing for Host Header Injection**

Summary
A web server commonly hosts several web applications on the same IP address, referring to each application via the
virtual host. In an incoming HTTP request, web servers often dispatch the request to the target virtual host based on the
value supplied in the Host header. Without proper validation of the header value, the attacker can supply invalid input
to cause the web server to:
dispatch requests to the first virtual host on the list
cause a redirect to an attacker-controlled domain
perform web cache poisoning
manipulate password reset functionality

Test Objectives
Assess if the Host header is being parsed dynamically in the application.
Bypass security controls that rely on the header.

How to Test
Initial testing is as simple as supplying another domain (i.e. attacker.com ) into the Host header field. It is how the web
server processes the header value that dictates the impact. The attack is valid when the web server processes the input
to send the request to an attacker-controlled host that resides at the supplied domain, and not to an internal virtual host
that resides on the web server.

GET / HTTP/1.1
Host: www.attacker.com
[...]

In the simplest case, this may cause a 302 redirect to the supplied domain.

HTTP/1.1 302 Found
[...]
Location: http://www.attacker.com/login.php

Alternatively, the web server may send the request to the first virtual host on the list.

X-Forwarded Host Header Bypass
In the event that Host header injection is mitigated by checking for invalid input injected via the Host header, you can
supply the value to the X-Forwarded-Host header.

GET / HTTP/1.1
Host: www.example.com
X-Forwarded-Host: www.attacker.com
...

Potentially producing client-side output such as:

...
<link src="http://www.attacker.com/link" />
...

Once again, this depends on how the web server processes the header value.

Web Cache Poisoning
Using this technique, an attacker can manipulate a web-cache to serve poisoned content to anyone who requests it.
This relies on the ability to poison the caching proxy run by the application itself, CDNs, or other downstream providers.
As a result, the victim will have no control over receiving the malicious content when requesting the vulnerable
application.

GET / HTTP/1.1
Host: www.attacker.com
...

The following will be served from the web cache, when a victim visits the vulnerable application.

...
<link src="http://www.attacker.com/link" />
...

Password Reset Poisoning
It is common for password reset functionality to include the Host header value when creating password reset links that
use a generated secret token. If the application processes an attacker-controlled domain to create a password reset
link, the victim may click on the link in the email and allow the attacker to obtain the reset token, thus resetting the
victim's password.

... Email snippet ...
Click on the following link to reset your password:
http://www.attacker.com/index.php?module=Login&action=resetPassword&token=<SECRET_TOKEN>
... Email snippet ...

References
What is a Host Header Attack?
Host Header Attack
Practical HTTP Host Header Attacks

---
