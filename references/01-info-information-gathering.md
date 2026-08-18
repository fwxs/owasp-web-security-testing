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
In order for search engines to work, computer programs (or robots ) regularly fetch data (referred to as crawling from
billions of pages on the web. These programs find web content and functionality by following links from other pages, or
by looking at sitemaps. If a website uses a special file called robots.txt to list pages that it does not want search
engines to fetch, then the pages listed there will be ignored. This is a basic overview - Google offers a more in-depth
explanation of how a search engine works.
Testers can use search engines to perform reconnaissance on websites and web applications. There are direct and
indirect elements to search engine discovery and reconnaissance: direct methods relate to searching the indexes and
the associated content from caches, while indirect methods relate to learning sensitive design and configuration
information by searching forums, newsgroups, and tendering websites.
Once a search engine robot has completed crawling, it commences indexing the web content based on tags and
associated attributes, such as <TITLE> , in order to return relevant search results. If the robots.txt file is not updated
during the lifetime of the web site, and in-line HTML meta tags that instruct robots not to index content have not been
used, then it is possible for indexes to contain web content not intended to be included by the owners. Website owners
may use the previously mentioned robots.txt , HTML meta tags, authentication, and tools provided by search
engines to remove such content.

Test Objectives
Identify what sensitive design and configuration information of the application, system, or organization is exposed
directly (on the organization's website) or indirectly (via third-party services).

How to Test
Use a search engine to search for potentially sensitive information. This may include:
network diagrams and configurations;
archived posts and emails by administrators or other key staff;
logon procedures and username formats;
usernames, passwords, and private keys;
third-party, or cloud service configuration files;
revealing error message content; and
development, test, User Acceptance Testing (UAT), and staging versions of sites.

Search Engines
Do not limit testing to just one search engine provider, as different search engines may generate different results.
Search engine results can vary in a few ways, depending on when the engine last crawled content, and the algorithm
the engine uses to determine relevant pages. Consider using the following (alphabetically-listed) search engines:
Baidu, China's most popular search engine.
Bing, a search engine owned and operated by Microsoft, and the second most popular worldwide. Supports
advanced search keywords.

binsearch.info, a search engine for binary Usenet newsgroups.
Common Crawl, "an open repository of web crawl data that can be accessed and analyzed by anyone."
DuckDuckGo, a privacy-focused search engine that compiles results from many different sources. Supports search
syntax.
Google, which offers the world's most popular search engine, and uses a ranking system to attempt to return the
most relevant results. Supports search operators.
Internet Archive Wayback Machine, "building a digital library of Internet sites and other cultural artifacts in digital
form."
Startpage, a search engine that uses Google's results without collecting personal information through trackers and
logs. Supports search operators.
Shodan, a service for searching Internet-connected devices and services. Usage options include a limited free
plan as well as paid subscription plans.
Both DuckDuckGo and Startpage offer some increased privacy to users by not utilizing trackers or keeping logs. This
can provide reduced information leakage about the tester.

Search Operators
A search operator is a special keyword or syntax that extends the capabilities of regular search queries, and can help
obtain more specific results. They generally take the form of operator:query . Here are some commonly supported
search operators:
site: will limit the search to the provided domain.
inurl: will only return results that include the keyword in the URL.
intitle: will only return results that have the keyword in the page title.
intext: or inbody: will only search for the keyword in the body of pages.
filetype: will match only a specific filetype, i.e. png, or php.

For example, to find the web content of owasp.org as indexed by a typical search engine, the syntax required is:

site:owasp.org

Figure 4.1.1-1: Google Site Operation Search Result Example

Viewing Cached Content
To search for content that has previously been indexed, use the cache: operator. This is helpful for viewing content
that may have changed since the time it was indexed, or that may no longer be available. Not all search engines
provide cached content to search; the most useful source at time of writing is Google.
To view owasp.org as it is cached, the syntax is:

cache:owasp.org

Figure 4.1.1-2: Google Cache Operation Search Result Example

Google Hacking, or Dorking
Searching with operators can be a very effective discovery technique when combined with the creativity of the tester.
Operators can be chained to effectively discover specific kinds of sensitive files and information. This technique, called
Google hacking or Dorking, is also possible using other search engines, as long as the search operators are
supported.
A database of dorks, such as Google Hacking Database, is a useful resource that can help uncover specific
information. Some categories of dorks available on this database include:
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

Databases for other search engines, such as Bing and Shodan, are available from resources such as Bishop Fox's
Google Hacking Diggity Project.

Remediation
Carefully consider the sensitivity of design and configuration information before it is posted online.
Periodically review the sensitivity of existing design and configuration information that is posted online.

---

## WSTG-INFO-02

**Fingerprint Web Server**

Summary
Web server fingerprinting is the task of identifying the type and version of web server that a target is running on. While
web server fingerprinting is often encapsulated in automated testing tools, it is important for researchers to understand
the fundamentals of how these tools attempt to identify software, and why this is useful.
Accurately discovering the type of web server that an application runs on can enable security testers to determine if the
application is vulnerable to attack. In particular, servers running older versions of software without up-to-date security
patches can be susceptible to known version-specific exploits.

Test Objectives
Determine the version and type of a running web server to enable further discovery of any known vulnerabilities.

How to Test
Techniques used for web server fingerprinting include banner grabbing, eliciting responses to malformed requests, and
using automated tools to perform more robust scans that use a combination of tactics. The fundamental premise by
which all these techniques operate is the same. They all strive to elicit some response from the web server which can
then be compared to a database of known responses and behaviors, and thus matched to a known server type.

Banner Grabbing
A banner grab is performed by sending an HTTP request to the web server and examining its response header. This
can be accomplished using a variety of tools, including telnet for HTTP requests, or openssl for requests over SSL.
For example, here is the response to a request from an Apache server.

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

Here is another response, this time from nginx.

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

Here's what a response from lighttpd looks like.

HTTP/1.0 200 OK
Content-Type: text/html
Accept-Ranges: bytes
ETag: "4192788355"
Last-Modified: Thu, 05 Sep 2019 17:40:42 GMT
Content-Length: 117
Connection: close
Date: Thu, 05 Sep 2019 17:57:57 GMT
Server: lighttpd/1.4.54

In these examples, the server type and version is clearly exposed. However, security-conscious applications may
obfuscate their server information by modifying the header. For example, here is an excerpt from the response to a
request for a site with a modified header:

HTTP/1.1 200 OK
Server: Website.com
Date: Thu, 05 Sep 2019 17:57:06 GMT
Content-Type: text/html; charset=utf-8
Status: 200 OK
...

In cases where the server information is obscured, testers may guess the type of server based on the ordering of the
header fields. Note that in the Apache example above, the fields follow this order:
Date
Server
Last-Modified
ETag
Accept-Ranges
Content-Length
Connection
Content-Type
However, in both the nginx and obscured server examples, the fields in common follow this order:
Server
Date
Content-Type
Testers can use this information to guess that the obscured server is nginx. However, considering that a number of
different web servers may share the same field ordering and fields can be modified or removed, this method is not
definite.

Sending Malformed Requests
Web servers may be identified by examining their error responses, and in the cases where they have not been
customized, their default error pages. One way to compel a server to present these is by sending intentionally incorrect
or malformed requests.

For example, here is the response to a request for the non-existent method SANTA CLAUS from an Apache server.

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

Here is the response to the same request from nginx.

GET / SANTA CLAUS/1.1

<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.17.3</center>
</body>
</html>

Here is the response to the same request from lighttpd.

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

As default error pages offer many differentiating factors between types of web servers, their examination can be an
effective method for fingerprinting even when server header fields are obscured.

Using Automated Scanning Tools
As stated earlier, web server fingerprinting is often included as a functionality of automated scanning tools. These tools
are able to make requests similar to those demonstrated above, as well as send other more server-specific probes.
Automated tools can compare responses from web servers much faster than manual testing, and utilize large
databases of known responses to attempt server identification. For these reasons, automated tools are more likely to
produce accurate results.
Here are some commonly-used scan tools that include web server fingerprinting functionality.
Netcraft, an online tool that scans websites for information, including the web server.
Nikto, an Open Source command-line scanning tool.
Nmap, an Open Source command-line tool that also has a GUI, Zenmap.

Remediation
While exposed server information is not necessarily in itself a vulnerability, it is information that can assist attackers in
exploiting other vulnerabilities that may exist. Exposed server information can also lead attackers to find versionspecific server vulnerabilities that can be used to exploit unpatched servers. For this reason it is recommended that
some precautions be taken. These actions include:
Obscuring web server information in headers, such as with Apache's mod_headers module.
Using a hardened reverse proxy server to create an additional layer of security between the web server and the
Internet.
Ensuring that web servers are kept up-to-date with the latest software and security patches.

---

## WSTG-INFO-03

**Review Webserver Metafiles for Information Leakage**

Summary
This section describes how to test various metadata files for information leakage of the web application's path(s), or
functionality. Furthermore, the list of directories that are to be avoided by Spiders, Robots, or Crawlers can also be
created as a dependency for Map execution paths through application. Other information may also be collected to
identify attack surface, technology details, or for use in social engineering engagement.

Test Objectives
Identify hidden or obfuscated paths and functionality through the analysis of metadata files.
Extract and map other information that could lead to better understanding of the systems at hand.

How to Test
Any of the actions performed below with wget could also be done with curl . Many Dynamic Application
Security Testing (DAST) tools such as ZAP and Burp Suite include checks or parsing for these resources as part of
their spider/crawler functionality. They can also be identified using various Google Dorks or leveraging advanced
search features such as inurl: .

Robots
Web Spiders, Robots, or Crawlers retrieve a web page and then recursively traverse hyperlinks to retrieve further web
content. Their accepted behavior is specified by the Robots Exclusion Protocol of the robots.txt file in the web root
directory.
As an example, the beginning of the robots.txt file from Google sampled on 2020 May 5 is quoted below:

User-agent: *
Disallow: /search
Allow: /search/about
Allow: /search/static
Allow: /search/howsearchworks
Disallow: /sdch
...

The User-Agent directive refers to the specific web spider/robot/crawler. For example, the User-Agent: Googlebot
refers to the spider from Google while User-Agent: bingbot refers to a crawler from Microsoft. User-Agent: * in the
example above applies to all web spiders/robots/crawlers.
The Disallow directive specifies which resources are prohibited by spiders/robots/crawlers. In the example above, the
following are prohibited:

...
Disallow: /search
...
Disallow: /sdch
...

Web spiders/robots/crawlers can intentionally ignore the Disallow directives specified in a robots.txt file, such as
those from Social Networks to ensure that shared linked are still valid. Hence, robots.txt should not be considered
as a mechanism to enforce restrictions on how web content is accessed, stored, or republished by third parties.
The robots.txt file is retrieved from the web root directory of the web server. For example, to retrieve the robots.txt
from www.google.com using wget or curl :

$ curl -O -Ss http://www.google.com/robots.txt && head -n5 robots.txt
User-agent: *
Disallow: /search
Allow: /search/about
Allow: /search/static
Allow: /search/howsearchworks
...

Analyze robots.txt Using Google Webmaster Tools
Web site owners can use the Google "Analyze robots.txt" function to analyze the website as part of its Google
Webmaster Tools. This tool can assist with testing and the procedure is as follows:
1. Sign into Google Webmaster Tools with a Google account.
2. On the dashboard, enter the URL for the site to be analyzed.
3. Choose between the available methods and follow the on screen instruction.

META Tags
<META> tags are located within the HEAD section of each HTML document and should be consistent across a web site
in the event that the robot/spider/crawler start point does not begin from a document link other than webroot i.e. a deep

link. Robots directive can also be specified through use of a specific META tag.
Robots META Tag
If there is no <META NAME="ROBOTS" ... > entry then the "Robots Exclusion Protocol" defaults to INDEX,FOLLOW
respectively. Therefore, the other two valid entries defined by the "Robots Exclusion Protocol" are prefixed with NO...
i.e. NOINDEX and NOFOLLOW .
Based on the Disallow directive(s) listed within the robots.txt file in webroot, a regular expression search for <META
NAME="ROBOTS" within each web page is undertaken and the result compared to the robots.txt file in webroot.

Miscellaneous META Information Tags
Organizations often embed informational META tags in web content to support various technologies such as screen
readers, social networking previews, search engine indexing, etc. Such meta-information can be of value to testers in
identifying technologies used, and additional paths/functionality to explore and test. The following meta information
was retrieved from www.whitehouse.gov via View Page Source on 2020 May 05:

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
A sitemap is a file where a developer or organization can provide information about the pages, videos, and other files
offered by the site or application, and the relationship between them. Search engines can use this file to more
intelligently explore your site. Testers can use sitemap.xml files to learn more about the site or application to explore it
more completely.
The following excerpt is from Google's primary sitemap retrieved 2020 May 05.

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

Exploring from there a tester may wish to retrieve the gmail sitemap https://www.google.com/gmail/sitemap.xml :

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
security.txt is a proposed standard which allows websites to define security policies and contact details. There are

multiple reasons this might be of interest in testing scenarios, including but not limited to:
Identifying further paths or resources to include in discovery/analysis.
Open Source intelligence gathering.
Finding information on Bug Bounties, etc.
Social Engineering.

The file may be present either in the root of the webserver or in the .well-known/ directory. Ex:
https://example.com/security.txt
https://example.com/.well-known/security.txt

Here is a real world example retrieved from LinkedIn 2020 May 05:

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
humans.txt is an initiative for knowing the people behind a website. It takes the form of a text file that contains

information about the different people who have contributed to building the website. See humanstxt for more info. This
file often (though not always) contains information for career or job sites/paths.
The following example was retrieved from Google 2020 May 05:

$ wget --no-verbose https://www.google.com/humans.txt && cat humans.txt
2020-05-07 12:57:52 URL:https://www.google.com/humans.txt [286/286] -> "humans.txt" [1]
Google is built by a large team of engineers, designers, researchers, robots, and others in many
different sites across the globe. It is updated continuously, and built with more tools and
technologies than we can shake a stick at. If you'd like to help us out, see careers.google.com.

Other .well-known Information Sources
There are other RFCs and Internet drafts which suggest standardized uses of files within the .well-known/ directory.
Lists of which can be found here or here.
It would be fairly simple for a tester to review the RFC/drafts are create a list to be supplied to a crawler or fuzzer, in
order to verify the existence or content of such files.

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
A paramount step in testing for web application vulnerabilities is to find out which particular applications are hosted on
a web server. Many applications have known vulnerabilities and known attack strategies that can be exploited in order
to gain remote control or to exploit data. In addition, many applications are often misconfigured or not updated, due to
the perception that they are only used "internally" and therefore no threat exists. With the proliferation of virtual web
servers, the traditional 1:1-type relationship between an IP address and a web server is losing much of its original
significance. It is not uncommon to have multiple web sites or applications whose symbolic names resolve to the same
IP address. This scenario is not limited to hosting environments, but also applies to ordinary corporate environments as
well.
Security professionals are sometimes given a set of IP addresses as a target to test. It is arguable that this scenario is
more akin to a penetration test-type engagement, but in any case it is expected that such an assignment would test all
web applications accessible through this target. The problem is that the given IP address hosts an HTTP service on port
80, but if a tester should access it by specifying the IP address (which is all they know) it reports "No web server
configured at this address" or a similar message. But that system could "hide" a number of web applications, associated
to unrelated symbolic (DNS) names. Obviously, the extent of the analysis is deeply affected by the tester tests all
applications or only tests the applications that they are aware of.
Sometimes, the target specification is richer. The tester may be given a list of IP addresses and their corresponding
symbolic names. Nevertheless, this list might convey partial information, i.e., it could omit some symbolic names and
the client may not even being aware of that (this is more likely to happen in large organizations).
Other issues affecting the scope of the assessment are represented by web applications published at non-obvious
URLs (e.g., http://www.example.com/some-strange-URL ), which are not referenced elsewhere. This may happen
either by error (due to misconfigurations), or intentionally (for example, unadvertised administrative interfaces).
To address these issues, it is necessary to perform web application discovery.

Test Objectives
Enumerate the applications within scope that exist on a web server.

How to Test
Web application discovery is a process aimed at identifying web applications on a given infrastructure. The latter is
usually specified as a set of IP addresses (maybe a net block), but may consist of a set of DNS symbolic names or a mix
of the two. This information is handed out prior to the execution of an assessment, be it a classic-style penetration test
or an application-focused assessment. In both cases, unless the rules of engagement specify otherwise (e.g., test only
the application located at the URL http://www.example.com/ ), the assessment should strive to be the most
comprehensive in scope, i.e. it should identify all the applications accessible through the given target. The following
examples examine a few techniques that can be employed to achieve this goal.
Some of the following techniques apply to Internet-facing web servers, namely DNS and reverse-IP web-based
search services and the use of search engines. Examples make use of private IP addresses (such as
192.168.1.100 ), which, unless indicated otherwise, represent generic IP addresses and are used only for
anonymity purposes.

There are three factors influencing how many applications are related to a given DNS name (or an IP address):
1. Different Base URL
The obvious entry point for a web application is www.example.com , i.e., with this shorthand notation we think of the
web application originating at http://www.example.com/ (the same applies for https). However, even though this
is the most common situation, there is nothing forcing the application to start at / .
For example, the same symbolic name may be associated to three web applications such as:
http://www.example.com/url1

http://www.example.com/url2

http://www.example.com/url3

In this case, the URL http://www.example.com/ would not be associated with a meaningful page, and the three
applications would be hidden, unless the tester explicitly knows how to reach them, i.e., the tester knows url1, url2
or url3. There is usually no need to publish web applications in this way, unless the owner doesn't want them to be
accessible in a standard way, and is prepared to inform the users about their exact location. This doesn't mean that
these applications are secret, just that their existence and location is not explicitly advertised.
2. Non-standard Ports
While web applications usually live on port 80 (http) and 443 (https), there is nothing magic about these port
numbers. In fact, web applications may be associated with arbitrary TCP ports, and can be referenced by
specifying
the
port
number
as
follows:
http[s]://www.example.com:port/ .
For
example,
http://www.example.com:20000/ .

3. Virtual Hosts
DNS allows a single IP address to be associated with one or more symbolic names. For example, the IP address
might be associated to DNS names
www.example.com ,
helpdesk.example.com ,
webmail.example.com . It is not necessary that all the names belong to the same DNS domain. This 1-to-N
192.168.1.100

relationship may be reflected to serve different content by using so called virtual hosts. The information specifying
the virtual host we are referring to is embedded in the HTTP 1.1 Host header.
One would not suspect the existence of other web applications in addition to the obvious www.example.com ,
unless they know of helpdesk.example.com and webmail.example.com .

Approaches to Address Issue 1 - Non-standard URLs
There is no way to fully ascertain the existence of non-standard-named web applications. Being non-standard, there is
no fixed criteria governing the naming convention, however there are a number of techniques that the tester can use to
gain some additional insight.
First, if the web server is mis-configured and allows directory browsing, it may be possible to spot these applications.
Vulnerability scanners may help in this respect.
Second, these applications may be referenced by other web pages and there is a chance that they have been spidered
and indexed by web search engines. If testers suspect the existence of such hidden applications on www.example.com
they could search using the site operator and examining the result of a query for site: www.example.com . Among the
returned URLs there could be one pointing to such a non-obvious application.
Another option is to probe for URLs which might be likely candidates for non-published applications. For example, a
web

mail

front

end

might

be

accessible

from

URLs

such

as

https://www.example.com/webmail ,

https://webmail.example.com/ , or https://mail.example.com/ . The same holds for administrative interfaces, which

may be published at hidden URLs (for example, a Tomcat administrative interface), and yet not referenced anywhere.
So doing a bit of dictionary-style searching (or "intelligent guessing") could yield some results. Vulnerability scanners
may help in this respect.

Approaches to Address Issue 2 - Non-standard Ports

It is easy to check for the existence of web applications on non-standard ports. A port scanner such as nmap is capable
of performing service recognition by means of the -sV option, and will identify http[s] services on arbitrary ports. What
is required is a full scan of the whole 64k TCP port address space.
For example, the following command will look up, with a TCP connect scan, all open ports on IP 192.168.1.100 and
will try to determine what services are bound to them (only essential switches are shown - nmap features a broad set of
options, whose discussion is out of scope):
nmap -Pn -sT -sV -p0-65535 192.168.1.100

It is sufficient to examine the output and look for http or the indication of SSL-wrapped services (which should be
probed to confirm that they are https). For example, the output of the previous command could look like:

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

From this example, one see that:
There is an Apache HTTP server running on port 80.
It looks like there is an HTTPS server on port 443 (but this needs to be confirmed, for example, by visiting
https://192.168.1.100 with a browser).
On port 901 there is a Samba SWAT web interface.
The service on port 1241 is not HTTPS, but is the SSL-wrapped Nessus daemon.
Port 3690 features an unspecified service (nmap gives back its fingerprint - here omitted for clarity - together with
instructions to submit it for incorporation in the nmap fingerprint database, provided you know which service it
represents).
Another unspecified service on port 8000; this might possibly be HTTP, since it is not uncommon to find HTTP
servers on this port. Let's examine this issue:

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

This confirms that in fact it is an HTTP server. Alternatively, testers could have visited the URL with a web browser; or
used the GET or HEAD Perl commands, which mimic HTTP interactions such as the one given above (however HEAD
requests may not be honored by all servers).

Apache Tomcat running on port 8080.
The same task may be performed by vulnerability scanners, but first check that the scanner of choice is able to identify
HTTP[S] services running on non-standard ports. For example, Nessus is capable of identifying them on arbitrary ports
(provided it is instructed to scan all the ports), and will provide, with respect to nmap, a number of tests on known web
server vulnerabilities, as well as on the SSL configuration of HTTPS services. As hinted before, Nessus is also able to
spot popular applications or web interfaces which could otherwise go unnoticed (for example, a Tomcat administrative
interface).

Approaches to Address Issue 3 - Virtual Hosts
There are a number of techniques which may be used to identify DNS names associated to a given IP address
x.y.z.t .

DNS Zone Transfers
This technique has limited use nowadays, given the fact that zone transfers are largely not honored by DNS servers.
However, it may be worth a try. First of all, testers must determine the name servers serving x.y.z.t . If a symbolic
name is known for x.y.z.t (let it be www.example.com ), its name servers can be determined by means of tools such
as nslookup , host , or dig , by requesting DNS NS records.
If no symbolic names are known for x.y.z.t , but the target definition contains at least a symbolic name, testers may
try to apply the same process and query the name server of that name (hoping that x.y.z.t will be served as well by
that name server). For example, if the target consists of the IP address x.y.z.t and the name mail.example.com ,
determine the name servers for domain example.com .
The following example shows how to identify the name servers for www.owasp.org by using the host command:

$ host -t ns www.owasp.org
www.owasp.org is an alias for owasp.org.
owasp.org name server ns1.secure.net.
owasp.org name server ns2.secure.net.

A zone transfer may now be requested to the name servers for domain example.com . If the tester is lucky, they will get
back a list of the DNS entries for this domain. This will include the obvious www.example.com and the not-so-obvious
helpdesk.example.com and webmail.example.com (and possibly others). Check all names returned by the zone
transfer and consider all of those which are related to the target being evaluated.
Trying to request a zone transfer for owasp.org from one of its name servers:

$ host -l www.owasp.org ns1.secure.net
Using domain server:
Name: ns1.secure.net
Address: 192.220.124.10#53
Aliases:
Host www.owasp.org not found: 5(REFUSED)
; Transfer failed.

DNS Inverse Queries
This process is similar to the previous one, but relies on inverse (PTR) DNS records. Rather than requesting a zone
transfer, try setting the record type to PTR and issue a query on the given IP address. If the testers are lucky, they may
get back a DNS name entry. This technique relies on the existence of IP-to-symbolic name maps, which is not
guaranteed.
Web-based DNS Searches

This kind of search is akin to DNS zone transfer, but relies on web-based services that enable name-based searches
on DNS. One such service is the Netcraft Search DNS service. The tester may query for a list of names belonging to
your domain of choice, such as example.com . Then they will check whether the names they obtained are pertinent to
the target they are examining.
Reverse-IP Services
Reverse-IP services are similar to DNS inverse queries, with the difference that the testers query a web-based
application instead of a name server. There are a number of such services available. Since they tend to return partial
(and often different) results, it is better to use multiple services to obtain a more comprehensive analysis.
Domain Tools Reverse IP (requires free membership)
Bing, syntax: ip:x.x.x.x
Webhosting Info, syntax: http://whois.webhosting.info/x.x.x.x
DNSstuff (multiple services available)
Net Square (multiple queries on domains and IP addresses, requires installation)
The following example shows the result of a query to one of the above reverse-IP services to 216.48.3.18 , the IP
address of www.owasp.org. Three additional non-obvious symbolic names mapping to the same address have been
revealed.

Figure 4.1.4-1: OWASP Whois Info

Googling
Following information gathering from the previous techniques, testers can rely on search engines to possibly refine and
increment their analysis. This may yield evidence of additional symbolic names belonging to the target, or applications
accessible via non-obvious URLs.
For instance, considering the previous example regarding www.owasp.org , the tester could query Google and other
search engines looking for information (hence, DNS names) related to the newly discovered domains of webgoat.org ,
webscarab.com , and webscarab.net .

Googling techniques are explained in Testing: Spiders, Robots, and Crawlers.

Tools
DNS lookup tools such as nslookup , dig and similar.
Search engines (Google, Bing and other major search engines).
Specialized DNS-related web-based search service: see text.

Nmap
Nessus Vulnerability Scanner
Nikto

---

## WSTG-INFO-05

**Review Webpage Content for Information Leakage**

Summary
It is very common, and even recommended, for programmers to include detailed comments and metadata on their
source code. However, comments and metadata included into the HTML code might reveal internal information that
should not be available to potential attackers. Comments and metadata review should be done in order to determine if
any information is being leaked.
For modern web apps, the use of client-Side JavaScript for the front-end is becoming more popular. Popular front-end
construction technologies use client-side JavaScript like ReactJS, AngularJS, or Vue. Similar to the comments and
metadata in HTML code, many programmers also hardcod sensitive information in JavaScript variables on the frontend. Sensitive information can include (but is not limited to): Private API Keys (e.g. an unrestricted Google Map API
Key), internal IP addresses, sensitive routes (e.g. route to hidden admin pages or functionality), or even credentials.
This sensitive information can be leaked from such front-end JavaScript code. A review should be done in order to
determine if any sensitive information leaked which could be used by attackers for abuse.
For large web applications, performance issues are a big concern to programmers. Programmers have used different
methods to optimize front-end performance, including Syntactically Awesome Style Sheets (SASS), Sassy CSS
(SCSS), webpack, etc. Using these technologies, front-end code will sometimes become harder to understand and
difficult to debug, and because of it, programmers often deploy source map files for debugging purposes. A "source
map" is a special file that connects a minified/uglified version of an asset (CSS or JavaScript) to the original authored
version. Programmers are still debating whether or not to bring source map files to the production environment.
However, it is undeniable that source map files or files for debugging if released to the production environment will
make their source more human-readable. It can make it easier for attackers to find vulnerabilities from the front-end or
collect sensitive information from it. JavaScript code review should be done in order to determine if any debug files are
exposed from the front-end. Depending on the context and sensitivity of the project, a security expert should decide
whether the files should exist in the production environment or not.

Test Objectives
Review webpage comments and metadata to find any information leakage.
Gather JavaScript files and review the JS code to better understand the application and to find any information
leakage.
Identify if source map files or other front-end debug files exist.

How to Test
Review webpage comments and metadata
HTML comments are often used by the developers to include debugging information about the application. Sometimes,
they forget about the comments and they leave them in production environments. Testers should look for HTML
comments which start with <!-- .
Check HTML source code for comments containing sensitive information that can help the attacker gain more insight
about the application. It might be SQL code, usernames and passwords, internal IP addresses, or debugging
information.

...
<div class="table2">

<div class="col1">1</div><div class="col2">Mary</div>
<div class="col1">2</div><div class="col2">Peter</div>
<div class="col1">3</div><div class="col2">Joe</div>
<!-- Query: SELECT id, name FROM app.users WHERE active='1' -->
</div>
...

The tester may even find something like this:

<!-- Use the DB administrator password for testing:

f@keP@a$$w0rD -->

Check HTML version information for valid version numbers and Data Type Definition (DTD) URLs

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">

strict.dtd - default strict DTD
loose.dtd - loose DTD
frameset.dtd - DTD for frameset documents

Some META tags do not provide active attack vectors but instead allow an attacker to profile an application:

<META name="Author" content="Andrew Muller">

A common (but not WCAG compliant) META tag is Refresh.

<META http-equiv="Refresh" content="15;URL=https://www.owasp.org/index.html">

A common use for META tag is to specify keywords that a search engine may use to improve the quality of search
results.

<META name="keywords" lang="en-us" content="OWASP, security, sunshine, lollipops">

Although most web servers manage search engine indexing via the robots.txt file, it can also be managed by META
tags. The tag below will advise robots to not index and not follow links on the HTML page containing the tag.

<META name="robots" content="none">

The Platform for Internet Content Selection (PICS) and Protocol for Web Description Resources (POWDER) provide
infrastructure for associating metadata with Internet content.

Identifying JavaScript Code and Gathering JavaScript Files
Programmers often hardcode sensitive information with JavaScript variables on the front-end. Testers should check
HTML source code and look for JavaScript code between <script> and </script> tags. Testers should also identify
external JavaScript files to review the code (JavaScript files have the file extension .js and name of the JavaScript
file usually put in the src (source) attribute of a <script> tag).

Check JavaScript code for any sensitive information leaks which could be used by attackers to further abuse or
manipulate the system. Look for values such as: API keys, internal IP addresses, sensitive routes, or credentials. For
example:

const myS3Credentials = {
accessKeyId: config('AWSS3AccessKeyID'),
secretAcccessKey: config('AWSS3SecretAccessKey'),
};

The tester may even find something like this:

var conString = "tcp://postgres:1234@localhost/postgres";

When an API Key is found, testers can check if the API Key restrictions are set per service or by IP, HTTP referrer,
application, SDK, etc.
For example, if testers found a Google Map API Key, they can check if this API Key is restricted by IP or restricted only
per the Google Map APIs. If the Google API Key is restricted only per the Google Map APIs, attackers can still use that
API Key to query unrestricted Google Map APIs and the application owner must to pay for that.

<script type="application/json">
...
{"GOOGLE_MAP_API_KEY":"AIzaSyDUEBnKgwiqMNpDplT6ozE4Z0XxuAbqDi4",
"RECAPTCHA_KEY":"6LcPscEUiAAAAHOwwM3fGvIx9rsPYUq62uRhGjJ0"}
...
</script>

In some cases, testers may find sensitive routes from JavaScript code, such as links to internal or hidden admin pages.

<script type="application/json">
...
"runtimeConfig":{"BASE_URL_VOUCHER_API":"https://staging-voucher.victim.net/api",
"BASE_BACKOFFICE_API":"https://10.10.10.2/api", "ADMIN_PAGE":"/hidden_administrator"}
...
</script>

Identifying Source Map Files
Source map files will usually be loaded when DevTools open. Testers can also find source map files by adding the
".map" extension after the extension of each external JavaScript file. For example, if a tester sees a
/static/js/main.chunk.js

file,

they

can

then

check

for

its

source

map

file

by

visiting

/static/js/main.chunk.js.map .

Black-Box Testing
Check source map files for any sensitive information that can help the attacker gain more insight about the application.
For example:

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

When websites load source map files, the front-end source code will become readable and easier to debug.

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
Enumerating the application and its attack surface is a key precursor before any thorough testing can be undertaken,
as it allows the tester to identify likely areas of weakness. This section aims to help identify and map out areas within
the application that should be investigated once enumeration and mapping have been completed.

Test Objectives
Identify possible entry and injection points through request and response analysis.

How to Test
Before any testing begins, the tester should always get a good understanding of the application and how the user and
browser communicates with it. As the tester walks through the application, they should pay attention to all HTTP
requests as well as every parameter and form field that is passed to the application. They should pay special attention
to when GET requests are used and when POST requests are used to pass parameters to the application. In addition,
they also need to pay attention to when other methods for RESTful services are used.
Note that in order to see the parameters sent in the body of requests such as a POST request, the tester may want to
use a tool such as an intercepting proxy (See tools). Within the POST request, the tester should also make special note
of any hidden form fields that are being passed to the application, as these usually contain sensitive information, such
as state information, quantity of items, the price of items, that the developer never intended for anyone to see or
change.
In the author's experience, it has been very useful to use an intercepting proxy and a spreadsheet for this stage of
testing. The proxy will keep track of every request and response between the tester and the application as they explore
it. Additionally, at this point, testers usually trap every request and response so that they can see exactly every header,
parameter, etc. that is being passed to the application and what is being returned. This can be quite tedious at times,
especially on large interactive sites (think of a banking application). However, experience will show what to look for and
this phase can be significantly reduced.
As the tester walks through the application, they should take note of any interesting parameters in the URL, custom
headers, or body of the requests/responses, and save them in a spreadsheet. The spreadsheet should include the
page requested (it might be good to also add the request number from the proxy, for future reference), the interesting
parameters, the type of request (GET, POST, etc), if access is authenticated/unauthenticated, if TLS is used, if it's part of
a multi-step process, if WebSockers are used, and any other relevant notes. Once they have every area of the
application mapped out, then they can go through the application and test each of the areas that they have identified
and make notes for what worked and what didn't work. The rest of this guide will identify how to test each of these areas
of interest, but this section must be undertaken before any of the actual testing can commence.
Below are some points of interests for all requests and responses. Within the requests section, focus on the GET and
POST methods, as these appear the majority of the requests. Note that other methods, such as PUT and DELETE, can
be used. Often, these more rare requests, if allowed, can expose vulnerabilities. There is a special section in this guide
dedicated for testing these HTTP methods.

Requests
Identify where GETs are used and where POSTs are used.

Identify all parameters used in a POST request (these are in the body of the request).
Within the POST request, pay special attention to any hidden parameters. When a POST is sent all the form fields
(including hidden parameters) will be sent in the body of the HTTP message to the application. These typically
aren't seen unless a proxy or view the HTML source code is used. In addition, the next page shown, its data, and
the level of access can all be different depending on the value of the hidden parameter(s).
Identify all parameters used in a GET request (i.e., URL), in particular the query string (usually after a ? mark).
Identify all the parameters of the query string. These usually are in a pair format, such as foo=bar . Also note that
many parameters can be in one query string such as separated by a & , \~ , : , or any other special character or
encoding.
A special note when it comes to identifying multiple parameters in one string or within a POST request is that some
or all of the parameters will be needed to execute the attacks. The tester needs to identify all of the parameters
(even if encoded or encrypted) and identify which ones are processed by the application. Later sections of the
guide will identify how to test these parameters. At this point, just make sure each one of them is identified.
Also pay attention to any additional or custom type headers not typically seen (such as debug: false ).

Responses
Identify where new cookies are set ( Set-Cookie header), modified, or added to.
Identify where there are any redirects (3xx HTTP status code), 400 status codes, in particular 403 Forbidden, and
500 internal server errors during normal responses (i.e., unmodified requests).
Also note where any interesting headers are used. For example, Server: BIG-IP indicates that the site is load
balanced. Thus, if a site is load balanced and one server is incorrectly configured, then the tester might have to
make multiple requests to access the vulnerable server, depending on the type of load balancing used.

Black-Box Testing
Testing for Application Entry Points
The following are two examples on how to check for application entry points.
Example 1
This example shows a GET request that would purchase an item from an online shopping application.

GET /shoppingApp/buyme.asp?CUSTOMERID=100&ITEM=z101a&PRICE=62.50&IP=x.x.x.x HTTP/1.1
Host: x.x.x.x
Cookie: SESSIONID=Z29vZCBqb2IgcGFkYXdhIG15IHVzZXJuYW1lIGlzIGZvbyBhbmQgcGFzc3dvcmQgaXMgYmFy

Here the tester would note all the parameters of the request such as CUSTOMERID, ITEM, PRICE, IP, and the
Cookie (which could just be encoded parameters or used for session state).
Example 2
This example shows a POST request that would log you into an application.

POST /KevinNotSoGoodApp/authenticate.asp?service=login HTTP/1.1
Host: x.x.x.x
Cookie: SESSIONID=dGhpcyBpcyBhIGJhZCBhcHAgdGhhdCBzZXRzIHByZWRpY3RhYmxlIGNvb2tpZXMgYW5kIG1pbmUgaXMgMT
IzNA==;CustomCookie=00my00trusted00ip00is00x.x.x.x00
user=admin&pass=pass123&debug=true&fromtrustIP=true

In this example the tester would note all the parameters as they have before, however the majority of the
parameters are passed in the body of the request and not in the URL. Additionally, note that there is a custom
HTTP header ( CustomCookie ) being used.

Gray-Box Testing

Testing for application entry points via a gray-box methodology would consist of everything already identified above
with one addition. In cases where there are external sources from which the application receives data and processes it
(such as SNMP traps, syslog messages, SMTP, or SOAP messages from other servers) a meeting with the application
developers could identify any functions that would accept or expect user input and how they are formatted. For
example, the developer could help in understanding how to formulate a correct SOAP request that the application
would accept and where the web service resides (if the web service or any other function hasn't already been identified
during the black-box testing).
OWASP Attack Surface Detector
The Attack Surface Detector (ASD) tool investigates the source code and uncovers the endpoints of a web application,
the parameters these endpoints accept, and the data type of those parameters. This includes the unlinked endpoints a
spider will not be able to find, or optional parameters totally unused in client-side code. It also has the capability to
calculate the changes in attack surface between two versions of an application.
The Attack Surface Detector is available as a plugin to both ZAP and Burp Suite, and a command-line tool is also
available. The command-line tool exports the attack surface as a JSON output, which can then be used by the ZAP and
Burp Suite plugin. This is helpful for cases where the source code is not provided to the penetration tester directly. For
example, the penetration tester can get the json output file from a customer who does not want to provide the source
code itself.
How to Use

The CLI jar file is available for download from https://github.com/secdec/attack-surface-detector-cli/releases.
You can run the following command for ASD to identify endpoints from the source code of the target web application.
java -jar attack-surface-detector-cli-1.3.5.jar <source-code-path> [flags]

Here is an example of running the command against OWASP RailsGoat.

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

You can also generate a JSON output file using the -json flag, which can be used by the plugin to both ZAP and Burp
Suite. See the following links for more details.
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
Before commencing security testing, understanding the structure of the application is paramount. Without a thorough
understanding of the layout of the application, it is unlikely that it will be tested thoroughly.

Test Objectives
Map the target application and understand the principal workflows.

How to Test
In black-box testing it is extremely difficult to test the entire codebase. Not just because the tester has no view of the
code paths through the application, but even if they did, to test all code paths would be very time consuming. One way
to reconcile this is to document what code paths were discovered and tested.
There are several ways to approach the testing and measurement of code coverage:
Path - test each of the paths through an application that includes combinatorial and boundary value analysis
testing for each decision path. While this approach offers thoroughness, the number of testable paths grows
exponentially with each decision branch.
Data Flow (or Taint Analysis) - tests the assignment of variables via external interaction (normally users). Focuses
on mapping the flow, transformation and use of data throughout an application.
Race - tests multiple concurrent instances of the application manipulating the same data.
The trade off as to what method is used and to what degree each method is used should be negotiated with the
application owner. Simpler approaches could also be adopted, including asking the application owner what functions
or code sections they are particularly concerned about and how those code segments can be reached.
To demonstrate code coverage to the application owner, the tester can start with a spreadsheet and document all the
links discovered by spidering the application (either manually or automatically). Then the tester can look more closely
at decision points in the application and investigate how many significant code paths are discovered. These should
then be documented in the spreadsheet with URLs, prose and screenshot descriptions of the paths discovered.

Code Review
Ensuring sufficient code coverage for the application owner is far easier with gray-box and white-box approach to
testing. Information solicited by and provided to the tester will ensure the minimum requirements for code coverage are
met.
Many modern Dynamic Application Security Testing (DAST) tools facilitate the use of a web server agent or could be
paired with a third-party agent to monitor web application coverage specifics.

Automatic Spidering
The automatic spider is a tool used to automatically discover new resources (URLs) on a particular website. It begins
with a list of URLs to visit, called the seeds, which depends on how the Spider is started. While there are a lot of
Spidering tools, the following example uses the Zed Attack Proxy (ZAP):

Figure 4.1.7-1: Zed Attack Proxy Screen

ZAP offers various automatic spidering options, which can leveraged based on the tester's needs:
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
There is nothing new under the sun, and nearly every web application that one may think of developing has already
been developed. With the vast number of free and Open Source software projects that are actively developed and
deployed around the world, it is very likely that an application security test will face a target that is entirely or partly
dependent on these well known applications or frameworks (e.g. WordPress, phpBB, Mediawiki, etc). Knowing the web
application components that are being tested significantly helps in the testing process and will also drastically reduce
the effort required during the test. These well known web applications have known HTML headers, cookies, and
directory structures that can be enumerated to identify the application. Most of the web frameworks have several
markers in those locations which help an attacker or tester to recognize them. This is basically what all automatic tools
do, they look for a marker from a predefined location and then compare it to the database of known signatures. For
better accuracy several markers are usually used.

Test Objectives
Fingerprint the components being used by the web applications.

How to Test
Black-Box Testing
There are several common locations to consider in order to identify frameworks or components:
HTTP headers
Cookies
HTML source code
Specific files and folders
File extensions
Error messages
HTTP Headers
The most basic form of identifying a web framework is to look at the X-Powered-By field in the HTTP response header.
Many tools can be used to fingerprint a target, the simplest one is netcat.
Consider the following HTTP Request-Response:

$ nc 127.0.0.1 80
HEAD / HTTP/1.0
HTTP/1.1 200 OK
Server: nginx/1.0.14
[...]
X-Powered-By: Mono

From the X-Powered-By field, we understand that the web application framework is likely to be Mono . However,
although this approach is simple and quick, this methodology doesn't work in 100% of cases. It is possible to easily
disable X-Powered-By header by a proper configuration. There are also several techniques that allow a web site to

obfuscate HTTP headers (see an example in the Remediation section). In the example above we can also note a
specific version of nginx is being used to serve the content.
So in the same example the tester could either miss the X-Powered-By header or obtain an answer like the following:

HTTP/1.1 200 OK
Server: nginx/1.0.14
Date: Sat, 07 Sep 2013 08:19:15 GMT
Content-Type: text/html;charset=ISO-8859-1
Connection: close
Vary: Accept-Encoding
X-Powered-By: Blood, sweat and tears

Sometimes there are more HTTP-headers that point at a certain framework. In the following example, according to the
information from HTTP-request, one can see that X-Powered-By header contains PHP version. However, the XGenerator header points out the used framework is actually Swiftlet , which helps a penetration tester to expand
their attack vectors. When performing fingerprinting, carefully inspect every HTTP-header for such leaks.

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
Another similar and somewhat more reliable way to determine the current web framework are framework-specific
cookies.
Consider the following HTTP-request:

Figure 4.1.8-7: Cakephp HTTP Request

The cookie CAKEPHP has automatically been set, which gives information about the framework being used. A list of
common cookie names is presented in Cookies section. Limitations still exist in relying on this identification mechanism
- it is possible to change the name of cookies. For example, for the selected CakePHP framework this could be done via
the following configuration (excerpt from core.php ):

/**
* The name of CakePHP's session cookie.
*
* Note the guidelines for Session names states: "The session name references
* the session id in cookies and URLs. It should contain only alphanumeric
* characters."
* @link http://php.net/session_name

*/
Configure::write('Session.cookie', 'CAKEPHP');

However, these changes are less likely to be made than changes to the X-Powered-By header, so this approach to
identification can be considered as more reliable.
HTML Source Code
This technique is based on finding certain patterns in the HTML page source code. Often one can find a lot of
information which helps a tester to recognize a specific component. One of the common markers are HTML comments
that directly lead to framework disclosure. More often certain framework-specific paths can be found, i.e. links to
framework-specific CSS or JS folders. Finally, specific script variables might also point to a certain framework.
From the screenshot below one can easily learn the used framework and its version by the mentioned markers. The
comment, specific paths and script variables can all help an attacker to quickly determine an instance of ZK framework.

Figure 4.1.8-2: ZK Framework HTML Source Sample

Frequently such information is positioned in the <head> section of HTTP responses, in <meta> tags, or at the end of
the page. Nevertheless, entire responses should be analyzed since it can be useful for other purposes such as
inspection of other useful comments and hidden fields. Sometimes, web developers do not care much about hiding
information about the frameworks or components used. It is still possible to stumble upon something like this at the
bottom of the page:

Figure 4.1.8-3: Banshee Bottom Page

Specific Files and Folders
There is another approach which greatly helps an attacker or tester to identify applications or components with high
accuracy. Every web component has its own specific file and folder structure on the server. It has been noted that one
can see the specific path from the HTML page source but sometimes they are not explicitly presented there and still
reside on the server.
In order to uncover them a technique known as forced browsing or "dirbusting" is used. Dirbusting is brute forcing a
target with known folder and filenames and monitoring HTTP-responses to enumerate server content. This information
can be used both for finding default files and attacking them, and for fingerprinting the web application. Dirbusting can
be done in several ways, the example below shows a successful dirbusting attack against a WordPress-powered target
with the help of defined list and intruder functionality of Burp Suite.

Figure 4.1.8-4: Dirbusting with Burp

We can see that for some WordPress-specific folders (for instance, /wp-includes/ , /wp-admin/ and /wp-content/ )
HTTP responses are 403 (Forbidden), 302 (Found, redirection to wp-login.php ), and 200 (OK) respectively. This is a

good indicator that the target is WordPress powered. The same way it is possible to dirbust different application plugin
folders and their versions. In the screenshot below one can see a typical CHANGELOG file of a Drupal plugin, which
provides information on the application being used and discloses a vulnerable plugin version.

Figure 4.1.8-5: Drupal Botcha Disclosure

Tip: before starting with dirbusting, check the robots.txt file first. Sometimes application specific folders and other
sensitive information can be found there as well. An example of such a robots.txt file is presented on a screenshot
below.

Figure 4.1.8-6: Robots Info Disclosure

Specific files and folders are different for each specific application. If the identified application or component is Open
Source there may be value in setting up a temporary installation during penetration tests in order to gain a better
understanding of what infrastructure or functionality is presented, and what files might be left on the server. However,
several good file lists already exist; one good example is FuzzDB wordlists of predictable files/folders.
File Extensions
URLs may include file extensions, which can also help to identify the web platform or technology.
For example, the OWASP wiki used PHP:

https://wiki.owasp.org/index.php?title=Fingerprint_Web_Application_Framework&action=edit&section=4

Here are some common web file extensions and associated technologies:
.php - PHP
.aspx - Microsoft ASP.NET
.jsp - Java Server Pages

Error Messages
As can be seen in the following screenshot the listed file system path points to use of WordPress ( wp-content ). Also
testers should be aware that WordPress is PHP based ( functions.php ).

Figure 4.1.8-7: WordPress Parse Error

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
While efforts can be made to use different cookie names (through changing configs), hiding or changing file/directory
paths (through rewriting or source code changes), removing known headers, etc. such efforts boil down to "security
through obscurity". System owners/admins should recognize that those efforts only slow down the most basic of
adversaries. The time/effort may be better used on stakeholder awareness and solution maintenance activities.

Tools
A list of general and well-known tools is presented below. There are also a lot of other utilities, as well as frameworkbased fingerprinting tools.

WhatWeb
Website: https://github.com/urbanadventurer/WhatWeb
Currently one of the best fingerprinting tools on the market. Included in a default Kali Linux build. Language: Ruby
Matches for fingerprinting are made with:
Text strings (case sensitive)
Regular expressions
Google Hack Database queries (limited set of keywords)
MD5 hashes
URL recognition

HTML tag patterns
Custom ruby code for passive and aggressive operations
Sample output is presented on a screenshot below:

Figure 4.1.8-8: Whatweb Output sample

Wappalyzer
Website: https://www.wappalyzer.com/
Wapplyzer is available in multiple usage models, the most popular of which is likely the Firefox/Chrome extensions.
They work only on regular expression matching and doesn't need anything other than the page to be loaded in
browser. It works completely at the browser level and gives results in the form of icons. Although sometimes it has false
positives, this is very handy to have notion of what technologies were used to construct a target website immediately
after browsing a page.
Sample output of a plug-in is presented on a screenshot below.

Figure 4.1.8-9: Wappalyzer Output for OWASP Website

References
Whitepapers
Saumil Shah: "An Introduction to HTTP fingerprinting"
Anant Shrivastava : "Web Application Finger Printing"

---

## WSTG-INFO-09

**Fingerprint Web Application**

This content has been merged into: Fingerprint Web Application Framework.

---

## WSTG-INFO-10

**Map Application Architecture**

Summary
The complexity of interconnected and heterogeneous web infrastructure can include hundreds of web applications and
makes configuration management and review a fundamental step in testing and deploying every single application. In
fact it takes only a single vulnerability to undermine the security of the entire infrastructure, and even small and
seemingly unimportant problems may evolve into severe risks for another application in the same infrastructure.
To address these problems, it is of utmost importance to perform an in-depth review of configuration and known security
issues. Before performing an in-depth review it is necessary to map the network and application architecture. The
different elements that make up the infrastructure need to be determined to understand how they interact with a web
application and how they affect security.

Test Objectives
Generate a map of the application at hand based on the research conducted.

How to Test
Map the Application Architecture
The application architecture needs to be mapped through some test to determine what different components are used
to build the web application. In small setups, such as a simple PHP application, a single server might be used that
serves the PHP application, and perhaps also the authentication mechanism.
On more complex setups, such as an online bank system, multiple servers might be involved. These may include a
reverse proxy, a front-end web server, an application server, and a database server or LDAP server. Each of these
servers will be used for different purposes and might even be segregated in different networks with firewalls between
them. This creates different network zones so that access to the web server will not necessarily grant a remote user
access to the authentication mechanism itself, and so that compromises of the different elements of the architecture can
be isolated so that they will not compromise the whole architecture.
Getting knowledge of the application architecture can be easy if this information is provided to the testing team by the
application developers in document form or through interviews, but can also prove to be very difficult if doing a blind
penetration test.
In the latter case, a tester will first start with the assumption that there is a simple setup (a single server). Then they will
retrieve information from other tests and derive the different elements, question this assumption, and extend the
architecture map. The tester will start by asking simple questions such as: "Is there a firewall protecting the web
server?". This question will be answered based on the results of network scans targeted at the web server and the
analysis of whether the network ports of the web server are being filtered in the network edge (no answer or ICMP
unreachables are received) or if the server is directly connected to the Internet (i.e. returns RST packets for all nonlistening ports). This analysis can be enhanced to determine the type of firewall used based on network packet tests. Is
it a stateful firewall or is it an access list filter on a router? How is it configured? Can it be bypassed? Is it a full fledged
web application firewall?
Detecting a reverse proxy in front of the web server can be done by analysis of the web server banner, which might
directly disclose the existence of a reverse proxy. It can also be determined by obtaining the answers given by the web
server to requests and comparing them to the expected answers. For example, some reverse proxies act as Intrusion

Prevention Systems (IPS) by blocking known attacks targeted at the web server. If the web server is known to answer
with a 404 message to a request that targets an unavailable page and returns a different error message for some
common web attacks like those done by vulnerability scanners, it might be an indication of a reverse proxy (or an
application-level firewall) which is filtering the requests and returning a different error page than the one expected.
Another example: if the web server returns a set of available HTTP methods (including TRACE) but the expected
methods return errors then there is probably something in between blocking them.
In some cases, even the protection system gives itself away. Here's an example of mod_security self identifying:

Figure 4.1.10-1: Example mod_security Error Page

Reverse proxies can also be introduced as proxy-caches to accelerate the performance of back-end application
servers. Detecting these proxies can be done based on the server header. They can also be detected by timing
requests that should be cached by the server and comparing the time taken to server the first request with subsequent
requests.
Another element that can be detected is network load balancers. Typically, these systems will balance a given TCP/IP
port to multiple servers based on different algorithms (round-robin, web server load, number of requests, etc.). Thus, the
detection of this architecture element needs to be done by examining multiple requests and comparing results to
determine if the requests are going to the same or different web servers. For example, based on the Date header if the
server clocks are not synchronized. In some cases, the network load balance process might inject new information in
the headers that will make it stand out distinctly, like the BIGipServer prefixed cookie introduced by F5 BIG-IP load
balancers.
Application web servers are usually easy to detect. The request for several resources is handled by the application
server itself (not the web server) and the response header will vary significantly (including different or additional values
in the answer header). Another way to detect these is to see if the web server tries to set cookies which are indicative of
an application web server being used (such as the JSESSIONID provided by various J2EE servers), or to rewrite URLs
automatically to do session tracking.
Authentication back ends (such as LDAP directories, relational databases, or RADIUS servers) however, are not as
easy to detect from an external point of view in an immediate way, since they will be hidden by the application itself.
The use of a back end database can be determined simply by navigating an application. If there is highly dynamic
content generated "on the fly" it is probably being extracted from some sort of database by the application itself.
Sometimes the way information is requested might give insight to the existence of a database back end. For example,
an online shopping application that uses numeric identifiers ( id ) when browsing the different articles in the shop.
However, when doing a blind application test, knowledge of the underlying database is usually only available when a
vulnerability surfaces in the application, such as poor exception handling or susceptibility to SQL injection.

4.2 Configuration and Deployment Management Testing
4.2.1 Test Network Infrastructure Configuration
4.2.2 Test Application Platform Configuration
4.2.3 Test File Extensions Handling for Sensitive Information
4.2.4 Review Old Backup and Unreferenced Files for Sensitive Information
4.2.5 Enumerate Infrastructure and Application Admin Interfaces
4.2.6 Test HTTP Methods
4.2.7 Test HTTP Strict Transport Security
4.2.8 Test RIA Cross Domain Policy
4.2.9 Test File Permission
4.2.10 Test for Subdomain Takeover
4.2.11 Test Cloud Storage

---

