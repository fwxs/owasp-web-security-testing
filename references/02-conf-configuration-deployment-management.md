# WSTG CONF — Configuration & Deployment Management

OWASP Web Security Testing Guide v4.2. 11 test cases: WSTG-CONF-01, WSTG-CONF-02, WSTG-CONF-03, WSTG-CONF-04, WSTG-CONF-05, WSTG-CONF-06, WSTG-CONF-07, WSTG-CONF-08, WSTG-CONF-09, WSTG-CONF-10, WSTG-CONF-11.

## Table of Contents

- [WSTG-CONF-01 — Test Network Infrastructure Configuration](#wstg-conf-01)
- [WSTG-CONF-02 — Test Application Platform Configuration](#wstg-conf-02)
- [WSTG-CONF-03 — Test File Extensions Handling for Sensitive Information](#wstg-conf-03)
- [WSTG-CONF-04 — Review Old Backup and Unreferenced Files for Sensitive Information](#wstg-conf-04)
- [WSTG-CONF-05 — Enumerate Infrastructure and Application Admin Interfaces](#wstg-conf-05)
- [WSTG-CONF-06 — Test HTTP Methods](#wstg-conf-06)
- [WSTG-CONF-07 — Test HTTP Strict Transport Security](#wstg-conf-07)
- [WSTG-CONF-08 — Test RIA Cross Domain Policy](#wstg-conf-08)
- [WSTG-CONF-09 — Test File Permission](#wstg-conf-09)
- [WSTG-CONF-10 — Test for Subdomain Takeover](#wstg-conf-10)
- [WSTG-CONF-11 — Test Cloud Storage](#wstg-conf-11)

---

## WSTG-CONF-01

**Test Network Infrastructure Configuration**

Summary
The intrinsic complexity of interconnected and heterogeneous web server infrastructure, which can include hundreds of
web applications, makes configuration management and review a fundamental step in testing and deploying every
single application. It takes only a single vulnerability to undermine the security of the entire infrastructure, and even
small and seemingly unimportant problems may evolve into severe risks for another application on the same server. In
order to address these problems, it is of utmost importance to perform an in-depth review of configuration and known
security issues, after having mapped the entire architecture.
Proper configuration management of the web server infrastructure is very important in order to preserve the security of
the application itself. If elements such as the web server software, the back-end database servers, or the authentication
servers are not properly reviewed and secured, they might introduce undesired risks or introduce new vulnerabilities
that might compromise the application itself.
For example, a web server vulnerability that would allow a remote attacker to disclose the source code of the
application itself (a vulnerability that has arisen a number of times in both web servers or application servers) could
compromise the application, as anonymous users could use the information disclosed in the source code to leverage
attacks against the application or its users.
The following steps need to be taken to test the configuration management infrastructure:
The different elements that make up the infrastructure need to be determined in order to understand how they
interact with a web application and how they affect its security.
All the elements of the infrastructure need to be reviewed in order to make sure that they don't contain any known
vulnerabilities.
A review needs to be made of the administrative tools used to maintain all the different elements.
The authentication systems, need to reviewed in order to assure that they serve the needs of the application and
that they cannot be manipulated by external users to leverage access.
A list of defined ports which are required for the application should be maintained and kept under change control.
After having mapped the different elements that make up the infrastructure (see Map Network and Application
Architecture) it is possible to review the configuration of each element founded and test for any known vulnerabilities.

Test Objectives
Review the applications' configurations set across the network and validate that they are not vulnerable.
Validate that used frameworks and systems are secure and not susceptible to known vulnerabilities due to
unmaintained software or default settings and credentials.

How to Test
Known Server Vulnerabilities
Vulnerabilities found in the different areas of the application architecture, be it in the web server or in the back end
database, can severely compromise the application itself. For example, consider a server vulnerability that allows a
remote, unauthenticated user to upload files to the web server or even to replace files. This vulnerability could
compromise the application, since a rogue user may be able to replace the application itself or introduce code that
would affect the back end servers, as its application code would be run just like any other application.

Reviewing server vulnerabilities can be hard to do if the test needs to be done through a blind penetration test. In these
cases, vulnerabilities need to be tested from a remote site, typically using an automated tool. However, testing for some
vulnerabilities can have unpredictable results on the web server, and testing for others (like those directly involved in
denial of service attacks) might not be possible due to the service downtime involved if the test was successful.
Some automated tools will flag vulnerabilities based on the web server version retrieved. This leads to both false
positives and false negatives. On one hand, if the web server version has been removed or obscured by the local site
administrator the scan tool will not flag the server as vulnerable even if it is. On the other hand, if the vendor providing
the software does not update the web server version when vulnerabilities are fixed, the scan tool will flag vulnerabilities
that do not exist. The latter case is actually very common as some operating system vendors back port patches of
security vulnerabilities to the software they provide in the operating system, but do not do a full upload to the latest
software version. This happens in most GNU/Linux distributions such as Debian, Red Hat or SuSE. In most cases,
vulnerability scanning of an application architecture will only find vulnerabilities associated with the "exposed"
elements of the architecture (such as the web server) and will usually be unable to find vulnerabilities associated to
elements which are not directly exposed, such as the authentication back ends, the back end database, or reverse
proxies in use.
Finally, not all software vendors disclose vulnerabilities in a public way, and therefore these weaknesses do not
become registered within publicly known vulnerability databases [2]. This information is only disclosed to customers or
published through fixes that do not have accompanying advisories. This reduces the usefulness of vulnerability
scanning tools. Typically, vulnerability coverage of these tools will be very good for common products (such as the
Apache web server, Microsoft's Internet Information Server, or IBM's Lotus Domino) but will be lacking for lesser known
products.
This is why reviewing vulnerabilities is best done when the tester is provided with internal information of the software
used, including versions and releases used and patches applied to the software. With this information, the tester can
retrieve the information from the vendor itself and analyze what vulnerabilities might be present in the architecture and
how they can affect the application itself. When possible, these vulnerabilities can be tested to determine their real
effects and to detect if there might be any external elements (such as intrusion detection or prevention systems) that
might reduce or negate the possibility of successful exploitation. Testers might even determine, through a configuration
review, that the vulnerability is not even present, since it affects a software component that is not in use.
It is also worthwhile to note that vendors will sometimes silently fix vulnerabilities and make the fixes available with new
software releases. Different vendors will have different release cycles that determine the support they might provide for
older releases. A tester with detailed information of the software versions used by the architecture can analyse the risk
associated to the use of old software releases that might be unsupported in the short term or are already unsupported.
This is critical, since if a vulnerability were to surface in an old software version that is no longer supported, the systems
personnel might not be directly aware of it. No patches will be ever made available for it and advisories might not list
that version as vulnerable as it is no longer supported. Even in the event that they are aware that the vulnerability is
present and the system is vulnerable, they will need to do a full upgrade to a new software release, which might
introduce significant downtime in the application architecture or might force the application to be re-coded due to
incompatibilities with the latest software version.

Administrative Tools
Any web server infrastructure requires the existence of administrative tools to maintain and update the information used
by the application. This information includes static content (web pages, graphic files), application source code, user
authentication databases, etc. Administrative tools will differ depending on the site, technology, or software used. For
example, some web servers will be managed using administrative interfaces which are, themselves, web servers (such
as the iPlanet web server) or will be administrated by plain text configuration files (in the Apache case [3]) or use
operating-system GUI tools (when using Microsoft's IIS server or ASP.Net).
In most cases the server configuration will be handled using different file maintenance tools used by the web server,
which are managed through FTP servers, WebDAV, network file systems (NFS, CIFS) or other mechanisms. Obviously,
the operating system of the elements that make up the application architecture will also be managed using other tools.

Applications may also have administrative interfaces embedded in them that are used to manage the application data
itself (users, content, etc.).
After having mapped the administrative interfaces used to manage the different parts of the architecture it is important to
review them since if an attacker gains access to any of them he can then compromise or damage the application
architecture. To do this it is important to:
Determine the mechanisms that control access to these interfaces and their associated susceptibilities. This
information may be available online.
Change the default username and password.
Some companies choose not to manage all aspects of their web server applications, but may have other parties
managing the content delivered by the web application. This external company might either provide only parts of the
content (news updates or promotions) or might manage the web server completely (including content and code). It is
common to find administrative interfaces available from the Internet in these situations, since using the Internet is
cheaper than providing a dedicated line that will connect the external company to the application infrastructure through
a management-only interface. In this situation, it is very important to test if the administrative interfaces can be
vulnerable to attacks.

References
[1] WebSEAL, also known as Tivoli Authentication Manager, is a reverse proxy from IBM which is part of the Tivoli
framework.
[2] Such as Symantec's Bugtraq, ISS' X-Force, or NIST's National Vulnerability Database (NVD).
[3] There are some GUI-based administration tools for Apache (like NetLoony) but they are not in widespread use
yet.

---

## WSTG-CONF-02

**Test Application Platform Configuration**

Summary
Proper configuration of the single elements that make up an application architecture is important in order to prevent
mistakes that might compromise the security of the whole architecture.
Configuration review and testing is a critical task in creating and maintaining an architecture. This is because many
different systems will be usually provided with generic configurations that might not be suited to the task they will
perform on the specific site they're installed on.
While the typical web and application server installation will contain a lot of functionality (like application examples,
documentation, test pages) what is not essential should be removed before deployment to avoid post-install
exploitation.

Test Objectives
Ensure that defaults and known files have been removed.
Validate that no debugging code or extensions are left in the production environments.
Review the logging mechanisms set in place for the application.

How to Test
Black-Box Testing
Sample and Known Files and Directories
Many web servers and application servers provide, in a default installation, sample applications and files for the benefit
of the developer and in order to test that the server is working properly right after installation. However, many default
web server applications have been later known to be vulnerable. This was the case, for example, for CVE-1999-0449
(Denial of Service in IIS when the Exair sample site had been installed), CAN-2002-1744 (Directory traversal
vulnerability in CodeBrws.asp in Microsoft IIS 5.0), CAN-2002-1630 (Use of sendmail.jsp in Oracle 9iAS), or CAN2003-1172 (Directory traversal in the view-source sample in Apache's Cocoon).
CGI scanners include a detailed list of known files and directory samples that are provided by different web or
application servers and might be a fast way to determine if these files are present. However, the only way to be really
sure is to do a full review of the contents of the web server or application server and determine of whether they are
related to the application itself or not.
Comment Review
It is very common for programmers to add comments when developing large web-based applications. However,
comments included inline in HTML code might reveal internal information that should not be available to an attacker.
Sometimes, even source code is commented out since a functionality is no longer required, but this comment is leaked
out to the HTML pages returned to the users unintentionally.
Comment review should be done in order to determine if any information is being leaked through comments. This
review can only be thoroughly done through an analysis of the web server static and dynamic content and through file
searches. It can be useful to browse the site either in an automatic or guided fashion and store all the content retrieved.
This retrieved content can then be searched in order to analyse any HTML comments available in the code.
System Configuration

Various tools, documents, or checklists can be used to give IT and security professionals a detailed assessment of
target systems' conformance to various configuration baselines or benchmarks. Such tools include (but are not limited
to):
CIS-CAT Lite
Microsoft's Attack Surface Analyzer
NIST's National Checklist Program

Gray-Box Testing
Configuration Review
The web server or application server configuration takes an important role in protecting the contents of the site and it
must be carefully reviewed in order to spot common configuration mistakes. Obviously, the recommended configuration
varies depending on the site policy, and the functionality that should be provided by the server software. In most cases,
however, configuration guidelines (either provided by the software vendor or external parties) should be followed to
determine if the server has been properly secured.
It is impossible to generically say how a server should be configured, however, some common guidelines should be
taken into account:
Only enable server modules (ISAPI extensions in the case of IIS) that are needed for the application. This reduces
the attack surface since the server is reduced in size and complexity as software modules are disabled. It also
prevents vulnerabilities that might appear in the vendor software from affecting the site if they are only present in
modules that have been already disabled.
Handle server errors (40x or 50x) with custom-made pages instead of with the default web server pages.
Specifically make sure that any application errors will not be returned to the end user and that no code is leaked
through these errors since it will help an attacker. It is actually very common to forget this point since developers do
need this information in pre-production environments.
Make sure that the server software runs with minimized privileges in the operating system. This prevents an error in
the server software from directly compromising the whole system, although an attacker could elevate privileges
once running code as the web server.
Make sure the server software properly logs both legitimate access and errors.
Make sure that the server is configured to properly handle overloads and prevent Denial of Service attacks. Ensure
that the server has been performance-tuned properly.
Never grant non-administrative identities (with the exception of NT SERVICE\WMSvc ) access to
applicationHost.config, redirection.config, and administration.config (either Read or Write access). This includes
Network Service , IIS_IUSRS , IUSR , or any custom identity used by IIS application pools. IIS worker processes
are not meant to access any of these files directly.
Never share out applicationHost.config, redirection.config, and administration.config on the network. When using
Shared Configuration, prefer to export applicationHost.config to another location (see the section titled "Setting
Permissions for Shared Configuration).
Keep in mind that all users can read .NET Framework machine.config and root web.config files by default. Do
not store sensitive information in these files if it should be for administrator eyes only.
Encrypt sensitive information that should be read by the IIS worker processes only and not by other users on the
machine.
Do not grant Write access to the identity that the Web server uses to access the shared applicationHost.config .
This identity should have only Read access.
Use a separate identity to publish applicationHost.config to the share. Do not use this identity for configuring
access to the shared configuration on the Web servers.
Use a strong password when exporting the encryption keys for use with shared -configuration.
Maintain restricted access to the share containing the shared configuration and encryption keys. If this share is
compromised, an attacker will be able to read and write any IIS configuration for your Web servers, redirect traffic

from your Web site to malicious sources, and in some cases gain control of all web servers by loading arbitrary
code into IIS worker processes.
Consider protecting this share with firewall rules and IPsec policies to allow only the member web servers to
connect.
Logging
Logging is an important asset of the security of an application architecture, since it can be used to detect flaws in
applications (users constantly trying to retrieve a file that does not really exist) as well as sustained attacks from rogue
users. Logs are typically properly generated by web and other server software. It is not common to find applications that
properly log their actions to a log and, when they do, the main intention of the application logs is to produce debugging
output that could be used by the programmer to analyze a particular error.
In both cases (server and application logs) several issues should be tested and analyzed based on the log contents:
1. Do the logs contain sensitive information?
2. Are the logs stored in a dedicated server?
3. Can log usage generate a Denial of Service condition?
4. How are they rotated? Are logs kept for the sufficient time?
5. How are logs reviewed? Can administrators use these reviews to detect targeted attacks?
6. How are log backups preserved?
7. Is the data being logged data validated (min/max length, chars etc) prior to being logged?
Sensitive Information in Logs

Some applications might, for example, use GET requests to forward form data which will be seen in the server logs.
This means that server logs might contain sensitive information (such as usernames as passwords, or bank account
details). This sensitive information can be misused by an attacker if they obtained the logs, for example, through
administrative interfaces or known web server vulnerabilities or misconfiguration (like the well-known server-status
misconfiguration in Apache-based HTTP servers).
Event logs will often contain data that is useful to an attacker (information leakage) or can be used directly in exploits:
Debug information
Stack traces
Usernames
System component names
Internal IP addresses
Less sensitive personal data (e.g. email addresses, postal addresses and telephone numbers associated with
named individuals)
Business data
Also, in some jurisdictions, storing some sensitive information in log files, such as personal data, might oblige the
enterprise to apply the data protection laws that they would apply to their back-end databases to log files too. And
failure to do so, even unknowingly, might carry penalties under the data protection laws that apply.
A wider list of sensitive information is:
Application source code
Session identification values
Access tokens
Sensitive personal data and some forms of personally identifiable information (PII)
Authentication passwords
Database connection strings

Encryption keys
Bank account or payment card holder data
Data of a higher security classification than the logging system is allowed to store
Commercially-sensitive information
Information it is illegal to collect in the relevant jurisdiction
Information a user has opted out of collection, or not consented to e.g. use of do not track, or where consent to
collect has expired
Log Location
Typically servers will generate local logs of their actions and errors, consuming the disk of the system the server is
running on. However, if the server is compromised its logs can be wiped out by the intruder to clean up all the traces of
its attack and methods. If this were to happen the system administrator would have no knowledge of how the attack
occurred or where the attack source was located. Actually, most attacker tool kits include a ''log zapper '' that is capable
of cleaning up any logs that hold given information (like the IP address of the attacker) and are routinely used in
attacker's system-level root kits.
Consequently, it is wiser to keep logs in a separate location and not in the web server itself. This also makes it easier to
aggregate logs from different sources that refer to the same application (such as those of a web server farm) and it also
makes it easier to do log analysis (which can be CPU intensive) without affecting the server itself.
Log Storage
Logs can introduce a Denial of Service condition if they are not properly stored. Any attacker with sufficient resources
could be able to produce a sufficient number of requests that would fill up the allocated space to log files, if they are not
specifically prevented from doing so. However, if the server is not properly configured, the log files will be stored in the
same disk partition as the one used for the operating system software or the application itself. This means that if the
disk were to be filled up the operating system or the application might fail because it is unable to write on disk.
Typically in UNIX systems logs will be located in /var (although some server installations might reside in /opt or
/usr/local) and it is important to make sure that the directories in which logs are stored are in a separate partition. In
some cases, and in order to prevent the system logs from being affected, the log directory of the server software itself
(such as /var/log/apache in the Apache web server) should be stored in a dedicated partition.
This is not to say that logs should be allowed to grow to fill up the file system they reside in. Growth of server logs
should be monitored in order to detect this condition since it may be indicative of an attack.
Testing this condition is as easy, and as dangerous in production environments, as firing off a sufficient and sustained
number of requests to see if these requests are logged and if there is a possibility to fill up the log partition through
these requests. In some environments where QUERY_STRING parameters are also logged regardless of whether they
are produced through GET or POST requests, big queries can be simulated that will fill up the logs faster since,
typically, a single request will cause only a small amount of data to be logged, such as date and time, source IP
address, URI request, and server result.
Log Rotation
Most servers (but few custom applications) will rotate logs in order to prevent them from filling up the file system they
reside on. The assumption when rotating logs is that the information in them is only necessary for a limited amount of
time.
This feature should be tested in order to ensure that:
Logs are kept for the time defined in the security policy, not more and not less.
Logs are compressed once rotated (this is a convenience, since it will mean that more logs will be stored for the
same available disk space).
File system permission of rotated log files are the same (or stricter) that those of the log files itself. For example,
web servers will need to write to the logs they use but they don't actually need to write to rotated logs, which means

that the permissions of the files can be changed upon rotation to prevent the web server process from modifying
these.
Some servers might rotate logs when they reach a given size. If this happens, it must be ensured that an attacker
cannot force logs to rotate in order to hide his tracks.
Log Access Control
Event log information should never be visible to end users. Even web administrators should not be able to see such
logs since it breaks separation of duty controls. Ensure that any access control schema that is used to protect access to
raw logs and any applications providing capabilities to view or search the logs is not linked with access control
schemas for other application user roles. Neither should any log data be viewable by unauthenticated users.
Log Review
Review of logs can be used for more than extraction of usage statistics of files in the web servers (which is typically
what most log-based application will focus on), but also to determine if attacks take place at the web server.
In order to analyze web server attacks the error log files of the server need to be analyzed. Review should concentrate
on:
40x (not found) error messages. A large amount of these from the same source might be indicative of a CGI
scanner tool being used against the web server
50x (server error) messages. These can be an indication of an attacker abusing parts of the application which fail
unexpectedly. For example, the first phases of a SQL injection attack will produce these error message when the
SQL query is not properly constructed and its execution fails on the back end database.
Log statistics or analysis should not be generated, nor stored, in the same server that produces the logs. Otherwise, an
attacker might, through a web server vulnerability or improper configuration, gain access to them and retrieve similar
information as would be disclosed by log files themselves.

References
Apache
Apache Security, by Ivan Ristic, O'reilly, March 2005.
Apache Security Secrets: Revealed (Again), Mark Cox, November 2003
Apache Security Secrets: Revealed, ApacheCon 2002, Las Vegas, Mark J Cox, October 2002
Performance Tuning
Lotus Domino
Lotus Security Handbook, William Tworek et al., April 2004, available in the IBM Redbooks collection
Lotus Domino Security, an X-force white-paper, Internet Security Systems, December 2002
Hackproofing Lotus Domino Web Server, David Litchfield, October 2001
Microsoft IIS
Security Best Practices for IIS 8
CIS Microsoft IIS Benchmarks
Securing Your Web Server (Patterns and Practices), Microsoft Corporation, January 2004
IIS Security and Programming Countermeasures, by Jason Coombs
From Blueprint to Fortress: A Guide to Securing IIS 5.0, by John Davis, Microsoft Corporation, June 2001
Secure Internet Information Services 5 Checklist, by Michael Howard, Microsoft Corporation, June 2000
Red Hat's (formerly Netscape's) iPlanet

Guide to the Secure Configuration and Administration of iPlanet Web Server, Enterprise Edition 4.1, by James
M Hayes, The Network Applications Team of the Systems and Network Attack Center (SNAC), NSA, January
WebSphere
IBM WebSphere V5.0 Security, WebSphere Handbook Series, by Peter Kovari et al., IBM, December 2002.
IBM WebSphere V4.0 Advanced Edition Security, by Peter Kovari et al., IBM, March 2002.
General
Logging Cheat Sheet, OWASP
SP 800-92 Guide to Computer Security Log Management, NIST
PCI DSS v3.2.1 Requirement 10 and PA-DSS v3.2 Requirement 4, PCI Security Standards Council
Generic:
CERT Security Improvement Modules: Securing Public Web Servers
How To: Use IISLockdown.exe

---

## WSTG-CONF-03

**Test File Extensions Handling for Sensitive Information**

Summary
File extensions are commonly used in web servers to easily determine which technologies, languages and plugins
must be used to fulfill the web request. While this behavior is consistent with RFCs and Web Standards, using standard
file extensions provides the penetration tester useful information about the underlying technologies used in a web
appliance and greatly simplifies the task of determining the attack scenario to be used on particular technologies. In
addition, mis-configuration of web servers could easily reveal confidential information about access credentials.
Extension checking is often used to validate files to be uploaded, which can lead to unexpected results because the
content is not what is expected, or because of unexpected OS filename handling.
Determining how web servers handle requests corresponding to files having different extensions may help in
understanding web server behavior depending on the kind of files that are accessed. For example, it can help to
understand which file extensions are returned as text or plain versus those that cause server-side execution. The latter
are indicative of technologies, languages or plugins that are used by web servers or application servers, and may
provide additional insight on how the web application is engineered. For example, a ".pl" extension is usually
associated with server-side Perl support. However, the file extension alone may be deceptive and not fully conclusive.
For example, Perl server-side resources might be renamed to conceal the fact that they are indeed Perl related. See
the next section on "web server components" for more on identifying server-side technologies and components.

Test Objectives
Dirbust sensitive file extensions, or extensions that might contain raw data (e.g. scripts, raw data, credentials, etc.).
Validate that no system framework bypasses exist on the rules set.

How to Test
Forced Browsing
Submit requests with different file extensions and verify how they are handled. The verification should be on a per web
directory basis. Verify directories that allow script execution. Web server directories can be identified by scanning tools
which look for the presence of well-known directories. In addition, mirroring the web site structure allows the tester to
reconstruct the tree of web directories served by the application.
If the web application architecture is load-balanced, it is important to assess all of the web servers. This may or may not
be easy, depending on the configuration of the balancing infrastructure. In an infrastructure with redundant components
there may be slight variations in the configuration of individual web or application servers. This may happen if the web
architecture employs heterogeneous technologies (think of a set of IIS and Apache web servers in a load-balancing
configuration, which may introduce slight asymmetric behavior between them, and possibly different vulnerabilities).
Example
The tester has identified the existence of a file named connection.inc . Trying to access it directly gives back its
contents, which are:

<?
mysql_connect("127.0.0.1", "root", "password")
or die("Could not connect");
?>

The tester determines the existence of a MySQL DBMS back end, and the (weak) credentials used by the web
application to access it.
The following file extensions should never be returned by a web server, since they are related to files which may
contain sensitive information or to files for which there is no reason to be served.
.asa
.inc
.config

The following file extensions are related to files which, when accessed, are either displayed or downloaded by the
browser. Therefore, files with these extensions must be checked to verify that they are indeed supposed to be served
(and are not leftovers), and that they do not contain sensitive information.
.zip , .tar , .gz , .tgz , .rar , etc.: (Compressed) archive files
.java : No reason to provide access to Java source files
.txt : Text files
.pdf : PDF documents
.docx , .rtf , .xlsx , .pptx , etc.: Office documents
.bak , .old and other extensions indicative of backup files (for example: ~ for Emacs backup files)

The list given above details only a few examples, since file extensions are too many to be comprehensively treated
here. Refer to FILExt for a more thorough database of extensions.
To identify files having a given extensions a mix of techniques can be employed. These techniques can include
Vulnerability Scanners, spidering and mirroring tools, manually inspecting the application (this overcomes limitations in
automatic spidering), querying search engines (see Testing: Spidering and googling). See also Testing for Old, Backup
and Unreferenced Files which deals with the security issues related to "forgotten" files.

File Upload
Windows 8.3 legacy file handling can sometimes be used to defeat file upload filters.
Usage Examples:
1. file.phtml gets processed as PHP code.
2. FILE~1.PHT is served, but not processed by the PHP ISAPI handler.
3. shell.phPWND can be uploaded.
4. SHELL~1.PHP will be expanded and returned by the OS shell, then processed by the PHP ISAPI handler.

Gray-Box Testing
Performing white-box testing against file extensions handling amounts to checking the configurations of web servers or
application servers taking part in the web application architecture, and verifying how they are instructed to serve
different file extensions.
If the web application relies on a load-balanced, heterogeneous infrastructure, determine whether this may introduce
different behavior.

Tools
Vulnerability scanners, such as Nessus and Nikto check for the existence of well-known web directories. They may
allow the tester to download the web site structure, which is helpful when trying to determine the configuration of web
directories and how individual file extensions are served. Other tools that can be used for this purpose include:

wget
curl
google for "web mirroring tools".

---

## WSTG-CONF-04

**Review Old Backup and Unreferenced Files for Sensitive Information**

Summary
While most of the files within a web server are directly handled by the server itself, it isn't uncommon to find
unreferenced or forgotten files that can be used to obtain important information about the infrastructure or the
credentials.
Most common scenarios include the presence of renamed old versions of modified files, inclusion files that are loaded
into the language of choice and can be downloaded as source, or even automatic or manual backups in form of
compressed archives. Backup files can also be generated automatically by the underlying file system the application is
hosted on, a feature usually referred to as "snapshots".
All these files may grant the tester access to inner workings, back doors, administrative interfaces, or even credentials
to connect to the administrative interface or the database server.
An important source of vulnerability lies in files which have nothing to do with the application, but are created as a
consequence of editing application files, or after creating on-the-fly backup copies, or by leaving in the web tree old
files or unreferenced files.Performing in-place editing or other administrative actions on production web servers may
inadvertently leave backup copies, either generated automatically by the editor while editing files, or by the
administrator who is zipping a set of files to create a backup.
It is easy to forget such files and this may pose a serious security threat to the application. That happens because
backup copies may be generated with file extensions differing from those of the original files. A .tar , .zip or .gz
archive that we generate (and forget...) has obviously a different extension, and the same happens with automatic
copies created by many editors (for example, emacs generates a backup copy named file~ when editing file ).
Making a copy by hand may produce the same effect (think of copying file to file.old ). The underlying file system
the application is on could be making snapshots of your application at different points in time without your knowledge,
which may also be accessible via the web, posing a similar but different backup file style threat to your application.
As a result, these activities generate files that are not needed by the application and may be handled differently than
the original file by the web server. For example, if we make a copy of login.asp named login.asp.old , we are
allowing users to download the source code of login.asp . This is because login.asp.old will be typically served as
text or plain, rather than being executed because of its extension. In other words, accessing login.asp causes the
execution of the server-side code of login.asp , while accessing login.asp.old causes the content of
login.asp.old (which is, again, server-side code) to be plainly returned to the user and displayed in the browser. This
may pose security risks, since sensitive information may be revealed.

Generally, exposing server-side code is a bad idea. Not only are you unnecessarily exposing business logic, but you
may be unknowingly revealing application-related information which may help an attacker (path names, data
structures, etc.). Not to mention the fact that there are too many scripts with embedded username and password in clear
text (which is a careless and very dangerous practice).
Other causes of unreferenced files are due to design or configuration choices when they allow diverse kind of
application-related files such as data files, configuration files, log files, to be stored in file system directories that can be
accessed by the web server. These files have normally no reason to be in a file system space that could be accessed

via web, since they should be accessed only at the application level, by the application itself (and not by the casual
user browsing around).

Threats
Old, backup and unreferenced files present various threats to the security of a web application:
Unreferenced files may disclose sensitive information that can facilitate a focused attack against the application; for
example include files containing database credentials, configuration files containing references to other hidden
content, absolute file paths, etc.
Unreferenced pages may contain powerful functionality that can be used to attack the application; for example an
administration page that is not linked from published content but can be accessed by any user who knows where
to find it.
Old and backup files may contain vulnerabilities that have been fixed in more recent versions; for example
viewdoc.old.jsp may contain a directory traversal vulnerability that has been fixed in viewdoc.jsp but can still

be exploited by anyone who finds the old version.
Backup files may disclose the source code for pages designed to execute on the server; for example requesting
viewdoc.bak may return the source code for viewdoc.jsp , which can be reviewed for vulnerabilities that may be
difficult to find by making blind requests to the executable page. While this threat obviously applies to scripted
languages, such as Perl, PHP, ASP, shell scripts, JSP, etc., it is not limited to them, as shown in the example
provided in the next bullet.
Backup archives may contain copies of all files within (or even outside) the webroot. This allows an attacker to
quickly enumerate the entire application, including unreferenced pages, source code, include files, etc. For
example, if you forget a file named myservlets.jar.old file containing (a backup copy of) your servlet
implementation classes, you are exposing a lot of sensitive information which is susceptible to decompilation and
reverse engineering.
In some cases copying or editing a file does not modify the file extension, but modifies the filename. This happens
for example in Windows environments, where file copying operations generate filenames prefixed with "Copy of "
or localized versions of this string. Since the file extension is left unchanged, this is not a case where an
executable file is returned as plain text by the web server, and therefore not a case of source code disclosure.
However, these files too are dangerous because there is a chance that they include obsolete and incorrect logic
that, when invoked, could trigger application errors, which might yield valuable information to an attacker, if
diagnostic message display is enabled.
Log files may contain sensitive information about the activities of application users, for example sensitive data
passed in URL parameters, session IDs, URLs visited (which may disclose additional unreferenced content), etc.
Other log files (e.g. ftp logs) may contain sensitive information about the maintenance of the application by system
administrators.
File system snapshots may contain copies of the code that contain vulnerabilities that have been fixed in more
recent versions. For example /.snapshot/monthly.1/view.php may contain a directory traversal vulnerability that
has been fixed in /view.php but can still be exploited by anyone who finds the old version.

Test Objectives
Find and analyse unreferenced files that might contain sensitive information.

How to Test
Black-Box Testing
Testing for unreferenced files uses both automated and manual techniques, and typically involves a combination of the
following:
Inference from the Naming Scheme Used for Published Content
Enumerate all of the application's pages and functionality. This can be done manually using a browser, or using an
application spidering tool. Most applications use a recognizable naming scheme, and organize resources into pages
and directories using words that describe their function. From the naming scheme used for published content, it is often

possible to infer the name and location of unreferenced pages. For example, if a page viewuser.asp is found, then
look also for edituser.asp , adduser.asp and deleteuser.asp . If a directory /app/user is found, then look also for
/app/admin and /app/manager .

Other Clues in Published Content
Many web applications leave clues in published content that can lead to the discovery of hidden pages and
functionality. These clues often appear in the source code of HTML and JavaScript files. The source code for all
published content should be manually reviewed to identify clues about other pages and functionality. For example:
Programmers' comments and commented-out sections of source code may refer to hidden content:

<!-- <A HREF="uploadfile.jsp">Upload a document to the server</A> -->
<!-- Link removed while bugs in uploadfile.jsp are fixed
-->

JavaScript may contain page links that are only rendered within the user's GUI under certain circumstances:

var adminUser=false;
if (adminUser) menu.add (new menuItem ("Maintain users", "/admin/useradmin.jsp"));

HTML pages may contain FORMs that have been hidden by disabling the SUBMIT element:

<form action="forgotPassword.jsp" method="post">
<input type="hidden" name="userID" value="123">
<!-- <input type="submit" value="Forgot Password"> -->
</form>

Another source of clues about unreferenced directories is the /robots.txt file used to provide instructions to web
robots:

User-agent: *
Disallow: /Admin
Disallow: /uploads
Disallow: /backup
Disallow: /~jbloggs
Disallow: /include

Blind Guessing
In its simplest form, this involves running a list of common filenames through a request engine in an attempt to guess
files and directories that exist on the server. The following netcat wrapper script will read a wordlist from stdin and
perform a basic guessing attack:

#!/bin/bash
server=example.org
port=80
while read url
do
echo -ne "$url\t"
echo -e "GET /$url HTTP/1.0\nHost: $server\n" | netcat $server $port | head -1
done | tee outputfile

Depending upon the server, GET may be replaced with HEAD for faster results. The output file specified can be
grepped for "interesting" response codes. The response code 200 (OK) usually indicates that a valid resource has
been found (provided the server does not deliver a custom "not found" page using the 200 code). But also look out for
301 (Moved), 302 (Found), 401 (Unauthorized), 403 (Forbidden) and 500 (Internal error), which may also indicate
resources or directories that are worthy of further investigation.
The basic guessing attack should be run against the webroot, and also against all directories that have been identified
through other enumeration techniques. More advanced/effective guessing attacks can be performed as follows:
Identify the file extensions in use within known areas of the application (e.g. jsp, aspx, html), and use a basic
wordlist appended with each of these extensions (or use a longer list of common extensions if resources permit).
For each file identified through other enumeration techniques, create a custom wordlist derived from that filename.
Get a list of common file extensions (including ~, bak, txt, src, dev, old, inc, orig, copy, tmp, swp, etc.) and use each
extension before, after, and instead of, the extension of the actual filename.
Note: Windows file copying operations generate filenames prefixed with "Copy of " or localized versions of this string,
hence they do not change file extensions. While "Copy of " files typically do not disclose source code when accessed,
they might yield valuable information in case they cause errors when invoked.
Information Obtained Through Server Vulnerabilities and Misconfiguration
The most obvious way in which a misconfigured server may disclose unreferenced pages is through directory listing.
Request all enumerated directories to identify any which provide a directory listing.
Numerous vulnerabilities have been found in individual web servers which allow an attacker to enumerate
unreferenced content, for example:
Apache ?M=D directory listing vulnerability.
Various IIS script source disclosure vulnerabilities.
IIS WebDAV directory listing vulnerabilities.
Use of Publicly Available Information
Pages and functionality in Internet-facing web applications that are not referenced from within the application itself may
be referenced from other public domain sources. There are various sources of these references:
Pages that used to be referenced may still appear in the archives of Internet search engines. For example,
1998results.asp may no longer be linked from a company's website, but may remain on the server and in search
engine databases. This old script may contain vulnerabilities that could be used to compromise the entire site. The
site: Google search operator may be used to run a query only against the domain of choice, such as in:
site:www.example.com . Using search engines in this way has lead to a broad array of techniques which you may

find useful and that are described in the Google Hacking section of this Guide. Check it to hone your testing skills
via Google. Backup files are not likely to be referenced by any other files and therefore may have not been indexed
by Google, but if they lie in browsable directories the search engine might know about them.
In addition, Google and Yahoo keep cached versions of pages found by their robots. Even if 1998results.asp has
been removed from the target server, a version of its output may still be stored by these search engines. The
cached version may contain references to, or clues about, additional hidden content that still remains on the server.
Content that is not referenced from within a target application may be linked to by third-party websites. For
example, an application which processes online payments on behalf of third-party traders may contain a variety of
bespoke functionality which can (normally) only be found by following links within the web sites of its customers.
Filename Filter Bypass
Because deny list filters are based on regular expressions, one can sometimes take advantage of obscure OS filename
expansion features in which work in ways the developer didn't expect. The tester can sometimes exploit differences in
ways that filenames are parsed by the application, web server, and underlying OS and it's filename conventions.
Example: Windows 8.3 filename expansion c:\\program files becomes C:\\PROGRA\~1

Remove incompatible characters
Convert spaces to underscores
Take the first six characters of the basename
Add ~<digit> which is used to distinguish files with names using the same six initial characters
This convention changes after the first 3 cname ollisions
Truncate file extension to three characters
Make all the characters uppercase

Gray-Box Testing
Performing gray box testing against old and backup files requires examining the files contained in the directories
belonging to the set of web directories served by the web server(s) of the web application infrastructure. Theoretically
the examination should be performed by hand to be thorough. However, since in most cases copies of files or backup
files tend to be created by using the same naming conventions, the search can be easily scripted. For example, editors
leave behind backup copies by naming them with a recognizable extension or ending and humans tend to leave
behind files with a .old or similar predictable extensions. A good strategy is that of periodically scheduling a
background job checking for files with extensions likely to identify them as copy or backup files, and performing manual
checks as well on a longer time basis.

Remediation
To guarantee an effective protection strategy, testing should be compounded by a security policy which clearly forbids
dangerous practices, such as:
Editing files in-place on the web server or application server file systems. This is a particularly bad habit, since it is
likely to generate backup or temporary files by the editors. It is amazing to see how often this is done, even in large
organizations. If you absolutely need to edit files on a production system, do ensure that you don't leave behind
anything which is not explicitly intended, and consider that you are doing it at your own risk.
Carefully check any other activity performed on file systems exposed by the web server, such as spot
administration activities. For example, if you occasionally need to take a snapshot of a couple of directories (which
you should not do on a production system), you may be tempted to zip them first. Be careful not to leave behind
those archive files.
Appropriate configuration management policies should help prevent obsolete and un-referenced files.
Applications should be designed not to create (or rely on) files stored under the web directory trees served by the
web server. Data files, log files, configuration files, etc. should be stored in directories not accessible by the web
server, to counter the possibility of information disclosure (not to mention data modification if web directory
permissions allow writing).
File system snapshots should not be accessible via the web if the document root is on a file system using this
technology. Configure your web server to deny access to such directories, for example under Apache a location
directive such this should be used:

<Location ~ ".snapshot">
Order deny,allow
Deny from all
</Location>

Tools
Vulnerability assessment tools tend to include checks to spot web directories having standard names (such as "admin",
"test", "backup", etc.), and to report any web directory which allows indexing. If you can't get any directory listing, you
should try to check for likely backup extensions. Check for example
Nessus
Nikto2

Web spider tools
wget
Wget for Windows
Sam Spade
Spike proxy includes a web site crawler function
Xenu
curl
Some of them are also included in standard Linux distributions. Web development tools usually include facilities to
identify broken links and unreferenced files.

---

## WSTG-CONF-05

**Enumerate Infrastructure and Application Admin Interfaces**

Summary
Administrator interfaces may be present in the application or on the application server to allow certain users to
undertake privileged activities on the site. Tests should be undertaken to reveal if and how this privileged functionality
can be accessed by an unauthorized or standard user.
An application may require an administrator interface to enable a privileged user to access functionality that may make
changes to how the site functions. Such changes may include:
user account provisioning
site design and layout
data manipulation
configuration changes
In many instances, such interfaces do not have sufficient controls to protect them from unauthorized access. Testing is
aimed at discovering these administrator interfaces and accessing functionality intended for the privileged users.

Test Objectives
Identify hidden administrator interfaces and functionality.

How to Test
Black-Box Testing
The following section describes vectors that may be used to test for the presence of administrative interfaces. These
techniques may also be used to test for related issues including privilege escalation, and are described elsewhere in
this guide(for example Testing for bypassing authorization schema and Testing for Insecure Direct Object References in
greater detail.
Directory and file enumeration. An administrative interface may be present but not visibly available to the tester.
Attempting to guess the path of the administrative interface may be as simple as requesting: /admin or
/administrator etc.. or in some scenarios can be revealed within seconds using Google dorks.
There are many tools available to perform brute forcing of server contents, see the tools section below for more
information. A tester may have to also identify the filename of the administration page. Forcibly browsing to the
identified page may provide access to the interface.
Comments and links in source code. Many sites use common code that is loaded for all site users. By examining
all source sent to the client, links to administrator functionality may be discovered and should be investigated.
Reviewing server and application documentation. If the application server or application is deployed in its default
configuration it may be possible to access the administration interface using information described in configuration
or help documentation. Default password lists should be consulted if an administrative interface is found and
credentials are required.
Publicly available information. Many applications such as WordPress have default administrative interfaces .
Alternative server port. Administration interfaces may be seen on a different port on the host than the main
application. For example, Apache Tomcat's Administration interface can often be seen on port 8080.
Parameter tampering. A GET or POST parameter or a cookie variable may be required to enable the administrator
functionality. Clues to this include the presence of hidden fields such as:

<input type="hidden" name="admin" value="no">

or in a cookie:
Cookie: session_cookie; useradmin=0

Once an administrative interface has been discovered, a combination of the above techniques may be used to attempt
to bypass authentication. If this fails, the tester may wish to attempt a brute force attack. In such an instance the tester
should be aware of the potential for administrative account lockout if such functionality is present.

Gray-Box Testing
A more detailed examination of the server and application components should be undertaken to ensure hardening (i.e.
administrator pages are not accessible to everyone through the use of IP filtering or other controls), and where
applicable, verification that all components do not use default credentials or configurations. Source code should be
reviewed to ensure that the authorization and authentication model ensures clear separation of duties between normal
users and site administrators. User interface functions shared between normal and administrator users should be
reviewed to ensure clear separation between the drawing of such components and information leakage from such
shared functionality.
Each web framework may have its own admin default pages or path. For example
WebSphere:

/admin
/admin-authz.xml
/admin.conf
/admin.passwd
/admin/*
/admin/logon.jsp
/admin/secure/logon.jsp

PHP:

/phpinfo
/phpmyadmin/
/phpMyAdmin/
/mysqladmin/
/MySQLadmin
/MySQLAdmin
/login.php
/logon.php
/xmlrpc.php
/dbadmin

FrontPage:

/admin.dll
/admin.exe
/administrators.pwd
/author.dll
/author.exe
/author.log
/authors.pwd
/cgi-bin

WebLogic:

/AdminCaptureRootCA
/AdminClients
/AdminConnections
/AdminEvents
/AdminJDBC
/AdminLicense
/AdminMain
/AdminProps
/AdminRealm
/AdminThreads

WordPress:

wp-admin/
wp-admin/about.php
wp-admin/admin-ajax.php
wp-admin/admin-db.php
wp-admin/admin-footer.php
wp-admin/admin-functions.php
wp-admin/admin-header.php

Tools
OWASP ZAP - Forced Browse is a currently maintained use of OWASP's previous DirBuster project.
THC-HYDRA is a tool that allows brute-forcing of many interfaces, including form-based HTTP authentication.
A brute forcer is much better when it uses a good dictionary, for example the netsparker dictionary.

References
Cirt: Default Password list
FuzzDB can be used to do brute force browsing admin login path
Common admin or debugging parameters

---

## WSTG-CONF-06

**Test HTTP Methods**

Summary
HTTP offers a number of methods that can be used to perform actions on the web server (the HTTP 1.1 standard refers
to them as methods but they are also commonly described as verbs ). While GET and POST are by far the most
common methods that are used to access information provided by a web server, HTTP allows several other (and
somewhat less known) methods. Some of these can be used for nefarious purposes if the web server is misconfigured.
RFC 7231 - Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content defines the following valid HTTP request
methods, or verbs:
GET
HEAD
POST
PUT
DELETE
CONNECT
OPTIONS
TRACE

However, most web applications only need to respond to GET and POST requests, receiving user data in the URL
query string or appended to the request respectively. The standard <a href=""></a> style links as well as forms
defined without a method trigger a GET request; form data submitted via <form method='POST'></form> trigger POST
requests. JavaScript and AJAX calls may send methods other than GET and POST but should usually not need to do
that. Since the other methods are so rarely used, many developers do not know, or fail to take into consideration, how
the web server or application framework's implementation of these methods impact the security features of the
application.

Test Objectives
Enumerate supported HTTP methods.
Test for access control bypass.
Test XST vulnerabilities.
Test HTTP method overriding techniques.

How to Test
Discover the Supported Methods
To perform this test, the tester needs some way to figure out which HTTP methods are supported by the web server that
is being examined. While the OPTIONS HTTP method provides a direct way to do that, verify the server's response by
issuing requests using different methods. This can be achieved by manual testing or something like the http-methods
Nmap script.
To use the http-methods Nmap script to test the endpoint /index.php on the server localhost using HTTPS, issue
the command:

nmap -p 443 --script http-methods --script-args http-methods.url-path='/index.php' localhost

When testing an application that has to accept other methods, e.g. a RESTful Web Service, test it thoroughly to make
sure that all endpoints accept only the methods that they require.
Testing the PUT Method
1. Capture the base request of the target with a web proxy.
2. Change the request method to PUT and add test.html file and send the request to the application server.

PUT /test.html HTTP/1.1
Host: testing-website
<html>
HTTP PUT Method is Enabled
</html>

3. If the server response with 2XX success codes or 3XX redirections and then confirm by GET request for
test.html file. The application is vulnerable.
If the HTTP PUT method is not allowed on base URL or request, try other paths in the system.
NOTE: If you are successful in uploading a web shell you should overwrite it or ensure that the security team of the
target are aware and remove the component promptly after your proof-of-concept.
Leveraging the PUT method an attacker may be able to place arbitrary and potentially malicious content, into the
system which may lead to remote code execution, defacing the site or denial of service.

Testing for Access Control Bypass
Find a page to visit that has a security constraint such that a GET request would normally force a 302 redirect to a log in
page or force a log in directly. Issue requests using various methods such as HEAD, POST, PUT etc. as well as
arbitrarily made up methods such as BILBAO, FOOBAR, CATS, etc. If the web application responds with a HTTP/1.1
200 OK that is not a log in page, it may be possible to bypass authentication or authorization. The following example
uses Nmap's ncat .

$ ncat www.example.com 80
HEAD /admin HTTP/1.1
Host: www.example.com
HTTP/1.1 200 OK
Date: Mon, 18 Aug 2008 22:44:11 GMT
Server: Apache
Set-Cookie: PHPSESSID=pKi...; path=/; HttpOnly
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Set-Cookie: adminOnlyCookie1=...; expires=Tue, 18-Aug-2009 22:44:31 GMT; domain=www.example.com
Set-Cookie: adminOnlyCookie2=...; expires=Mon, 18-Aug-2008 22:54:31 GMT; domain=www.example.com
Set-Cookie: adminOnlyCookie3=...; expires=Sun, 19-Aug-2007 22:44:30 GMT; domain=www.example.com
Content-Language: EN
Connection: close
Content-Type: text/html; charset=ISO-8859-1

If the system appears vulnerable, issue CSRF-like attacks such as the following to exploit the issue more fully:

HEAD /admin/createUser.php?member=myAdmin
PUT /admin/changePw.php?member=myAdmin&passwd=foo123&confirm=foo123
CATS /admin/groupEdit.php?group=Admins&member=myAdmin&action=add

Using the above three commands, modified to suit the application under test and testing requirements, a new user
would be created, a password assigned, and the user made an administrator, all using blind request submission.

Testing for Cross-Site Tracing Potential
Note: in order to understand the logic and the goals of a cross-site tracing (XST) attack, one must be familiar with crosssite scripting attacks.
The TRACE method, intended for testing and debugging, instructs the web server to reflect the received message back
to the client. This method, while apparently harmless, can be successfully leveraged in some scenarios to steal
legitimate users' credentials. This attack technique was discovered by Jeremiah Grossman in 2003, in an attempt to
bypass the HttpOnly attribute that aims to protect cookies from being accessed by JavaScript. However, the TRACE
method can be used to bypass this protection and access the cookie even when this attribute is set.
Test for cross-site tracing potential by issuing a request such as the following:

$ ncat www.victim.com 80
TRACE / HTTP/1.1
Host: www.victim.com
Random: Header
HTTP/1.1 200 OK
Random: Header
...

The web server returned a 200 and reflected the random header that was set in place. To further exploit this issue:

$ ncat www.victim.com 80
TRACE / HTTP/1.1
Host: www.victim.com
Attack: <script>prompt()</script>

The above example works if the response is being reflected in the HTML context.
In older browsers, attacks were pulled using XHR](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest)
technology, which leaked the headers when the server reflects them (e.g. Cookies, Authorization tokens, etc.) and
bypassed security measures such as the [HttpOnly attribute. This attack can be pulled in recent browsers only if the
application integrates with technologies similar to Flash.

Testing for HTTP Method Overriding
Some web frameworks provide a way to override the actual HTTP method in the request by emulating the missing
HTTP verbs passing some custom header in the requests. The main purpose of this is to circumvent some middleware
(e.g. proxy, firewall) limitation where methods allowed usually do not encompass verbs such as PUT or DELETE . The
following alternative headers could be used to do such verb tunneling:
X-HTTP-Method
X-HTTP-Method-Override
X-Method-Override

In order to test this, in the scenarios where restricted verbs such as PUT or DELETE return a "405 Method not allowed",
replay the same request with the addition of the alternative headers for HTTP method overriding, and observe how the

system responds. The application should respond with a different status code (e.g. 200) in cases where method
overriding is supported.
The web server in the following example does not allow the DELETE method and blocks it:

$ ncat www.example.com 80
DELETE /resource.html HTTP/1.1
Host: www.example.com
HTTP/1.1 405 Method Not Allowed
Date: Sat, 04 Apr 2020 18:26:53 GMT
Server: Apache
Allow: GET,HEAD,POST,OPTIONS
Content-Length: 320
Content-Type: text/html; charset=iso-8859-1
Vary: Accept-Encoding

After adding the X-HTTP-Header , the server responds to the request with a 200:

$ ncat www.example.com 80
DELETE /resource.html HTTP/1.1
Host: www.example.com
X-HTTP-Method: DELETE
HTTP/1.1 200 OK
Date: Sat, 04 Apr 2020 19:26:01 GMT
Server: Apache

Remediation
Ensure that only the required headers are allowed, and that the allowed headers are properly configured.
Ensure that no workarounds are implemented to bypass security measures implemented by user-agents,
frameworks, or web servers.

Tools
Ncat
cURL
nmap http-methods NSE script
w3af plugin htaccess_methods

References
RFC 2109 and RFC 2965: "HTTP State Management Mechanism"
HTACCESS: BILBAO Method Exposed
Amit Klein: "XS(T) attack variants which can, in some cases, eliminate the need for TRACE"
Fortify - Misused HTTP Method Override
CAPEC-107: Cross Site Tracing

---

## WSTG-CONF-07

**Test HTTP Strict Transport Security**

Summary
The HTTP Strict Transport Security (HSTS) feature lets a web application inform the browser through the use of a
special response header that it should never establish a connection to the specified domain servers using unencrypted HTTP. Instead, it should automatically establish all connection requests to access the site through HTTPS. It
also prevents users from overriding certificate errors.
Considering the importance of this security measure it is prudent to verify that the web site is using this HTTP header in
order to ensure that all the data travels encrypted between the web browser and the server.
The HTTP strict transport security header uses two directives:
max-age : to indicate the number of seconds that the browser should automatically convert all HTTP requests to

HTTPS.
includeSubDomains : to indicate that all related sub-domains must use HTTPS.
preload Unofficial: to indicate that the domain(s) are on the preload list(s) and that browsers should never

connect without HTTPS.
This is supported by all major browsers but is not official part of the specification. (See hstspreload.org for
more information.)
Here's an example of the HSTS header implementation:
Strict-Transport-Security: max-age=31536000; includeSubDomains

The use of this header by web applications must be checked to find if the following security issues could be produced:
Attackers sniffing the network traffic and accessing the information transferred through an un-encrypted channel.
Attackers exploiting a manipulator in the middle attack because of the problem of accepting certificates that are not
trusted.
Users who mistakenly entered an address in the browser putting HTTP instead of HTTPS, or users who click on a
link in a web application which mistakenly indicated use of the HTTP protocol.

Test Objectives
Review the HSTS header and its validity.

How to Test
The presence of the HSTS header can be confirmed by examining the server's response through an intercepting proxy
or by using curl as follows:

$ curl -s -D- https://owasp.org | grep -i strict
Strict-Transport-Security: max-age=31536000

References
OWASP HTTP Strict Transport Security

OWASP Appsec Tutorial Series - Episode 4: Strict Transport Security
HSTS Specification

---

## WSTG-CONF-08

**Test RIA Cross Domain Policy**

Summary
Rich Internet Applications (RIA) have adopted Adobe's crossdomain.xml policy files to allow for controlled cross
domain access to data and service consumption using technologies such as Oracle Java, Silverlight, and Adobe Flash.
Therefore, a domain can grant remote access to its services from a different domain. However, often the policy files that
describe the access restrictions are poorly configured. Poor configuration of the policy files enables Cross-site Request
Forgery attacks, and may allow third parties to access sensitive data meant for the user.

What are cross-domain policy files?
A cross-domain policy file specifies the permissions that a web client such as Java, Adobe Flash, Adobe Reader, etc.
use to access data across different domains. For Silverlight, Microsoft adopted a subset of the Adobe's
crossdomain.xml, and additionally created it's own cross-domain policy file: clientaccesspolicy.xml.
Whenever a web client detects that a resource has to be requested from other domain, it will first look for a policy file in
the target domain to determine if performing cross-domain requests, including headers, and socket-based connections
are allowed.
Master policy files are located at the domain's root. A client may be instructed to load a different policy file but it will
always check the master policy file first to ensure that the master policy file permits the requested policy file.
Crossdomain.xml vs. Clientaccesspolicy.xml
Most RIA applications support crossdomain.xml. However in the case of Silverlight, it will only work if the
crossdomain.xml specifies that access is allowed from any domain. For more granular control with Silverlight,
clientaccesspolicy.xml must be used.
Policy files grant several types of permissions:
Accepted policy files (Master policy files can disable or restrict specific policy files)
Sockets permissions
Header permissions
HTTP/HTTPS access permissions
Allowing access based on cryptographic credentials
An example of an overly permissive policy file:

<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM
"http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
<site-control permitted-cross-domain-policies="all"/>
<allow-access-from domain="*" secure="false"/>
<allow-http-request-headers-from domain="*" headers="*" secure="false"/>
</cross-domain-policy>

How can cross domain policy files can be abused?
Overly permissive cross-domain policies.

Generating server responses that may be treated as cross-domain policy files.
Using file upload functionality to upload files that may be treated as cross-domain policy files.

Impact of Abusing Cross-Domain Access
Defeat CSRF protections.
Read data restricted or otherwise protected by cross-origin policies.

Test Objectives
Review and validate the policy files.

How to Test
Testing for RIA Policy Files Weakness
To test for RIA policy file weakness the tester should try to retrieve the policy files crossdomain.xml and
clientaccesspolicy.xml from the application's root, and from every folder found.
For example, if the application's URL is http://www.owasp.org , the tester should try to download the files
http://www.owasp.org/crossdomain.xml and http://www.owasp.org/clientaccesspolicy.xml .

After retrieving all the policy files, the permissions allowed should be be checked under the least privilege principle.
Requests should only come from the domains, ports, or protocols that are necessary. Overly permissive policies should
be avoided. Policies with * in them should be closely examined.
Example
<cross-domain-policy>
<allow-access-from domain="*" />
</cross-domain-policy>

Result Expected

A list of policy files found.
A list of weak settings in the policies.

Tools
Nikto
OWASP Zed Attack Proxy Project
W3af

References
Adobe: "Cross-domain policy file specification"
Adobe: "Cross-domain policy file usage recommendations for Flash Player"
Oracle: "Cross-Domain XML Support"
MSDN: "Making a Service Available Across Domain Boundaries"
MSDN: "Network Security Access Restrictions in Silverlight"
Stefan Esser: "Poking new holes with Flash Crossdomain Policy Files"
Jeremiah Grossman: "Crossdomain.xml Invites Cross-site Mayhem"
Google Doctype: "Introduction to Flash security"
UCSD: Analyzing the Crossdomain Policies of Flash Applications

---

## WSTG-CONF-09

**Test File Permission**

Summary
When a resource is given a permissions setting that provides access to a wider range of actors than required, it could
lead to the exposure of sensitive information, or the modification of that resource by unintended parties. This is
especially dangerous when the resource is related to program configuration, execution, or sensitive user data.
A clear example is an execution file that is executable by unauthorized users. For another example, account
information or a token value to access an API - increasingly seen in modern web services or microservices - may be
stored in a configuration file whose permissions are set to world-readable from the installation by default. Such
sensitive data can be exposed by internal malicious actors of the host or by a remote attacker who compromised the
service with other vulnerabilities but obtained only a normal user privilege.

Test Objectives
Review and identify any rogue file permissions.

How to Test
In Linux, use ls command to check the file permissions. Alternatively, namei can also be used to recursively list file
permissions.
$ namei -l /PathToCheck/

The files and directories that require file permission testing include but are not limited to:
Web files/directory
Configuration files/directory
Sensitive files (encrypted data, password, key)/directory
Log files (security logs, operation logs, admin logs)/directory
Executables (scripts, EXE, JAR, class, PHP, ASP)/directory
Database files/directory
Temp files /directory
Upload files/directory

Remediation
Set the permissions of the files and directories properly so that unauthorized users cannot access critical resources
unnecessarily.

Tools
Windows AccessEnum
Windows AccessChk
Linux namei

References
CWE-732: Incorrect Permission Assignment for Critical Resource

---

## WSTG-CONF-10

**Test for Subdomain Takeover**

Summary
A successful exploitation of this kind of vulnerability allows an adversary to claim and take control of the victim's
subdomain. This attack relies on the following:
1. The victim's external DNS server subdomain record is configured to point to a non-existing or non-active
resource/external service/endpoint. The proliferation of XaaS (Anything as a Service) products and public cloud
services offer a lot of potential targets to consider.
2. The service provider hosting the resource/external service/endpoint does not handle subdomain ownership
verification properly.
If the subdomain takeover is successful a wide variety of attacks are possible (serving malicious content, phising,
stealing user session cookies, credentials, etc.). This vulnerability could be exploited for a wide variety of DNS resource
records including: A , CNAME , MX , NS , TXT etc. In terms of the attack severity an NS subdomain takeover (although
less likely) has the highest impact because a successful attack could result in full control over the whole DNS zone and
the victim's domain.

GitHub
1. The victim (victim.com) uses GitHub for development and configured a DNS record ( coderepo.victim.com ) to
access it.
2. The victim decides to migrate their code repository from GitHub to a commercial platform and does not remove
coderepo.victim.com from their DNS server.
3. An adversary finds out that coderepo.victim.com is hosted on GitHub and uses GitHub Pages to claim
coderepo.victim.com using their GitHub account.

Expired Domain
1. The victim (victim.com) owns another domain (victimotherdomain.com) and uses a CNAME record (www) to
reference the other domain ( www.victim.com -> victimotherdomain.com )
2. At some point, victimotherdomain.com expires and is available for registration by anyone. Since the CNAME
record is not deleted from the victim.com DNS zone, anyone who registers victimotherdomain.com has full
control over www.victim.com until the DNS record is present.

Test Objectives
Enumerate all possible domains (previous and current).
Identify forgotten or misconfigured domains.

How to Test
Black-Box Testing
The first step is to enumerate the victim DNS servers and resource records. There are multiple ways to accomplish this
task, for example DNS enumeration using a list of common subdomains dictionary, DNS brute force or using web
search engines and other OSINT data sources.
Using the dig command the tester looks for the following DNS server response messages that warrant further
investigation:

NXDOMAIN
SERVFAIL
REFUSED
no servers could be reached.

Testing DNS A, CNAME Record Subdomain Takeover
Perform a basic DNS enumeration on the victim's domain ( victim.com ) using dnsrecon :

$ ./dnsrecon.py -d victim.com
[*] Performing General Enumeration of Domain: victim.com
...
[-] DNSSEC is not configured for victim.com
[*]
A subdomain.victim.com 192.30.252.153
[*]
CNAME subdomain1.victim.com fictioussubdomain.victim.com
...

Identify which DNS resource records are dead and point to inactive/not-used services. Using the dig command for the
CNAME record:

$ dig CNAME fictioussubdomain.victim.com
; <<>> DiG 9.10.3-P4-Ubuntu <<>> ns victim.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 42950
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

The following DNS responses warrant further investigation: NXDOMAIN .
To test the A record the tester performs a whois database lookup and identifies GitHub as the service provider:

$ whois 192.30.252.153 | grep "OrgName"
OrgName: GitHub, Inc.

The tester visits subdomain.victim.com or issues a HTTP GET request which returns a "404 - File not found" response
which is a clear indication of the vulnerability.

Figure 4.2.10-1: GitHub 404 File Not Found response

The tester claims the domain using GitHub Pages:

Figure 4.2.10-2: GitHub claim domain

Testing NS Record Subdomain Takeover
Identify all nameservers for the domain in scope:

$ dig ns victim.com +short
ns1.victim.com
nameserver.expireddomain.com

In this fictious example the tester checks if the domain expireddomain.com is active with a domain registrar search. If
the domain is available for purchase the subdomain is vulnerable.
The following DNS responses warrant further investigation: SERVFAIL or REFUSED .

Gray-Box Testing
The tester has the DNS zone file available which means DNS enumeration is not necessary. The testing methodology
is the same.

Remediation
To mitigate the risk of subdomain takeover the vulnerable DNS resource record(s) should be removed from the DNS
zone. Continous monitoring and periodic checks are recommended as best practice.

Tools
dig - man page
recon-ng - Web Reconnaissance framework
theHarvester - OSINT intelligence gathering tool
Sublist3r - OSINT subdomain enumeration tool
dnsrecon - DNS Enumeration Script
OWASP Amass DNS enumeration

References
HackerOne - A Guide To Subdomain Takeovers
Subdomain Takeover: Basics
Subdomain Takeover: Going beyond CNAME
OWASP AppSec Europe 2017 - Frans Rosén: DNS hijacking using cloud providers - no verification needed

---

## WSTG-CONF-11

**Test Cloud Storage**

Summary
Cloud storage services facilitate web application and services to store and access objects in the storage service.
Improper access control configuration, however, may result in sensitive information exposure, data being tampered, or
unauthorized access.
A known example is where an Amazon S3 bucket is misconfigured, although the other cloud storage services may also
be exposed to similar risks. By default, all S3 buckets are private and can be accessed only by users that are explicitly
granted access. Users can grant public access to both the bucket itself and to individual objects stored within that
bucket. This may lead to an unauthorized user being able to upload new files, modify or read stored files.

Test Objectives
Assess that the access control configuration for the storage services is properly in place.

How to Test
First identify the URL to access the data in the storage service, and then consider the following tests:
read the unauthorized data
upload a new arbitrary file
You may use curl for the tests with the following commands and see if unauthorized actions can be performed
successfully.
To test the ability to read an object:

curl -X GET https://<cloud-storage-service>/<object>

To test the ability to upload a file:

curl -X PUT -d 'test' 'https://<cloud-storage-service>/test.txt'

Testing for Amazon S3 Bucket Misconfiguration
The Amazon S3 bucket URLs follow one of two formats, either virtual host style or path-style.
Virtual Hosted Style Access

https://bucket-name.s3.Region.amazonaws.com/key-name

In the following example, my-bucket is the bucket name, us-west-2 is the region, and puppy.png is the key-name:

https://my-bucket.s3.us-west-2.amazonaws.com/puppy.png

Path-Style Access

https://s3.Region.amazonaws.com/bucket-name/key-name

As above, in the following example, my-bucket is the bucket name, us-west-2 is the region, and puppy.png is the
key-name:

https://s3.us-west-2.amazonaws.com/my-bucket/puppy.jpg

For some regions, the legacy global endpoint that does not specify a region-specific endpoint can be used. Its format is
also either virtual hosted style or path-style.
Virtual Hosted Style Access

https://bucket-name.s3.amazonaws.com

Path-Style Access

https://s3.amazonaws.com/bucket-name

Identify Bucket URL
For black-box testing, S3 URLs can be found in the HTTP messages. The following example shows a bucket URL is
sent in the img tag in a HTTP response.

...
<img src="https://my-bucket.s3.us-west-2.amazonaws.com/puppy.png">
...

For gray-box testing, you can obtain bucket URLs from Amazon's web interface, documents, source code, or any other
available sources.
Testing with AWS-CLI
In addition to testing with curl, you can also test with the AWS Command-line tool. In this case s3:// protocol is used.
List

The following command lists all the objects of the bucket when it is configured public.

aws s3 ls s3://<bucket-name>

Upload

The following is the command to upload a file

aws s3 cp arbitrary-file s3://bucket-name/path-to-save

This example shows the result when the upload has been successful.

$ aws s3 cp test.txt s3://bucket-name/test.txt
upload: ./test.txt to s3://bucket-name/test.txt

This example shows the result when the upload has failed.

$ aws s3 cp test.txt s3://bucket-name/test.txt
upload failed: ./test2.txt to s3://bucket-name/test2.txt An error occurred (AccessDenied) when
calling the PutObject operation: Access Denied

Remove

The following is the command to remove an object

aws s3 rm s3://bucket-name/object-to-remove

Tools
AWS CLI

References
Working with Amazon S3 Buckets
flAWS 2

4.3 Identity Management Testing
4.3.1 Test Role Definitions
4.3.2 Test User Registration Process
4.3.3 Test Account Provisioning Process
4.3.4 Testing for Account Enumeration and Guessable User Account
4.3.5 Testing for Weak or Unenforced Username Policy

---

