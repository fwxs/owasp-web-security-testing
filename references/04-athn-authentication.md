# WSTG ATHN — Authentication

OWASP Web Security Testing Guide v4.2. 10 test cases: WSTG-ATHN-01, WSTG-ATHN-02, WSTG-ATHN-03, WSTG-ATHN-04, WSTG-ATHN-05, WSTG-ATHN-06, WSTG-ATHN-07, WSTG-ATHN-08, WSTG-ATHN-09, WSTG-ATHN-10.

## Table of Contents

- [WSTG-ATHN-01 — Testing for Credentials Transported over an Encrypted Channel](#wstg-athn-01)
- [WSTG-ATHN-02 — Testing for Default Credentials](#wstg-athn-02)
- [WSTG-ATHN-03 — Testing for Weak Lock Out Mechanism](#wstg-athn-03)
- [WSTG-ATHN-04 — Testing for Bypassing Authentication Schema](#wstg-athn-04)
- [WSTG-ATHN-05 — Testing for Vulnerable Remember Password](#wstg-athn-05)
- [WSTG-ATHN-06 — Testing for Browser Cache Weaknesses](#wstg-athn-06)
- [WSTG-ATHN-07 — Testing for Weak Password Policy](#wstg-athn-07)
- [WSTG-ATHN-08 — Testing for Weak Security Question Answer](#wstg-athn-08)
- [WSTG-ATHN-09 — Testing for Weak Password Change or Reset Functionalities](#wstg-athn-09)
- [WSTG-ATHN-10 — Testing for Weaker Authentication in Alternative Channel](#wstg-athn-10)

---

## WSTG-ATHN-01

**Testing for Credentials Transported over an Encrypted Channel**

Summary
Testing for credentials transport verifies that web applications encrypt authentication data in transit. This encryption
prevents attackers from taking over accounts by sniffing network traffic. Web applications use HTTPS to encrypt
information in transit for both client to server and server to client communications. A client can send or receive
authentication data during the following interactions:
A client sends a credential to request login
The server responds to a successful login with a session token
An authenticated client sends a session token to request sensitive information from the web site
A client sends a token to the web site if they forgot their password
Failure to encrypt any of these credentials in transit can allow attackers with network sniffing tools to view credentials
and possibly use them to steal a user's account. The attacker could sniff traffic directly using Wireshark or similar tools,
or they could set up a proxy to capture HTTP requests. Sensitive data should be encrypted in transit to prevent this.
The fact that traffic is encrypted does not necessarily mean that it's completely safe. The security also depends on the
encryption algorithm used and the robustness of the keys that the application is using. See Testing for Weak Transport
Layer Security to verify the encryption algorithm is sufficient.

Test Objectives
Assess whether any use case of the web site or application causes the server or the client to exchange credentials
without encryption.

How to Test
To test for credential transport, capture traffic between a client and web application server that needs credentials.
Check for credentials transferred during login and while using the application with a valid session. To set up for the test:
1. Set up and start a tool to capture traffic, such as one of the following:
The web browser's developer tools
A proxy including OWASP ZAP
2. Disable any features or plugins that make the web browser favour HTTPS. Some browsers or extensions, such as
HTTPS Everywhere, will combat forced browsing by redirecting HTTP requests to HTTPS.
In the captured traffic, look for sensitive data including the following:
Passphrases or passwords, usually inside a message body
Tokens, usually inside cookies
Account or password reset codes
For any message containing this sensitive data, verify the exchange occurred using HTTPS (and not HTTP). The
following examples show captured data that indicate passed or failed tests, where the web application is on a server
called www.example.org .

Login
Find the address of the login page and attempt to switch the protocol to HTTP. For example, the URL for the forced
browsing could look like the following: http://www.example.org/login .
If the login page is normally HTTPS, attempt to remove the "S" to see if the login page loads as HTTP.
Log in using a valid account while attempting to force the use of unencrypted HTTP. In a passing test, the login request
should be HTTPS:

Request URL: https://www.example.org/j_acegi_security_check
Request method: POST
...
Response headers:
HTTP/1.1 302 Found
Server: nginx/1.19.2
Date: Tue, 29 Sep 2020 00:59:04 GMT
Transfer-Encoding: chunked
Connection: keep-alive
X-Content-Type-Options: nosniff
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Set-Cookie: JSESSIONID.a7731d09=node01ai3by8hip0g71kh3ced41pmqf4.node0; Path=/; Secure; HttpOnly
ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE=dXNlcmFiYzoxNjAyNTUwNzQ0NDU3OjFmNDlmYTZhOGI1YTZkYTYxNDIwYWV
mNmM0OTI1OGFhODA3Y2ZmMjg4MDM3YjcwODdmN2I2NjMwOWIyMDU3NTc=; Path=/; Expires=Tue, 13-Oct-2020 00:59:04
GMT; Max-Age=1209600; Secure; HttpOnly
Location: https://www.example.org/
...
POST data:
j_username=userabc
j_password=My-Protected-Password-452
from=/
Submit=Sign in

In the login, the credentials are encrypted due to the HTTPS request URL
If the server returns cookie information for a session token, the cookie should also include the Secure attribute to
avoid the client exposing the cookie over unencrypted channels later. Look for the Secure keyword in the
response header.
The test fails if any login transfers a credential over HTTP, similar to the following:

Request URL: http://www.example.org/j_acegi_security_check
Request method: POST
...
POST data:
j_username=userabc
j_password=My-Protected-Password-452
from=/
Submit=Sign in

In this failing test example:
The fetch URL is http:// and it exposes the plaintext j_username and j_password through the post data.
In this case, since the test already shows POST data exposing all the credentials, there is no point checking
response headers (which would also likely expose a session token or cookie).

Account Creation
To test for unencrypted account creation, attempt to force browse to the HTTP version of the account creation and
create an account, for example: http://www.example.org/securityRealm/createAccount

The test passes if even after the forced browsing, the client still sends the new account request through HTTPS:

Request URL: https://www.example.org/securityRealm/createAccount
Request method: POST
...
Response headers:
HTTP/1.1 200 OK
Server: nginx/1.19.2
Date: Tue, 29 Sep 2020 01:11:50 GMT
Content-Type: text/html;charset=utf-8
Content-Length: 3139
Connection: keep-alive
X-Content-Type-Options: nosniff
Set-Cookie: JSESSIONID.a7731d09=node011yew1ltrsh1x1k3m6g6b44tip8.node0; Path=/; Secure; HttpOnly
Expires: 0
Cache-Control: no-cache,no-store,must-revalidate
X-Hudson-Theme: default
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
X-Hudson: 1.395
X-Jenkins: 2.257
X-Jenkins-Session: 4551da08
X-Hudson-CLI-Port: 50000
X-Jenkins-CLI-Port: 50000
X-Jenkins-CLI2-Port: 50000
X-Frame-Options: sameorigin
Content-Encoding: gzip
X-Instance-Identity:
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3344ru7RK0jgdpKs3cfrBy2tteYI1laGpbP4fr5zOx2b/1OEvbVioU5U
btfIUHruD9N7jBG+KG4pcWfUiXdLp2skrBYsXBfiwUDA8Wam3wSbJWTmPfSRiIu4dsfIedj0bYX5zJSa6QPLxYolaKtBP4vEnP6l
BFqW2vMuzaN6QGReAxM4NKWTijFtpxjchyLQ2o+K5mSEJQIWDIqhv1sKxdM9zkb6pW/rI1deJJMSih66les5kXgbH2fnO7Fz6di8
8jT1tAHoaXWkPM9X0EbklkHPT9b7RVXziOURXVIPUTU5u+LYGkNavEb+bdPmsD94elD/cf5ZqdGNoOAE5AYS0QIDAQAB
...
POST data:
username=user456
fullname=User 456
password1=My-Protected-Password-808
password2=My-Protected-Password-808
Submit=Create account
Jenkins-Crumb=58e6f084fd29ea4fe570c31f1d89436a0578ef4d282c1bbe03ffac0e8ad8efd6

Similar to a login, most web applications automatically give a session token on a successful account creation. If
there is a Set-Cookie: , verify it has a Secure; attribute as well.
The test fails if the client sends a new account request with unencrypted HTTP:

Request URL: http://www.example.org/securityRealm/createAccount
Request method: POST
...
POST data:
username=user456
fullname=User 456
password1=My-Protected-Password-808
password2=My-Protected-Password-808
Submit=Create account
Jenkins-Crumb=8c96276321420cdbe032c6de141ef556cab03d91b25ba60be8fd3d034549cdd3

This Jenkins user creation form exposed all the new user details (name, full name, and password) in POST data to
the HTTP create account page

Password Reset, Change Password or Other Account Manipulation

Similar to login and account creation, if the web application has features that allow a user to change an account or call
a different service with credentials, verify all of those interactions are HTTPS. The interactions to test include the
following:
Forms that allow users to handle a forgotten password or other credential
Forms that allow users to edit credentials
Forms that require the user to authenticate with another provider (for example, payment processing)

Accessing Resources While Logged In
After logging in, access all the features of the application, including public features that do not necessarily require a
login to access. Forced browse to the HTTP version of the web site to see if the client leaks credentials.
The test passes if all interactions send the session token over HTTPS similar to the following example:

Request URL:http://www.example.org/
Request method:GET
...
Request headers:
GET / HTTP/1.1
Host: www.example.org
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: keep-alive
Cookie: JSESSIONID.a7731d09=node01ai3by8hip0g71kh3ced41pmqf4.node0;
ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE=dXNlcmFiYzoxNjAyNTUwNzQ0NDU3OjFmNDlmYTZhOGI1YTZkYTYxNDIwYWV
mNmM0OTI1OGFhODA3Y2ZmMjg4MDM3YjcwODdmN2I2NjMwOWIyMDU3NTc=; screenResolution=1920x1200
Upgrade-Insecure-Requests: 1

The session token in the cookie is encrypted since the request URL is HTTPS
The test fails if the browser submits a session token over HTTP in any part of the web site, even if forced browsing is
required to trigger this case:

Request URL:http://www.example.org/
Request method:GET
...
Request headers:
GET / HTTP/1.1
Host: www.example.org
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Cookie: language=en; welcomebanner_status=dismiss; cookieconsent_status=dismiss;
screenResolution=1920x1200; JSESSIONID.c1e7b45b=node01warjbpki6icgxkn0arjbivo84.node0
Upgrade-Insecure-Requests: 1

The GET request exposed the session token

JSESSIONID

(from browser to server) in request URL

http://www.example.org/

Remediation
Use HTTPS for the whole web site. Implement HSTS and redirect any HTTP to HTTPS. The site gains the following
benefits from using HTTPS for all its features:

It prevents attackers from modifying interactions with the web server (including placing JavaScript malware through
a compromised router).
It avoids losing customers to insecure site warnings. New browsers mark HTTP based web sites as insecure.
It makes writing certain applications easier. For example, Android APIs need overrides to connect to anything via
HTTP.
If it is cumbersome to switch to HTTPS, prioritize HTTPS for sensitive operations first. For the medium term, plan to
convert the whole application to HTTPS to avoid losing customers to compromise or the warnings of HTTP being
insecure. If the organization does not already buy certificates for HTTPS, look in to Let's Encrypt or other free certificate
authorities on the server.

---

## WSTG-ATHN-02

**Testing for Default Credentials**

Summary
Nowadays web applications often make use of popular Open Source or commercial software that can be installed on
servers with minimal configuration or customization by the server administrator. Moreover, a lot of hardware appliances
(i.e. network routers and database servers) offer web-based configuration or administrative interfaces.
Often these applications, once installed, are not properly configured and the default credentials provided for initial
authentication and configuration are never changed. These default credentials are well known by penetration testers
and, unfortunately, also by malicious attackers, who can use them to gain access to various types of applications.
Furthermore, in many situations, when a new account is created on an application, a default password (with some
standard characteristics) is generated. If this password is predictable and the user does not change it on the first
access, this can lead to an attacker gaining unauthorized access to the application.
The root cause of this problem can be identified as:
Inexperienced IT personnel, who are unaware of the importance of changing default passwords on installed
infrastructure components, or leave the password as default for "ease of maintenance".
Programmers who leave back doors to easily access and test their application and later forget to remove them.
Applications with built-in non-removable default accounts with a preset username and password.
Applications that do not force the user to change the default credentials after the first log in.

Test Objectives
Enumerate the applications for default credentials and validate if they still exist.
Review and assess new user accounts and if they are created with any defaults or identifiable patterns.

How to Test
Testing for Default Credentials of Common Applications
In black-box testing the tester knows nothing about the application and its underlying infrastructure. In reality this is
often not true, and some information about the application is known. We suppose that you have identified, through the
use of the techniques described in this Testing Guide under the chapter Information Gathering, at least one or more
common applications that may contain accessible administrative interfaces.
When you have identified an application interface, for example a Cisco router web interface or a WebLogic
administrator portal, check that the known usernames and passwords for these devices do not result in successful
authentication. To do this you can consult the manufacturer's documentation or, in a much simpler way, you can find
common credentials using a search engine or by using one of the sites or tools listed in the Reference section.
When facing applications where we do not have a list of default and common user accounts (for example due to the fact
that the application is not wide spread) we can attempt to guess valid default credentials. Note that the application
being tested may have an account lockout policy enabled, and multiple password guess attempts with a known
username may cause the account to be locked. If it is possible to lock the administrator account, it may be troublesome
for the system administrator to reset it.

Many applications have verbose error messages that inform the site users as to the validity of entered usernames. This
information will be helpful when testing for default or guessable user accounts. Such functionality can be found, for
example, on the log in page, password reset and forgotten password page, and sign up page. Once you have found a
default username you could also start guessing passwords for this account.
More information about this procedure can be found in the following sections:
Testing for User Enumeration and Guessable User Account
Testing for Weak password policy.
Since these types of default credentials are often bound to administrative accounts you can proceed in this manner:
Try the following usernames - "admin", "administrator", "root", "system", "guest", "operator", or "super". These are
popular among system administrators and are often used. Additionally you could try "qa", "test", "test1", "testing"
and similar names. Attempt any combination of the above in both the username and the password fields. If the
application is vulnerable to username enumeration, and you manage to successfully identify any of the above
usernames, attempt passwords in a similar manner. In addition try an empty password or one of the following
"password", "pass123", "password123", "admin", or "guest" with the above accounts or any other enumerated
accounts. Further permutations of the above can also be attempted. If these passwords fail, it may be worth using a
common username and password list and attempting multiple requests against the application. This can, of course,
be scripted to save time.
Application administrative users are often named after the application or organization. This means if you are
testing an application named "Obscurity", try using obscurity/obscurity or any other similar combination as the
username and password.
When performing a test for a customer, attempt using names of contacts you have received as usernames with any
common passwords. Customer email addresses mail reveal the user accounts naming convention: if employee
"John Doe" has the email address jdoe@example.com , you can try to find the names of system administrators on
social media and guess their username by applying the same naming convention to their name.
Attempt using all the above usernames with blank passwords.
Review the page source and JavaScript either through a proxy or by viewing the source. Look for any references to
users and passwords in the source. For example If username='admin' then starturl=/admin.asp else
/index.asp (for a successful log in versus a failed log in). Also, if you have a valid account, then log in and view
every request and response for a valid log in versus an invalid log in, such as additional hidden parameters,
interesting GET request (login=yes), etc.
Look for account names and passwords written in comments in the source code. Also look in backup directories for
source code (or backups of source code) that may contain interesting comments and code.

Testing for Default Password of New Accounts
It can also occur that when a new account is created in an application the account is assigned a default password. This
password could have some standard characteristics making it predictable. If the user does not change it on first usage
(this often happens if the user is not forced to change it) or if the user has not yet logged on to the application, this can
lead an attacker to gain unauthorized access to the application.
The advice given before about a possible lockout policy and verbose error messages are also applicable here when
testing for default passwords.
The following steps can be applied to test for these types of default credentials:
Looking at the User Registration page may help to determine the expected format and minimum or maximum
length of the application usernames and passwords. If a user registration page does not exist, determine if the
organization uses a standard naming convention for usernames such as their email address or the name before
the @ in the email.
Try to extrapolate from the application how usernames are generated. For example, can a user choose their own
username or does the system generate an account name for the user based on some personal information or by

using a predictable sequence? If the application does generate the account names in a predictable sequence,
such as user7811 , try fuzzing all possible accounts recursively. If you can identify a different response from the
application when using a valid username and a wrong password, then you can try a brute force attack on the valid
username (or quickly try any of the identified common passwords above or in the reference section).
Try to determine if the system generated password is predictable. To do this, create many new accounts quickly
after one another so that you can compare and determine if the passwords are predictable. If predictable, try to
correlate these with the usernames, or any enumerated accounts, and use them as a basis for a brute force attack.
If you have identified the correct naming convention for the user name, try to "brute force" passwords with some
common predictable sequence like for example dates of birth.
Attempt using all the above usernames with blank passwords or using the username also as password value.
Gray-Box Testing
The following steps rely on an entirely gray-box approach. If only some of this information is available to you, refer to
black-box testing to fill the gaps.
Talk to the IT personnel to determine which passwords they use for administrative access and how administration
of the application is undertaken.
Ask IT personnel if default passwords are changed and if default user accounts are disabled.
Examine the user database for default credentials as described in the black-box testing section. Also check for
empty password fields.
Examine the code for hard coded usernames and passwords.
Check for configuration files that contain usernames and passwords.
Examine the password policy and, if the application generates its own passwords for new users, check the policy
in use for this procedure.

Tools
Burp Intruder
THC Hydra
Nikto 2

References
CIRT

---

## WSTG-ATHN-03

**Testing for Weak Lock Out Mechanism**

Summary
Account lockout mechanisms are used to mitigate brute force attacks. Some of the attacks that can be defeated by
using lockout mechanism:
Login password or username guessing attack.
Code guessing on any 2FA functionality or Security Questions.
Account lockout mechanisms require a balance between protecting accounts from unauthorized access and protecting
users from being denied authorized access. Accounts are typically locked after 3 to 5 unsuccessful attempts and can
only be unlocked after a predetermined period of time, via a self-service unlock mechanism, or intervention by an
administrator.
Despite it being easy to conduct brute force attacks, the result of a successful attack is dangerous as the attacker will
have full access on the user account and with it all the functionality and services they have access to.

Test Objectives
Evaluate the account lockout mechanism's ability to mitigate brute force password guessing.
Evaluate the unlock mechanism's resistance to unauthorized account unlocking.

How to Test
Lockout Mechanism
To test the strength of lockout mechanisms, you will need access to an account that you are willing or can afford to lock.
If you have only one account with which you can log on to the web application, perform this test at the end of your test
plan to avoid losing testing time by being locked out.
To evaluate the account lockout mechanism's ability to mitigate brute force password guessing, attempt an invalid log
in by using the incorrect password a number of times, before using the correct password to verify that the account was
locked out. An example test may be as follows:
1. Attempt to log in with an incorrect password 3 times.
2. Successfully log in with the correct password, thereby showing that the lockout mechanism doesn't trigger after 3
incorrect authentication attempts.
3. Attempt to log in with an incorrect password 4 times.
4. Successfully log in with the correct password, thereby showing that the lockout mechanism doesn't trigger after 4
incorrect authentication attempts.
5. Attempt to log in with an incorrect password 5 times.
6. Attempt to log in with the correct password. The application returns "Your account is locked out.", thereby
confirming that the account is locked out after 5 incorrect authentication attempts.
7. Attempt to log in with the correct password 5 minutes later. The application returns "Your account is locked out.",
thereby showing that the lockout mechanism does not automatically unlock after 5 minutes.
8. Attempt to log in with the correct password 10 minutes later. The application returns "Your account is locked out.",
thereby showing that the lockout mechanism does not automatically unlock after 10 minutes.

9. Successfully log in with the correct password 15 minutes later, thereby showing that the lockout mechanism
automatically unlocks after a 10 to 15 minute period.
A CAPTCHA may hinder brute force attacks, but they can come with their own set of weaknesses, and should not
replace a lockout mechanism. A CAPTCHA mechanism may be bypassed if implemented incorrectly. CAPTCHA flaws
include:
1. Easily defeated challenge, such as arithimetic or limited question set.
2. CAPTCHA checks for HTTP response code instead of response success.
3. CAPTCHA server-side logic defaults to a successful solve.
4. CAPTCHA challenge result is never validated server-side.
5. CAPTCHA input field or parameter is manually processed, and is improperly validated or escaped.
To evaluate CAPTCHA effectiveness:
1. Assess CAPTCHA challenges and attempt automating solutions depending on difficulty.
2. Attempt to submit request without solving CAPTCHA via the normal UI mechanism(s).
3. Attempt to submit request with intentional CAPTCHA challenge failure.
4. Attempt to submit request without solving CAPTCHA (assuming some default values may be passed by client-side
code, etc) while using a testing proxy (request submitted directly server-side).
5. Attempt to fuzz CAPTCHA data entry points (if present) with common injection payloads or special characters
sequences.
6. Check if the solution to the CAPTCHA might be the alt-text of the image(s), filename(s), or a value in an associated
hidden field.
7. Attempt to re-submit previously identified known good responses.
8. Check if clearing cookies causes the CAPTCHA to be bypassed (for example if the CAPTCHA is only shown after a
number of failures).
9. If the CAPTCHA is part of a multi-step process, attempt to simply access or complete a step beyond the CAPTCHA
(for example if CAPTCHA is the first step in a login process, try simply submitting the second step [username and
password]).
10. Check for alternative methods that might not have CAPTCHA enforced, such as an API endpoint meant to facilitate
mobile app access.
Repeat this process to every possible functionality that could require a lockout mechanism.

Unlock Mechanism
To evaluate the unlock mechanism's resistance to unauthorized account unlocking, initiate the unlock mechanism and
look for weaknesses. Typical unlock mechanisms may involve secret questions or an emailed unlock link. The unlock
link should be a unique one-time link, to stop an attacker from guessing or replaying the link and performing brute force
attacks in batches.
Note that an unlock mechanism should only be used for unlocking accounts. It is not the same as a password recovery
mechanism, yet could follow the same security practices.

Remediation
Apply account unlock mechanisms depending on the risk level. In order from lowest to highest assurance:
1. Time-based lockout and unlock.
2. Self-service unlock (sends unlock email to registered email address).
3. Manual administrator unlock.
4. Manual administrator unlock with positive user identification.

Factors to consider when implementing an account lockout mechanism:
1. What is the risk of brute force password guessing against the application?
2. Is a CAPTCHA sufficient to mitigate this risk?
3. Is a client-side lockout mechanism being used (e.g., JavaScript)? (If so, disable the client-side code to test.)
4. Number of unsuccessful log in attempts before lockout. If the lockout threshold is to low then valid users may be
locked out too often. If the lockout threshold is to high then the more attempts an attacker can make to brute force
the account before it will be locked. Depending on the application's purpose, a range of 5 to 10 unsuccessful
attempts is typical lockout threshold.
5. How will accounts be unlocked?
i. Manually by an administrator: this is the most secure lockout method, but may cause inconvenience to users
and take up the administrator's "valuable" time.
a. Note that the administrator should also have a recovery method in case his account gets locked.
b. This unlock mechanism may lead to a denial-of-service attack if an attacker's goal is to lock the accounts
of all users of the web application.
ii. After a period of time: What is the lockout duration? Is this sufficient for the application being protected? E.g. a
5 to 30 minute lockout duration may be a good compromise between mitigating brute force attacks and
inconveniencing valid users.
iii. Via a self-service mechanism: As stated before, this self-service mechanism must be secure enough to avoid
that the attacker can unlock accounts himself.

References
See the OWASP article on Brute Force Attacks.
Forgot Password CS.

---

## WSTG-ATHN-04

**Testing for Bypassing Authentication Schema**

Summary
In computer security, authentication is the process of attempting to verify the digital identity of the sender of a
communication. A common example of such a process is the log on process. Testing the authentication schema means
understanding how the authentication process works and using that information to circumvent the authentication
mechanism.
While most applications require authentication to gain access to private information or to execute tasks, not every
authentication method is able to provide adequate security. Negligence, ignorance, or simple understatement of
security threats often result in authentication schemes that can be bypassed by simply skipping the log in page and
directly calling an internal page that is supposed to be accessed only after authentication has been performed.
In addition, it is often possible to bypass authentication measures by tampering with requests and tricking the
application into thinking that the user is already authenticated. This can be accomplished either by modifying the given
URL parameter, by manipulating the form, or by counterfeiting sessions.
Problems related to the authentication schema can be found at different stages of the software development life cycle
(SDLC), like the design, development, and deployment phases:
In the design phase errors can include a wrong definition of application sections to be protected, the choice of not
applying strong encryption protocols for securing the transmission of credentials, and many more.
In the development phase errors can include the incorrect implementation of input validation functionality or not
following the security best practices for the specific language.
In the application deployment phase, there may be issues during the application setup (installation and
configuration activities) due to a lack in required technical skills or due to the lack of good documentation.

Test Objectives
Ensure that authentication is applied across all services that require it.

How to Test
Black-Box Testing
There are several methods of bypassing the authentication schema that is used by a web application:
Direct page request (forced browsing)
Parameter modification
Session ID prediction
SQL injection
Direct Page Request
If a web application implements access control only on the log in page, the authentication schema could be bypassed.
For example, if a user directly requests a different page via forced browsing, that page may not check the credentials of
the user before granting access. Attempt to directly access a protected page through the address bar in your browser to
test using this method.

Figure 4.4.4-1: Direct Request to Protected Page

Parameter Modification
Another problem related to authentication design is when the application verifies a successful log in on the basis of a
fixed value parameters. A user could modify these parameters to gain access to the protected areas without providing
valid credentials. In the example below, the "authenticated" parameter is changed to a value of "yes", which allows the
user to gain access. In this example, the parameter is in the URL, but a proxy could also be used to modify the
parameter, especially when the parameters are sent as form elements in a POST request or when the parameters are
stored in a cookie.

http://www.site.com/page.asp?authenticated=no
raven@blackbox /home $nc www.site.com 80
GET /page.asp?authenticated=yes HTTP/1.0
HTTP/1.1 200 OK
Date: Sat, 11 Nov 2006 10:22:44 GMT
Server: Apache
Connection: close
Content-Type: text/html; charset=iso-8859-1
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<HTML><HEAD>
</HEAD><BODY>
<H1>You Are Authenticated</H1>
</BODY></HTML>

Figure 4.4.4-2: Parameter Modified Request

Session ID Prediction
Many web applications manage authentication by using session identifiers (session IDs). Therefore, if session ID
generation is predictable, a malicious user could be able to find a valid session ID and gain unauthorized access to the
application, impersonating a previously authenticated user.
In the following figure, values inside cookies increase linearly, so it could be easy for an attacker to guess a valid
session ID.

Figure 4.4.4-3: Cookie Values Over Time

In the following figure, values inside cookies change only partially, so it's possible to restrict a brute force attack to the
defined fields shown below.

Figure 4.4.4-4: Partially Changed Cookie Values

SQL Injection (HTML Form Authentication)
SQL Injection is a widely known attack technique. This section is not going to describe this technique in detail as there
are several sections in this guide that explain injection techniques beyond the scope of this section.

Figure 4.4.4-5: SQL Injection

The following figure shows that with a simple SQL injection attack, it is sometimes possible to bypass the authentication
form.

Figure 4.4.4-6: Simple SQL Injection Attack

Gray-Box Testing
If an attacker has been able to retrieve the application source code by exploiting a previously discovered vulnerability
(e.g., directory traversal), or from a web repository (Open Source Applications), it could be possible to perform refined
attacks against the implementation of the authentication process.
In the following example (PHPBB 2.0.13 - Authentication Bypass Vulnerability), at line 5 the unserialize() function
parses a user supplied cookie and sets values inside the $row array. At line 10 the user's MD5 password hash stored
inside the back end database is compared to the one supplied.

if (isset($HTTP_COOKIE_VARS[$cookiename . '_sid']) {
$sessiondata = isset($HTTP_COOKIE_VARS[$cookiename . '_data']) ?
unserialize(stripslashes($HTTP_COOKIE_VARS[$cookiename . '_data'])) : array();
$sessionmethod = SESSION_METHOD_COOKIE;
}
if(md5($password) == $row['user_password'] && $row['user_active']) {
$autologin = (isset($HTTP_POST_VARS['autologin'])) ? TRUE : 0;
}

In PHP, a comparison between a string value and a boolean value (1 and TRUE ) is always TRUE , so by supplying the
following string (the important part is b:1 ) to the unserialize() function, it is possible to bypass the authentication
control:

a:2:{s:11:"autologinid";b:1;s:6:"userid";s:1:"2";}

Tools
WebGoat
OWASP Zed Attack Proxy (ZAP)

References
Whitepapers
Mark Roxberry: "PHPBB 2.0.13 vulnerability"
David Endler: "Session ID Brute Force Exploitation and Prediction"

---

## WSTG-ATHN-05

**Testing for Vulnerable Remember Password**

Summary
Credentials are the most widely used authentication technology. Due to such a wide usage of username-password
pairs, users are no longer able to properly handle their credentials across the multitude of used applications.
In order to assist users with their credentials, multiple technologies surfaced:
Applications provide a remember me functionality that allows the user to stay authenticated for long periods of
time, without asking the user again for their credentials.
Password Managers - including browser password managers - that allow the user to store their credentials in a
secure manner and later on inject them in user-forms without any user intervention.

Test Objectives
Validate that the generated session is managed securely and do not put the user's credentials in danger.

How to Test
As these methods provide a better user experience and allow the user to forget all about their credentials, they
increase the attack surface area. Some applications:
Store the credentials in an encoded fashion in the browser's storage mechanisms, which can be verified by
following the web storage testing scenario and going through the session analysis scenarios. Credentials
shouldn't be stored in any way in the client-side application, and should be substitued by tokens generated serverside.
Automatically inject the user's credentials that can be abused by:
ClickJacking attacks.
CSRF attacks.
Tokens should be analyzed in terms of token-lifetime, where some tokens never expire and put the users in danger
if those tokens ever get stolen. Make sure to follow the session timeout testing scenario.

Remediation
Follow session management good practices.
Ensure that no credentials are stored in clear text or are easily retrievable in encoded or encrypted forms in
browser storage mechanisms; they should be stored server-side and follow good password storage practices.

---

## WSTG-ATHN-06

**Testing for Browser Cache Weaknesses**

Summary
In this phase the tester checks that the application correctly instructs the browser to not retain sensitive data.
Browsers can store information for purposes of caching and history. Caching is used to improve performance, so that
previously displayed information doesn't need to be downloaded again. History mechanisms are used for user
convenience, so the user can see exactly what they saw at the time when the resource was retrieved. If sensitive
information is displayed to the user (such as their address, credit card details, Social Security Number, or username),
then this information could be stored for purposes of caching or history, and therefore retrievable through examining the
browser's cache or by simply pressing the browser's Back button.

Test Objectives
Review if the application stores sensitive information on the client-side.
Review if access can occur without authorization.

How to Test
Browser History
Technically, the Back button is a history and not a cache (see Caching in HTTP: History Lists). The cache and the
history are two different entities. However, they share the same weakness of presenting previously displayed sensitive
information.
The first and simplest test consists of entering sensitive information into the application and logging out. Then the tester
clicks the Back button of the browser to check whether previously displayed sensitive information can be accessed
whilst unauthenticated.
If by pressing the Back button the tester can access previous pages but not access new ones, then it is not an
authentication issue, but a browser history issue. If these pages contain sensitive data, it means that the application did
not forbid the browser from storing it.
Authentication does not necessarily need to be involved in the testing. For example, when a user enters their email
address in order to sign up to a newsletter, this information could be retrievable if not properly handled.
The Back button can be stopped from showing sensitive data. This can be done by:
Delivering the page over HTTPS.
Setting Cache-Control: must-revalidate

Browser Cache
Here testers check that the application does not leak any sensitive data into the browser cache. In order to do that, they
can use a proxy (such as OWASP ZAP) and search through the server responses that belong to the session, checking
that for every page that contains sensitive information the server instructed the browser not to cache any data. Such a
directive can be issued in the HTTP response headers with the following directives:
Cache-Control: no-cache, no-store
Expires: 0

Pragma: no-cache

These directives are generally robust, although additional flags may be necessary for the Cache-Control header in
order to better prevent persistently linked files on the file system. These include:
Cache-Control: must-revalidate, max-age=0, s-maxage=0

HTTP/1.1:
Cache-Control: no-cache

HTTP/1.0:
Pragma: no-cache
Expires: "past date or illegal value (e.g., 0)"

For instance, if testers are testing an e-commerce application, they should look for all pages that contain a credit card
number or some other financial information, and check that all those pages enforce the no-cache directive. If they find
pages that contain critical information but that fail to instruct the browser not to cache their content, they know that
sensitive information will be stored on the disk, and they can double-check this simply by looking for the page in the
browser cache.
The exact location where that information is stored depends on the client operating system and on the browser that has
been used. Here are some examples:
Mozilla Firefox:
Unix/Linux: ~/.cache/mozilla/firefox/
Windows: C:\Users\<user_name>\AppData\Local\Mozilla\Firefox\Profiles\<profile-id>\Cache2\
Internet Explorer:
C:\Users\<user_name>\AppData\Local\Microsoft\Windows\INetCache\

Chrome:
Windows: C:\Users\<user_name>\AppData\Local\Google\Chrome\User Data\Default\Cache
Unix/Linux: ~/.cache/google-chrome
Reviewing Cached Information
Firefox provides functionality for viewing cached information, which may be to your benefit as a tester. Of course the
industry has also produced various extensions, and external apps which you may prefer or need for Chrome, Internet
Explorer, or Edge.
Cache details are also available via developer tools in most modern browsers, such as Firefox, Chrome, and Edge.
With Firefox it is also possible to use the URL about:cache to check cache details.
Check Handling for Mobile Browsers
Handling of cache directives may be completely different for mobile browsers. Therefore, testers should start a new
browsing session with clean caches and take advantage of features like Chrome's Device Mode or Firefox's
Responsive Design Mode to re-test or separately test the concepts outlined above.
Additionally, personal proxies such as ZAP and Burp Suite allow the tester to specify which User-Agent should be
sent by their spiders/crawlers. This could be set to match a mobile browser User-Agent string and used to see which
caching directives are sent by the application being tested.

Gray-Box Testing
The methodology for testing is equivalent to the black-box case, as in both scenarios testers have full access to the
server response headers and to the HTML code. However, with gray-box testing, the tester may have access to account

credentials that will allow them to test sensitive pages that are accessible only to authenticated users.

Tools
OWASP Zed Attack Proxy

References
Whitepapers
Caching in HTTP

---

## WSTG-ATHN-07

**Testing for Weak Password Policy**

Summary
The most prevalent and most easily administered authentication mechanism is a static password. The password
represents the keys to the kingdom, but is often subverted by users in the name of usability. In each of the recent high
profile hacks that have revealed user credentials, it is lamented that most common passwords are still: 123456 ,
password and qwerty .

Test Objectives
Determine the resistance of the application against brute force password guessing using available password
dictionaries by evaluating the length, complexity, reuse, and aging requirements of passwords.

How to Test
1. What characters are permitted and forbidden for use within a password? Is the user required to use characters
from different character sets such as lower and uppercase letters, digits and special symbols?
2. How often can a user change their password? How quickly can a user change their password after a previous
change? Users may bypass password history requirements by changing their password 5 times in a row so that
after the last password change they have configured their initial password again.
3. When must a user change their password?
Both NIST and NCSC recommend against forcing regular password expiry, although it may be required by
standards such as PCI DSS.
4. How often can a user reuse a password? Does the application maintain a history of the user's previous used 8
passwords?
5. How different must the next password be from the last password?
6. Is the user prevented from using his username or other account information (such as first or last name) in the
password?
7. What are the minimum and maximum password lengths that can be set, and are they appropriate for the sensitivity
of the account and application?
8. Is it possible set common passwords such as Password1 or 123456 ?

Remediation
To mitigate the risk of easily guessed passwords facilitating unauthorized access there are two solutions: introduce
additional authentication controls (i.e. two-factor authentication) or introduce a strong password policy. The simplest
and cheapest of these is the introduction of a strong password policy that ensures password length, complexity, reuse
and aging; although ideally both of them should be implemented.

References
Brute Force Attacks

---

## WSTG-ATHN-08

**Testing for Weak Security Question Answer**

Summary
Often called "secret" questions and answers, security questions and answers are often used to recover forgotten
passwords (see Testing for weak password change or reset functionalities, or as extra security on top of the password.
They are typically generated upon account creation and require the user to select from some pre-generated questions
and supply an appropriate answer. They may allow the user to generate their own question and answer pairs. Both
methods are prone to insecurities.Ideally, security questions should generate answers that are only known by the user,
and not guessable or discoverable by anybody else. This is harder than it sounds. Security questions and answers rely
on the secrecy of the answer. Questions and answers should be chosen so that the answers are only known by the
account holder. However, although a lot of answers may not be publicly known, most of the questions that websites
implement promote answers that are pseudo-private.

Pre-generated Questions
The majority of pre-generated questions are fairly simplistic in nature and can lead to insecure answers. For example:
The answers may be known to family members or close friends of the user, e.g. "What is your mother's maiden
name?", "What is your date of birth?"
The answers may be easily guessable, e.g. "What is your favorite color?", "What is your favorite baseball team?"
The answers may be brute forcible, e.g. "What is the first name of your favorite high school teacher?" - the answer
is probably on some easily downloadable lists of popular first names, and therefore a simple brute force attack can
be scripted.
The answers may be publicly discoverable, e.g. "What is your favorite movie?" - the answer may easily be found on
the user's social media profile page.

Self-generated Questions
The problem with having users to generate their own questions is that it allows them to generate very insecure
questions, or even bypass the whole point of having a security question in the first place. Here are some real world
examples that illustrate this point:
"What is 1+1?"
"What is your username?"
"My password is S3cur|ty!"

Test Objectives
Determine the complexity and how straight-forward the questions are.
Assess possible user answers and brute force capabilities.

How to Test
Testing for Weak Pre-generated Questions
Try to obtain a list of security questions by creating a new account or by following the "I don't remember my password"process. Try to generate as many questions as possible to get a good idea of the type of security questions that are
asked. If any of the security questions fall in the categories described above, they are vulnerable to being attacked
(guessed, brute-forced, available on social media, etc.).

Testing for Weak Self-Generated Questions
Try to create security questions by creating a new account or by configuring your existing account's password recovery
properties. If the system allows the user to generate their own security questions, it is vulnerable to having insecure
questions created. If the system uses the self-generated security questions during the forgotten password functionality
and if usernames can be enumerated (see Testing for Account Enumeration and Guessable User Account, then it
should be easy for the tester to enumerate a number of self-generated questions. It should be expected to find several
weak self-generated questions using this method.

Testing for Brute-forcible Answers
Use the methods described in Testing for Weak lock out mechanism to determine if a number of incorrectly supplied
security answers trigger a lockout mechanism.
The first thing to take into consideration when trying to exploit security questions is the number of questions that need to
be answered. The majority of applications only need the user to answer a single question, whereas some critical
applications may require the user to answer two or even more questions.
The next step is to assess the strength of the security questions. Could the answers be obtained by a simple Google
search or with social engineering attack? As a penetration tester, here is a step-by-step walkthrough of exploiting a
security question scheme:
Does the application allow the end user to choose the question that needs to be answered? If so, focus on
questions which have:
A "public" answer; for example, something that could be find with a simple search-engine query.
A factual answer such as a "first school" or other facts which can be looked up.
Few possible answers, such as "what model was your first car". These questions would present the attacker
with a short list of possible answers, and based on statistics the attacker could rank answers from most to least
likely.
Determine how many guesses you have if possible.
Does the password reset allow unlimited attempts?
Is there a lockout period after X incorrect answers? Keep in mind that a lockout system can be a security
problem in itself, as it can be exploited by an attacker to launch a Denial of Service against legitimate users.
Pick the appropriate question based on analysis from the above points, and do research to determine the most
likely answers.
The key to successfully exploiting and bypassing a weak security question scheme is to find a question or set of
questions which give the possibility of easily finding the answers. Always look for questions which can give you the
greatest statistical chance of guessing the correct answer, if you are completely unsure of any of the answers. In the
end, a security question scheme is only as strong as the weakest question.

References
The Curse of the Secret Question
The OWASP Security Questions Cheat Sheet

---

## WSTG-ATHN-09

**Testing for Weak Password Change or Reset Functionalities**

Summary
The password change and reset function of an application is a self-service password change or reset mechanism for
users. This self-service mechanism allows users to quickly change or reset their password without an administrator
intervening. When passwords are changed they are typically changed within the application. When passwords are
reset they are either rendered within the application or emailed to the user. This may indicate that the passwords are
stored in plain text or in a decryptable format.

Test Objectives
Determine the resistance of the application to subversion of the account change process allowing someone to
change the password of an account.
Determine the resistance of the passwords reset functionality against guessing or bypassing.

How to Test
For both password change and password reset it is important to check:
1. if users, other than administrators, can change or reset passwords for accounts other than their own.
2. if users can manipulate or subvert the password change or reset process to change or reset the password of
another user or administrator.
3. if the password change or reset process is vulnerable to CSRF.

Test Password Reset
In addition to the previous checks it is important to verify the following:
What information is required to reset the password?
The first step is to check whether secret questions are required. Sending the password (or a password reset link) to
the user email address without first asking for a secret question means relying 100% on the security of that email
address, which is not suitable if the application needs a high level of security.
On the other hand, if secret questions are used, the next step is to assess their strength. This specific test is
discussed in detail in the Testing for Weak security question/answer paragraph of this guide.
How are reset passwords communicated to the user?
The most insecure scenario here is if the password reset tool shows you the password; this gives the attacker the
ability to log into the account, and unless the application provides information about the last log in the victim would
not know that their account has been compromised.
A less insecure scenario is if the password reset tool forces the user to immediately change their password. While
not as stealthy as the first case, it allows the attacker to gain access and locks the real user out.
The best security is achieved if the password reset is done via an email to the address the user initially registered
with, or some other email address; this forces the attacker to not only guess at which email account the password

reset was sent to (unless the application show this information) but also to compromise that email account in order
to obtain the temporary password or the password reset link.
Are reset passwords generated randomly?
The most insecure scenario here is if the application sends or visualizes the old password in clear text because
this means that passwords are not stored in a hashed form, which is a security issue in itself.
The best security is achieved if passwords are randomly generated with a secure algorithm that cannot be derived.
Is the reset password functionality requesting confirmation before changing the password?
To limit denial-of-service attacks the application should email a link to the user with a random token, and only if the
user visits the link then the reset procedure is completed. This ensures that the current password will still be valid
until the reset has been confirmed.

Test Password Change
In addition to the previous test it is important to verify:
Is the old password requested to complete the change?
The most insecure scenario here is if the application permits the change of the password without requesting the
current password. Indeed if an attacker is able to take control of a valid session they could easily change the
victim's password. See also Testing for Weak password policy paragraph of this guide.

Remediation
The password change or reset function is a sensitive function and requires some form of protection, such as requiring
users to re-authenticate or presenting the user with confirmation screens during the process.

References
OWASP Forgot Password Cheat Sheet

---

## WSTG-ATHN-10

**Testing for Weaker Authentication in Alternative Channel**

Summary
Even if the primary authentication mechanisms do not include any vulnerabilities, it may be that vulnerabilities exist in
alternative legitimate authentication user channels for the same user accounts. Tests should be undertaken to identify
alternative channels and, subject to test scoping, identify vulnerabilities.
The alternative user interaction channels could be utilized to circumvent the primary channel, or expose information
that can then be used to assist an attack against the primary channel. Some of these channels may themselves be
separate web applications using different hostnames or paths. For example:
Standard website
Mobile, or specific device, optimized website
Accessibility optimized website
Alternative country and language websites
Parallel websites that utilize the same user accounts (e.g. another website offering different functionally of the
same organization, a partner website with which user accounts are shared)
Development, test, UAT and staging versions of the standard website
But they could also be other types of application or business processes:
Mobile device app
Desktop application
Call center operators
Interactive voice response or phone tree systems
Note that the focus of this test is on alternative channels; some authentication alternatives might appear as different
content delivered via the same website and would almost certainly be in scope for testing. These are not discussed
further here, and should have been identified during information gathering and primary authentication testing. For
example:
Progressive enrichment and graceful degradation that change functionality
Site use without cookies
Site use without JavaScript
Site use without plugins such as for Flash and Java
Even if the scope of the test does not allow the alternative channels to be tested, their existence should be
documented. These may undermine the degree of assurance in the authentication mechanisms and may be a
precursor to additional testing.

Example
The primary website is http://www.example.com and authentication functions always take place on pages using TLS
https://www.example.com/myaccount/ .
However, a separate mobile-optimized website exists that does not use TLS at all, and has a weaker password
recovery mechanism http://m.example.com/myaccount/ .

Test Objectives
Identify alternative authentication channels.
Assess the security measures used and if any bypasses exists on the alternative channels.

How to Test
Understand the Primary Mechanism
Fully test the website's primary authentication functions. This should identify how accounts are issued, created or
changed and how passwords are recovered, reset, or changed. Additionally knowledge of any elevated privilege
authentication and authentication protection measures should be known. These precursors are necessary to be able to
compare with any alternative channels.

Identify Other Channels
Other channels can be found by using the following methods:
Reading site content, especially the home page, contact us, help pages, support articles and FAQs, T&Cs, privacy
notices, the robots.txt file and any sitemap.xml files.
Searching HTTP proxy logs, recorded during previous information gathering and testing, for strings such as
"mobile", "android", blackberry", "ipad", "iphone", "mobile app", "e-reader", "wireless", "auth", "sso", "single sign on"
in URL paths and body content.
Use search engines to find different websites from the same organization, or using the same domain name, that
have similar home page content or which also have authentication mechanisms.
For each possible channel confirm whether user accounts are shared across these, or provide access to the same or
similar functionality.

Enumerate Authentication Functionality
For each alternative channel where user accounts or functionality are shared, identify if all the authentication functions
of the primary channel are available, and if anything extra exists. It may be useful to create a grid like the one below:
Primary

Mobile

Call Center

Partner Website

Register

Yes

-

-

Log in

Yes

Yes

Yes(SSO)

Log out

-

-

-

Password reset

Yes

Yes

-

-

Change password

-

-

In this example, mobile has an extra function "change password" but does not offer "log out". A limited number of tasks
are also possible by phoning the call center. Call centers can be interesting, because their identity confirmation checks
might be weaker than the website's, allowing this channel to be used to aid an attack against a user's account.
While enumerating these it is worth taking note of how session management is undertaken, in case there is overlap
across any channels (e.g. cookies scoped to the same parent domain name, concurrent sessions allowed across
channels, but not on the same channel).

Review and Test
Alternative channels should be mentioned in the testing report, even if they are marked as "information only" or "out of
scope". In some cases the test scope might include the alternative channel (e.g. because it is just another path on the
target host name), or may be added to the scope after discussion with the owners of all the channels. If testing is
permitted and authorized, all the other authentication tests in this guide should then be performed, and compared
against the primary channel.

Related Test Cases
The test cases for all the other authentication tests should be utilized.

Remediation
Ensure a consistent authentication policy is applied across all channels so that they are equally secure.

4.5 Authorization Testing
4.5.1 Testing Directory Traversal File Include
4.5.2 Testing for Bypassing Authorization Schema
4.5.3 Testing for Privilege Escalation
4.5.4 Testing for Insecure Direct Object References

---

