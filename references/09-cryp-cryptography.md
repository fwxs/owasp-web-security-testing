# WSTG CRYP — Cryptography

OWASP Web Security Testing Guide v4.2. 4 test cases: WSTG-CRYP-01, WSTG-CRYP-02, WSTG-CRYP-03, WSTG-CRYP-04.

## Table of Contents

- [WSTG-CRYP-01 — Testing for Weak Transport Layer Security](#wstg-cryp-01)
- [WSTG-CRYP-02 — Testing for Padding Oracle](#wstg-cryp-02)
- [WSTG-CRYP-03 — Testing for Sensitive Information Sent via Unencrypted Channels](#wstg-cryp-03)
- [WSTG-CRYP-04 — Testing for Weak Encryption](#wstg-cryp-04)

---

## WSTG-CRYP-01

**Testing for Weak Transport Layer Security**

Summary
When information is sent between the client and the server, it must be encrypted and protected in order to prevent an
attacker from being able to read or modify it. This is most commonly done using HTTPS, which uses the Transport
Layer Security (TLS) protocol, a replacement for the older Secure Socket Layer (SSL) protocol. TLS also provides a
way for the server to demonstrate to the client that they have connected to the correct server, by presenting a trusted
digital certificate.
Over the years there have been a large number of cryptographic weaknesses identified in the SSL and TLS protocols,
as well as in the ciphers that they use. Additionally, many of the implementations of these protocols have also had
serious vulnerabilities. As such, it is important to test that sites are not only implementing TLS, but that they are doing so
in a secure manner.

Test Objectives
Validate the service configuration.
Review the digital certificate's cryptographic strength and validity.
Ensure that the TLS security is not bypassable and is properly implemented across the application.

How to Test
Transport layer security related issues can be broadly split into the following areas:

Server Configuration
There are a large number of protocol versions, ciphers, and extensions supported by TLS. Many of these are
considered to be legacy, and have cryptographic weaknesses, such as those listed below. Note that new weaknesses
are likely to be identified over time, so this list may be incomplete.
SSLv2 (DROWN)
SSLv3 (POODLE)
TLSv1.0 (BEAST)
EXPORT ciphers suites (FREAK)
NULL ciphers (they only provide authentication).
Anonymous ciphers (these may be supported on SMTP servers, as discussed in RFC 7672)
RC4 ciphers (NOMORE)
CBC mode ciphers (BEAST, Lucky 13)
TLS compression (CRIME)
Weak DHE keys (LOGJAM)
The Mozilla Server Side TLS Guide details the protocols and ciphers that are currently recommended.
Exploitability
It should be emphasised that while many of these attacks have been demonstrated in a lab environment, they are not
generally considered practical to exploit in the real world, as they require a (usually active) MitM attack, and significant
resources. As such, they are unlikely to be exploited by anyone other than nation states.

Digital Certificates
Cryptographic Weaknesses
From a cryptographic perspective, there are two main areas that need to be reviewed on a digital certificate:
The key strength should be at least 2048 bits.
The signature algorithm should be at least SHA-256. Legacy algorithms such as MD5 and SHA-1 should not be
used.
Validity
As well as being cryptographically secure, the certificate must also be considered valid (or trusted). This means that it
must:
Be within the defined validity period.
Any certificates issued after 1st September 2020 must not have a maximum lifespan of more than 398 days.
Be signed by a trusted certificate authority (CA).
This should either be a trusted public CA for externally facing applications, or an internal CA for internal
applications.
Don't flag internal applications as having untrusted certificates just because your system doesn't trust the CA.
Have a Subject Alternate Name (SAN) that matches the hostname of the system.
The Common Name (CN) field is ignored by modern browsers, which only look at the SAN.
Make sure that you're accessing the system with the correct name (for example, if you access the host by IP
then any certificate will be appear untrusted).
Some certificates may be issued for wildcard domains (such as *.example.org ), meaning that they can be valid for
multiple subdomains. Although convenient, there are a number of security concerns around this that should be
considered. These are discussed in the OWASP Transport Layer Security Cheat Sheet.
Certificates can also leak information about internal systems or domain names in the Issuer and SAN fields, which can
be useful when trying to build up a picture of the internal network or conduct social engineering activities.

Implementation Vulnerabilities
Over the years there have been vulnerabilities in the various TLS implementations. There are too many to list here, but
some of the key examples are:
Debian OpenSSL Predictable Random Number Generator (CVE-2008-0166)
OpenSSL Insecure Renegotiation (CVE-2009-3555)
OpenSSL Heartbleed (CVE-2014-0160)
F5 TLS POODLE (CVE-2014-8730)
Microsoft Schannel Denial of Service (MS14-066 / CVE CVE-2014-6321)

Application Vulnerabilities
As well as the underlying TLS configuration being securely configured, the application also needs to use it in a secure
way. Some of these points are addressed elsewhere in this guide:
Not sending sensitive data over unencrypted channels (WSTG-CRYP-03)
Setting the HTTP Strict-Transport-Security header (WSTG-CONF-07)
Setting the Secure flag on cookies (WSTG-SESS-02)
Mixed Active Content
Mixed active content is when active resources (such as scripts to CSS) are loaded over unencrypted HTTP and
included into a secure (HTTPS) page. This is dangerous because it would allow an attacker to modify these files (as
they are sent unencrypted), which could allow them to execute arbitrary code (JavaScript or CSS) in the page. Passive

content (such as images) loaded over an insecure connection can also leak information or allow an attacker to deface
the page, although it is less likely to lead to a full compromise.
Note: modern browsers will block active content being loaded from insecure sources into secure pages.
Redirecting from HTTP to HTTPS
Many sites will accept connections over unencrypted HTTP, and then immediately redirect the user to the secure
(HTTPS) version of the site with a 301 Moved Permanently redirect. The HTTPS version of the site then sets the
Strict-Transport-Security header to instruct the browser to always use HTTPS in future.
However, if an attacker is able to intercept this initial request, they could redirect the user to a malicious site, or use a
tool such as sslstrip to intercept subsequent requests.
In order to defend against this type of attack, the site must use be added to the preload list.

Automated Testing
There are a large number of scanning tools that can be used to identify weaknesses in the SSL/TLS configuration of a
service, including both dedicated tools and general purpose vulnerability scanners. Some of the more popular ones
are:
Nmap (various scripts)
OWASP O-Saft
sslscan
sslyze
SSL Labs
testssl.sh

Manual Testing
It is also possible to carry out most checks manually, using command-line looks such as openssl s_client or
gnutls-cli to connect with specific protocols, ciphers or options.

When testing like this, be aware that the version of OpenSSL or GnuTLS shipped with most modern systems may will
not support some outdated and insecure protocols such as SSLv2 or EXPORT ciphers. Make sure that your version
supports the outdated versions before using it for testing, or you'll end up with false negatives.
It can also be possible to performed limited testing using a web browser, as modern browsers will provide details of the
protocols and ciphers that are being used in their developer tools. They also provide an easy way to test whether a
certificate is considered trusted, by browsing to the service and seeing if you are presented with a certificate warning.

References
OWASP Transport Layer Protection Cheat Sheet
Mozilla Server Side TLS Guide

---

## WSTG-CRYP-02

**Testing for Padding Oracle**

Summary
A padding oracle is a function of an application which decrypts encrypted data provided by the client, e.g. internal
session state stored on the client, and leaks the state of the validity of the padding after decryption. The existence of a
padding oracle allows an attacker to decrypt encrypted data and encrypt arbitrary data without knowledge of the key
used for these cryptographic operations. This can lead to leakage of sensible data or to privilege escalation
vulnerabilities, if integrity of the encrypted data is assumed by the application.
Block ciphers encrypt data only in blocks of certain sizes. Block sizes used by common ciphers are 8 and 16 bytes.
Data where the size doesn't match a multiple of the block size of the used cipher has to be padded in a specific manner
so the decryptor is able to strip the padding. A commonly used padding scheme is PKCS#7. It fills the remaining bytes
with the value of the padding length.

Example 1
If the padding has the length of 5 bytes, the byte value 0x05 is repeated five times after the plain text.
An error condition is present if the padding doesn't match the syntax of the used padding scheme. A padding oracle is
present if an application leaks this specific padding error condition for encrypted data provided by the client. This can
happen by exposing exceptions (e.g. BadPaddingException in Java) directly, by subtle differences in the responses
sent to the client or by another side-channel like timing behavior.
Certain modes of operation of cryptography allow bit-flipping attacks, where flipping of a bit in the cipher text causes
that the bit is also flipped in the plain text. Flipping a bit in the n-th block of CBC encrypted data causes that the same bit
in the (n+1)-th block is flipped in the decrypted data. The n-th block of the decrypted cipher text is garbaged by this
manipulation.
The padding oracle attack enables an attacker to decrypt encrypted data without knowledge of the encryption key and
used cipher by sending skillful manipulated cipher texts to the padding oracle and observing of the results returned by
it. This causes loss of confidentiality of the encrypted data. E.g. in the case of session data stored on the client-side the
attacker can gain information about the internal state and structure of the application.
A padding oracle attack also enables an attacker to encrypt arbitrary plain texts without knowledge of the used key and
cipher. If the application assumes that integrity and authenticity of the decrypted data is given, an attacker could be able
to manipulate internal session state and possibly gain higher privileges.

Test Objectives
Identify encrypted messages that rely on padding.
Attempt to break the padding of the encrypted messages and analyze the returned error messages for further
analysis.

How to Test
Black-Box Testing
First the possible input points for padding oracles must be identified. Generally the following conditions must be met:
1. The data is encrypted. Good candidates are values which appear to be random.

2. A block cipher is used. The length of the decoded (Base64 is used often) cipher text is a multiple of common cipher
block sizes like 8 or 16 bytes. Different cipher texts (e.g. gathered by different sessions or manipulation of session
state) share a common divisor in the length.
Example 2
Dg6W8OiWMIdVokIDH15T/A== results after Base64 decoding in 0e 0e 96 f0 e8 96 30 87 55 a2 42 03 1f 5e 53 fc .
This seems to be random and 16 byte long.

If such an input value candidate is identified, the behavior of the application to bit-wise tampering of the encrypted
value should be verified. Normally this Base64 encoded value will include the initialization vector (IV) prepended to the
cipher text. Given a plaintext p and a cipher with a block size n , the number of blocks will be b = ceil( length(b) /
n) . The length of the encrypted string will be y=(b+1)*n due to the initialization vector. To verify the presence of the

oracle, decode the string, flip the last bit of the second-to-last block b-1 (the least significant bit of the byte at y-n-1 ),
re-encode and send. Next, decode the original string, flip the last bit of the block b-2 (the least significant bit of the
byte at y-2*n-1 ), re-encode and send.
If it is known that the encrypted string is a single block (the IV is stored on the server or the application is using a bad
practice hardcoded IV), several bit flips must be performed in turn. An alternative approach could be to prepend a
random block, and flip bits in order to make the last byte of the added block take all possible values (0 to 255).
The tests and the base value should at least cause three different states while and after decryption:
Cipher text gets decrypted, resulting data is correct.
Cipher text gets decrypted, resulting data is garbled and causes some exception or error handling in the
application logic.
Cipher text decryption fails due to padding errors.
Compare the responses carefully. Search especially for exceptions and messages which state that something is wrong
with the padding. If such messages appear, the application contains a padding oracle. If the three different states
described above are observable implicitly (different error messages, timing side-channels), there is a high probability
that there is a padding oracle present at this point. Try to perform the padding oracle attack to ensure this.
Example 3

ASP.NET throws System.Security.Cryptography.CryptographicException: Padding is invalid and cannot be
removed. if padding of a decrypted cipher text is broken.

In Java a javax.crypto.BadPaddingException is thrown in this case.
Decryption errors or similar can be possible padding oracles.
A secure implementation will check for integrity and cause only two responses: ok and failed . There are no
side channels which can be used to determine internal error states.

Gray-Box Testing
Verify that all places where encrypted data from the client, that should only be known by the server, is decrypted. The
following conditions should be met by such code:
1. The integrity of the cipher text should be verified by a secure mechanism, like HMAC or authenticated cipher
operation modes like GCM or CCM.
2. All error states while decryption and further processing are handled uniformly.

Example 4
Visualization of the decryption process

Tools
Bletchley

PadBuster
Padding Oracle Exploitation Tool (POET)
Poracle
python-paddingoracle

References
Wikepedia - Padding Oracle Attack
Juliano Rizzo, Thai Duong, "Practical Padding Oracle Attacks"

---

## WSTG-CRYP-03

**Testing for Sensitive Information Sent via Unencrypted Channels**

Summary
Sensitive data must be protected when it is transmitted through the network. If data is transmitted over HTTPS or
encrypted in another way the protection mechanism must not have limitations or vulnerabilities, as explained in the
broader article Testing for Weak Transport Layer Security and in other OWASP documentation:
OWASP Top 10 2017 A3-Sensitive Data Exposure.
OWASP ASVS - Verification V9.
Transport Layer Protection Cheat Sheet.
As a rule of thumb if data must be protected when it is stored, this data must also be protected during transmission.
Some examples for sensitive data are:
Information used in authentication (e.g. Credentials, PINs, Session identifiers, Tokens, Cookies...)
Information protected by laws, regulations or specific organizational policy (e.g. Credit Cards, Customers data)
If the application transmits sensitive information via unencrypted channels - e.g. HTTP - it is considered a security risk.
Some examples are Basic authentication which sends authentication credentials in plain-text over HTTP, form based
authentication credentials sent via HTTP, or plain-text transmission of any other information considered sensitive due to
regulations, laws, organizational policy or application business logic.
Examples for Personal Identifying Information (PII) are:
Social security numbers
Bank account numbers
Passport information
Healthcare related information
Medical insurance information
Student information
Credit and debit card numbers
Drivers license and State ID information

Test Objectives
Identify sensitive information transmitted through the various channels.
Assess the privacy and security of the channels used.

How to Test
Various types of information that must be protected, could be transmitted by the application in clear text. It is possible to
check if this information is transmitted over HTTP instead of HTTPS, or whether weak ciphers are used. See more
information about insecure transmission of credentials OWASP Top 10 2017 A3-Sensitive Data Exposure or Transport
Layer Protection Cheat Sheet.

Example 1: Basic Authentication over HTTP
A typical example is the usage of Basic Authentication over HTTP. When using Basic Authentication, user credentials
are encoded rather than encrypted, and are sent as HTTP headers. In the example below the tester uses curl to test for
this issue. Note how the application uses Basic authentication, and HTTP rather than HTTPS

$ curl -kis http://example.com/restricted/
HTTP/1.1 401 Authorization Required
Date: Fri, 01 Aug 2013 00:00:00 GMT
WWW-Authenticate: Basic realm="Restricted Area"
Accept-Ranges: bytes Vary:
Accept-Encoding Content-Length: 162
Content-Type: text/html
<html><head><title>401 Authorization Required</title></head>
<body bgcolor=white> <h1>401 Authorization Required</h1> Invalid login credentials!

</body></html>

Example 2: Form-Based Authentication Performed over HTTP
Another typical example is authentication forms which transmit user authentication credentials over HTTP. In the
example below one can see HTTP being used in the action attribute of the form. It is also possible to see this issue by
examining the HTTP traffic with an interception proxy.

<form action="http://example.com/login">
<label for="username">User:</label> <input type="text" id="username"-name="username"-value=""/>
<br />
<label for="password">Password:</label> <input type="password" id="password"-name="password"value=""/>
<input type="submit" value="Login"/>
</form>

Example 3: Cookie Containing Session ID Sent over HTTP
The Session ID Cookie must be transmitted over protected channels. If the cookie does not have the secure flag set, it
is permitted for the application to transmit it unencrypted. Note below the setting of the cookie is done without the
Secure flag, and the entire log in process is performed in HTTP and not HTTPS.

https://secure.example.com/login
POST /login HTTP/1.1
Host: secure.example.com
[...]
Referer: https://secure.example.com/
Content-Type: application/x-www-form-urlencoded
Content-Length: 188
HTTP/1.1 302 Found
Date: Tue, 03 Dec 2013 21:18:55 GMT
Server: Apache
Set-Cookie: JSESSIONID=BD99F321233AF69593EDF52B123B5BDA; expires=Fri, 01-Jan-2014 00:00:00 GMT;
path=/; domain=example.com; httponly
Location: private/
Content-Length: 0
Content-Type: text/html

http://example.com/private
GET /private HTTP/1.1
Host: example.com
[...]

Referer: https://secure.example.com/login
Cookie: JSESSIONID=BD99F321233AF69593EDF52B123B5BDA;
HTTP/1.1 200 OK
Content-Type: text/html;charset=UTF-8
Content-Length: 730
Date: Tue, 25 Dec 2013 00:00:00 GMT

Example 4: Testing Password Sensitive Information in Source Code or Logs
Use one of the following techniques to search for senstive information.
Checking if password or encyrption key is hardcoded in the source code or configuration files.
grep

-r

-E

"Pass

|

password

|

pwd

|user

|

guest|

admin

|

encry

|

key

|

decrypt

|

sharekey

"

./PathToSearch/

Checking if logs or source code may contain phone number, email address, ID or any other PII. Change the regular
expression based on the format of the PII.
grep -r " {2\}[0-9]\{6\} " ./PathToSearch/

Tools
curl
grep
Identity Finder
Wireshark
TCPDUMP

---

## WSTG-CRYP-04

**Testing for Weak Encryption**

Summary
Incorrect uses of encryption algorithms may result in sensitive data exposure, key leakage, broken authentication,
insecure session, and spoofing attacks. There are some encryption or hash algorithms known to be weak and are not
suggested for use such as MD5 and RC4.
In addition to the right choices of secure encryption or hash algorithms, the right uses of parameters also matter for the
security level. For example, ECB (Electronic Code Book) mode is not suggested for use in asymmetric encryption.

Test Objectives
Provide a guideline for the identification weak encryption or hashing uses and implementations.

How to Test
Basic Security Checklist
When using AES128 or AES256, the IV (Initialization Vector) must be random and unpredictable. Refer to FIPS
140-2, Security Requirements for Cryptographic Modules, section 4.9.1. random number generator tests. For
example,

in

Java,

java.util.Random

is

considered

a

weak

random

number

generator.

java.security.SecureRandom should be used instead of java.util.Random .

For asymmetric encryption, use Elliptic Curve Cryptography (ECC) with a secure curve like Curve25519 preferred.
If ECC can't be used then use RSA encryption with a minimum 2048bit key.
When uses of RSA in signature, PSS padding is recommended.
Weak hash/encryption algorithms should not be used such MD5, RC4, DES, Blowfish, SHA1. 1024-bit RSA or
DSA, 160-bit ECDSA (elliptic curves), 80/112-bit 2TDEA (two key triple DES)
Minimum Key length requirements:

Key exchange: Diffie-Hellman key exchange with minimum 2048 bits
Message Integrity: HMAC-SHA2
Message Hash: SHA2 256 bits
Asymmetric encryption: RSA 2048 bits
Symmetric-key algorithm: AES 128 bits
Password Hashing: PBKDF2, Scrypt, Bcrypt
ECDH, ECDSA: 256 bits

Uses of SSH, CBC mode should not be used.
When symmetric encryption algorithm is used, ECB (Electronic Code Book) mode should not be used.
When PBKDF2 is used to hash password, the parameter of iteration is recommended to be over 10000. NIST also
suggests at least 10,000 iterations of the hash function. In addition, MD5 hash function is forbidden to be used with
PBKDF2 such as PBKDF2WithHmacMD5.

Source Code Review
Search for the following keywords to identify use of weak algorithms: MD4, MD5, RC4, RC2, DES, Blowfish, SHA1, ECB

For Java implementations, the following API is related to encryption. Review the parameters of the encryption
implementation. For example,

SecretKeyFactory(SecretKeyFactorySpi keyFacSpi, Provider provider, String algorithm)
SecretKeySpec(byte[] key, int offset, int len, String algorithm)
Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");

For RSA encryption, the following padding modes are suggested.

RSA/ECB/OAEPWithSHA-1AndMGF1Padding (2048)
RSA/ECB/OAEPWithSHA-256AndMGF1Padding (2048)

Search for ECB , it's not allowed to be used in padding.
Review if different IV (initial Vector) is used.

// Use a different IV value for every encryption
byte[] newIv = ...;
s = new GCMParameterSpec(s.getTLen(), newIv);
cipher.init(..., s);
...

Search for IvParameterSpec , check if the IV value is generated differently and randomly.

IvParameterSpec iv = new IvParameterSpec(randBytes);
SecretKeySpec skey = new SecretKeySpec(key.getBytes(), "AES");
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, skey, iv);

In Java, search for MessageDigest to check if weak hash algorithm (MD5 or CRC) is used. For example:
MessageDigest md5 = MessageDigest.getInstance("MD5");

For signature, SHA1 and MD5 should not be used. For example:
Signature sig = Signature.getInstance("SHA1withRSA");

Search for PBKDF2 . To generate the hash value of password, PBKDF2 is suggested to be used. Review the
parameters to generate the PBKDF2 has value.
The iterations should be over 10000, and the salt value should be generated as random value.

private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes)
throws NoSuchAlgorithmException, InvalidKeySpecException
{
PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
return skf.generateSecret(spec).getEncoded();
}

Hard-coded sensitive information:

User related keywords: name, root, su, sudo, admin, superuser, login, username, uid
Key related keywords: public key, AK, SK, secret key, private key, passwd, password, pwd, share key,
shared key, cryto, base64
Other common sensitive keywords: sysadmin, root, privilege, pass, key, code, master, admin, uname, s
ession, token, Oauth, privatekey, shared secret

Tools
Vulnerability scanners such as Nessus, NMAP (scripts), or OpenVAS can scan for use or acceptance of weak
encryption against protocol such as SNMP, TLS, SSH, SMTP, etc.
Use static code analysis tool to do source code review such as klocwork, Fortify, Coverity, CheckMark for the
following cases.

CWE-261: Weak Cryptography for Passwords
CWE-323: Reusing a Nonce, Key Pair in Encryption
CWE-326: Inadequate Encryption Strength
CWE-327: Use of a Broken or Risky Cryptographic Algorithm
CWE-328: Reversible One-Way Hash
CWE-329: Not Using a Random IV with CBC Mode
CWE-330: Use of Insufficiently Random Values
CWE-347: Improper Verification of Cryptographic Signature
CWE-354: Improper Validation of Integrity Check Value
CWE-547: Use of Hard-coded, Security-relevant Constants
CWE-780 Use of RSA Algorithm without OAEP

References
NIST FIPS Standards
Wikipedia: Initialization Vector
Secure Coding - Generating Strong Random Numbers
Optimal Asymmetric Encryption Padding
Cryptographic Storage Cheat Sheet
Password Storage Cheat Sheet
Secure Coding - Do not use insecure or weak cryptographic algorithms
Insecure Randomness
Insufficient Entropy
Insufficient Session-ID Length
Using a broken or risky cryptographic algorithm
Javax.crypto.cipher API
ISO 18033-1:2015 - Encryption Algorithms
ISO 18033-2:2015 - Asymmetric Ciphers
ISO 18033-3:2015 - Block Ciphers

4.10 Business Logic Testing
4.10.0 Introduction to Business Logic
4.10.1 Test Business Logic Data Validation
4.10.2 Test Ability to Forge Requests
4.10.3 Test Integrity Checks
4.10.4 Test for Process Timing
4.10.5 Test Number of Times a Function Can Be Used Limits
4.10.6 Testing for the Circumvention of Work Flows
4.10.7 Test Defenses Against Application Misuse
4.10.8 Test Upload of Unexpected File Types
4.10.9 Test Upload of Malicious Files

Introduction to Business Logic
Testing for business logic flaws in a multi-functional dynamic web application requires thinking in unconventional
methods. If an application's authentication mechanism is developed with the intention of performing steps 1, 2, 3 in that
specific order to authenticate a user. What happens if the user goes from step 1 straight to step 3? In this simplistic
example, does the application provide access by failing open; deny access, or just error out with a 500 message?
There are many examples that can be made, but the one constant lesson is "think outside of conventional wisdom".
This type of vulnerability cannot be detected by a vulnerability scanner and relies upon the skills and creativity of the
penetration tester. In addition, this type of vulnerability is usually one of the hardest to detect, and usually application
specific but, at the same time, usually one of the most detrimental to the application, if exploited.
The classification of business logic flaws has been under-studied; although exploitation of business flaws frequently
happens in real-world systems, and many applied vulnerability researchers investigate them. The greatest focus is in
web applications. There is debate within the community about whether these problems represent particularly new
concepts, or if they are variations of well-known principles.
Testing of business logic flaws is similar to the test types used by functional testers that focus on logical or finite state
testing. These types of tests require that security professionals think a bit differently, develop abused and misuse cases
and use many of the testing techniques embraced by functional testers. Automation of business logic abuse cases is
not possible and remains a manual art relying on the skills of the tester and their knowledge of the complete business
process and its rules.

Business Limits and Restrictions
Consider the rules for the business function being provided by the application. Are there any limits or restrictions on
people's behavior? Then consider whether the application enforces those rules. It's generally pretty easy to identify the
test and analysis cases to verify the application if you're familiar with the business. If you are a third-party tester, then
you're going to have to use your common sense and ask the business if different operations should be allowed by the
application.
Sometimes, in very complex applications, the tester will not have a full understanding of every aspect of the application
initially. In these situations, it is best to have the client walk the tester through the application, so that they may gain a
better understanding of the limits and intended functionality of the application, before the actual test begins.
Additionally, having a direct line to the developers (if possible) during testing will help out greatly, if any questions arise
regarding the application's functionality.

Challenges of Logic Testing
Automated tools find it hard to understand context, hence it's up to a person to perform these kinds of tests. The
following two examples will illustrate how understanding the functionality of the application, the developer's intentions,
and some creative "out-of-the-box" thinking can break the application's logic. The first example starts with a simplistic
parameter manipulation, whereas the second is a real world example of a multi-step process leading to completely
subvert the application.
Example 1:
Suppose an e-commerce site allows users to select items to purchase, view a summary page and then tender the sale.
What if an attacker was able to go back to the summary page, maintaining their same valid session and inject a lower
cost for an item and complete the transaction, and then check out?
Example 2:

Holding/locking resources and keeping others from purchases these items online may result in attackers purchasing
items at a lower price. The countermeasure to this problem is to implement timeouts and mechanisms to ensure that
only the correct price can be charged.
Example 3:
What if a user was able to start a transaction linked to their club/loyalty account and then after points have been added
to their account cancel out of the transaction? Will the points/credits still be applied to their account?

Tools
While there are tools for testing and verifying that business processes are functioning correctly in valid situations these
tools are incapable of detecting logical vulnerabilities. For example, tools have no means of detecting if a user is able
to circumvent the business process flow through editing parameters, predicting resource names or escalating
privileges to access restricted resources nor do they have any mechanism to help the human testers to suspect this
state of affairs.
The following are some common tool types that can be useful in identifying business logic issues.
When installing addons you should always be diligent in considering the permissions they request and your browser
usage habits.

Intercepting Proxy
To Observe the Request and Response Blocks of HTTP Traffic
OWASP Zed Attack Proxy
Burp Proxy

Web Browser Plug-ins
To view and modify HTTP/HTTPS headers, post parameters, and observe the DOM of the Browser
Tamper Data for FF Quantum
Tamper Chrome (for Google Chrome)

Miscellaneous Test Tools
Web Developer toolbar
The Web Developer extension adds a toolbar button to the browser with various web developer tools. This is
the official port of the Web Developer extension for Firefox.
HTTP Request Maker for Chrome
HTTP Request Maker for Firefox
Request Maker is a tool for penetration testing. With it you can easily capture requests made by web pages,
tamper with the URL, headers and POST data and, of course, make new requests
Cookie Editor for Chrome
Cookie Editor for Firefox
Cookie Editor is a cookie manager. You can add, delete, edit, search, protect, and block cookies

References
Whitepapers
The Common Misuse Scoring System (CMSS): Metrics for Software Feature Misuse Vulnerabilities - NISTIR 7864
Finite State testing of Graphical User Interfaces, Fevzi Belli
Principles and Methods of Testing Finite State Machines - A Survey, David Lee, Mihalis Yannakakis
Security Issues in Online Games, Jianxin Jeff Yan and Hyun-Jin Choi
Securing Virtual Worlds Against Real Attack, Dr. Igor Muttik, McAfee

Seven Business Logic Flaws That Put Your Website At Risk - Jeremiah Grossman Founder and CTO, WhiteHat
Security
Toward Automated Detection of Logic Vulnerabilities in Web Applications - Viktoria Felmetsger Ludovico Cavedon
Christopher Kruegel Giovanni Vigna

OWASP Related
How to Prevent Business Flaws Vulnerabilities in Web Applications, Marco Morana

Useful Web Sites
Abuse of Functionality
Business logic
Business Logic Flaws and Yahoo Games
CWE-840: Business Logic Errors
Defying Logic: Theory, Design, and Implementation of Complex Systems for Testing Application Logic
Software Testing Lifecycle

Books
The Decision Model: A Business Logic Framework Linking Business and Technology, By Barbara Von Halle, Larry
Goldberg, Published by CRC Press, ISBN1420082817 (2010)

---

