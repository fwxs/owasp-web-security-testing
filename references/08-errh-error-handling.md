# WSTG ERRH — Error Handling

OWASP WSTG v4.2. Tests WSTG-ERRH-01, 02.

## Table of Contents

- [ERRH-01 Improper Error Handling](#wstg-errh-01)
- [ERRH-02 Stack Traces](#wstg-errh-02)

---

## WSTG-ERRH-01

**Testing for Improper Error Handling**

Goal: find error output (stack traces, memory dumps, timeouts, input-mismatch messages) that leaks internals — API/service names, framework/app versions, service-to-service mapping for attack chaining — or opens a DoS/control-bypass path via an unhandled exception.

Black-box:
- **Web server**: request random nonexistent files/folders (404s); request existing folders and observe behavior (403, blank page, directory listing); send RFC-breaking requests (oversized path, malformed headers, altered HTTP version) — even apps with proper error handling can expose the underlying server (NGINX/Apache/IIS) this way since it must process the malformed request first.
- **Application**: identify every input point and its expected type (string/int/JSON/XML...), then fuzz. Full injection fuzzing is expensive — when time-constrained, handpick inputs likely to break the parser: unbalanced JSON brackets, oversized text for short fields, CRLF injection in parsed params, filename-invalid special characters. Fuzz every input type, since interpreters sometimes throw outside the app's own exception handling. Identify which backend service produced an error (DB, internal API...) and refine the fuzz list to extract more detail from it — especially valuable for mapping microservice architectures where inconsistent error handling reveals which service handles which request. Watch for errors disguised as success responses, hidden in a 302, or returned in a nonstandard shape.

Remediation: implement centralized/global error handling that returns generic messages to the client and logs full detail server-side (see OWASP Proactive Controls C10, Error Handling Cheat Sheet).

Refs: WSTG Appendix C — Fuzz Vectors; OWASP Proactive Controls C10; ASVS v4.1 §7.4; CWE-728; OWASP Error Handling Cheat Sheet; OWASP Juice Shop (Error Handling challenge).

---

## WSTG-ERRH-02

**Testing for Stack Traces**

Merged into: [Testing for Improper Error Handling](#wstg-errh-01).

---
