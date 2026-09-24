# WSTG CRYP — Cryptography

OWASP WSTG v4.2. Tests WSTG-CRYP-01 → 04.

## Table of Contents

- [CRYP-01 Weak Transport Layer Security](#wstg-cryp-01)
- [CRYP-02 Padding Oracle](#wstg-cryp-02)
- [CRYP-03 Sensitive Info via Unencrypted Channels](#wstg-cryp-03)
- [CRYP-04 Weak Encryption](#wstg-cryp-04)

---

## WSTG-CRYP-01

**Testing for Weak Transport Layer Security**

Goal: confirm TLS is not just present but correctly configured — weak protocol versions, weak ciphers, or a bad certificate all undermine it even when HTTPS is enabled.

**Server configuration** — known-weak protocols/ciphers (list grows over time; check Mozilla Server Side TLS Guide for current recommendations):

| Weakness | Attack |
|---|---|
| SSLv2 | DROWN |
| SSLv3 | POODLE |
| TLSv1.0 | BEAST |
| EXPORT cipher suites | FREAK |
| NULL ciphers | auth only, no encryption |
| Anonymous ciphers | sometimes on SMTP, see RFC 7672 |
| RC4 ciphers | NOMORE |
| CBC mode ciphers | BEAST, Lucky 13 |
| TLS compression | CRIME |
| Weak DHE keys | LOGJAM |

Most of these need an active MitM plus heavy resources — lab-demonstrated more often than practically exploited, realistically a nation-state-tier threat.

**Digital certificates** — crypto strength: key ≥ 2048 bits, signature algorithm ≥ SHA-256 (no MD5/SHA-1). Validity: within its validity period (max 398-day lifespan for certs issued after 2020-09-01); signed by a trusted CA (public CA for external apps, internal CA acceptable for internal apps — don't flag internal certs untrusted just because your own machine doesn't trust that CA); SAN matches the hostname you're accessing (modern browsers ignore CN; accessing by IP will always show as untrusted). Wildcard certs (`*.example.org`) are convenient but carry their own risks (see OWASP TLS Cheat Sheet). Issuer/SAN fields can leak internal domain names useful for network mapping or social engineering.

Known implementation CVEs worth checking for: Debian OpenSSL PRNG (CVE-2008-0166), OpenSSL Insecure Renegotiation (CVE-2009-3555), Heartbleed (CVE-2014-0160), F5 TLS POODLE (CVE-2014-8730), Microsoft Schannel DoS (CVE-2014-6321).

**Application-level TLS use** — also verify: sensitive data isn't sent over unencrypted channels ([CRYP-03](#wstg-cryp-03)), `Strict-Transport-Security` header is set (WSTG-CONF-07), cookies carry the `Secure` flag (WSTG-SESS-02). Watch for **mixed active content** (scripts/CSS loaded over HTTP into an HTTPS page — attacker-modifiable, can run arbitrary JS/CSS; modern browsers block this, but passive content like images can still leak info or deface the page) and unprotected **HTTP→HTTPS redirects** (an attacker intercepting the initial HTTP request can redirect to a malicious site or run sslstrip on subsequent traffic — defend with HSTS preload).

Tools: Nmap (TLS scripts), OWASP O-Saft, sslscan, sslyze, SSL Labs, testssl.sh, or manual `openssl s_client` / `gnutls-cli` (note: modern OpenSSL/GnuTLS builds may drop support for legacy protocols like SSLv2, causing false negatives — confirm your tool version still supports what you're testing). Browser dev tools also show negotiated protocol/cipher and surface cert-trust warnings directly.

Refs: OWASP Transport Layer Protection Cheat Sheet; Mozilla Server Side TLS Guide.

---

## WSTG-CRYP-02

**Testing for Padding Oracle**

Goal: find a decryption endpoint that leaks whether client-supplied ciphertext had valid padding after decryption — letting an attacker decrypt data and forge arbitrary ciphertext without the key.

Block ciphers pad plaintext to a block-size multiple (commonly PKCS#7: remaining bytes filled with the padding length, e.g. 5 bytes of padding → `0x05` repeated 5×). A padding oracle exists when the app leaks the specific "padding invalid" error state — via an exposed exception (Java `BadPaddingException`, ASP.NET `CryptographicException: Padding is invalid...`), a subtly different response, or a timing side-channel — as distinct from other decryption failures. CBC mode is also subject to bit-flipping: flipping a bit in block *n* of ciphertext flips the same bit in block *n+1* of the decrypted plaintext, while garbling block *n* itself.

Black-box:
1. Find candidate values: encrypted-looking (high entropy), and — once Base64-decoded — a length that's a multiple of a common block size (8/16 bytes); compare across sessions for a shared length divisor.
2. Given ciphertext of length `y = (b+1)*n` (IV prepended, `b` = number of blocks), flip the last bit of block `b-1` (byte `y-n-1`), re-encode, and resubmit; repeat against block `b-2`. For single-block ciphertext with a server-side or hardcoded IV, flip bits sequentially, or prepend a random block and cycle its last byte through all 256 values.
3. Look for three distinguishable response states: decrypts and processes fine; decrypts but produces garbled data that trips app-level error handling; fails decryption outright with a padding error. An oracle exists if these are distinguishable — via explicit padding-error messages, or implicitly via differing errors/timing. Confirm by running the full attack.

Gray-box: verify every point that decrypts client-supplied data (1) checks ciphertext integrity via HMAC or an authenticated mode (GCM/CCM), and (2) handles all decrypt/processing error states identically — a secure implementation returns only `ok`/`failed`, no side channel.

Tools: Bletchley, PadBuster, POET, Poracle, python-paddingoracle.

Refs: Wikipedia — Padding Oracle Attack; Rizzo & Duong, *Practical Padding Oracle Attacks*.

---

## WSTG-CRYP-03

**Testing for Sensitive Information Sent via Unencrypted Channels**

Goal: confirm sensitive data — auth credentials, PINs, session IDs, tokens, cookies, regulated PII (SSNs, bank/passport/health/insurance/student records, card numbers, driver's license/state ID) — is never transmitted in plaintext. Rule of thumb: anything protected at rest must also be protected in transit.

Black-box — look for:
- **Basic Auth over HTTP**: credentials are base64-encoded, not encrypted:
  ```
  $ curl -kis http://example.com/restricted/
  HTTP/1.1 401 Authorization Required
  WWW-Authenticate: Basic realm="Restricted Area"
  ```
- **Form auth posting to HTTP**: `<form action="http://example.com/login">` — spot via source or an intercepting proxy.
- **Session cookie sent over HTTP / missing `Secure` flag** — check `Set-Cookie` for the flag and confirm the whole login flow stays on HTTPS, not just the initial page.
- **Hardcoded secrets or PII in source/logs**:
  ```
  grep -rE "pass|password|pwd|user|guest|admin|encry|key|decrypt|sharekey" ./PathToSearch/
  grep -rE "[0-9]{6}" ./PathToSearch/   # adjust pattern to the PII format expected
  ```

Tools: curl, grep, Identity Finder, Wireshark, tcpdump.

Refs: OWASP Top 10 2017 A3 — Sensitive Data Exposure; OWASP ASVS V9; Transport Layer Protection Cheat Sheet.

---

## WSTG-CRYP-04

**Testing for Weak Encryption**

Goal: identify weak algorithms, weak parameters, or weak key material that undermine otherwise-present encryption — leading to data exposure, key leakage, broken auth, or spoofing.

Checklist:

| Area | Requirement |
|---|---|
| Symmetric IV | random + unpredictable (`SecureRandom`, not `java.util.Random`); unique per encryption |
| Asymmetric algorithm | ECC (Curve25519 preferred) over RSA; if RSA, ≥2048-bit key with OAEP/PSS padding |
| Forbidden algorithms | MD5, RC4, DES, Blowfish, SHA1, 1024-bit RSA/DSA, 160-bit ECDSA, 2-key 3DES |
| Key exchange | Diffie-Hellman ≥2048 bits |
| Message integrity | HMAC-SHA2 |
| Message hash | SHA-256+ |
| Symmetric key | AES ≥128 bits |
| Password hashing | PBKDF2 / scrypt / bcrypt, iteration count >10,000 (never `PBKDF2WithHmacMD5`) |
| Cipher mode | never ECB; avoid CBC for SSH |

Source review — grep for weak-algorithm keywords (`MD4`, `MD5`, `RC4`, `RC2`, `DES`, `Blowfish`, `SHA1`, `ECB`) and inspect usage, e.g. Java:
```java
Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");     // weak cipher/mode
MessageDigest md5 = MessageDigest.getInstance("MD5");       // weak hash
Signature sig = Signature.getInstance("SHA1withRSA");       // weak signature
```
Prefer `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`. Check `IvParameterSpec`/`GCMParameterSpec` usage for a freshly randomized IV per operation, not a reused/hardcoded one. For `PBKDF2`, confirm iteration count >10,000 and a randomly generated salt. Also grep for hardcoded secrets: `password`, `secret key`, `private key`, `token`, `api key`, `shared secret`, etc.

Tools: Nessus, Nmap scripts, OpenVAS (protocol-level scanning); Klocwork, Fortify, Coverity, Checkmarx (static source review) — flag CWE-261, 323, 326-330, 347, 354, 547, 780.

Refs: NIST FIPS 140-2; OWASP Cryptographic Storage Cheat Sheet; OWASP Password Storage Cheat Sheet.

---
