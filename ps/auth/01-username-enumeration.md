# Authentication - Username Enumeration via different responses
**Platform:** PortSwigger Web Security Academy
**Date:** 2026-07-08
**Category:** Authentication

## Vulnerability
The application returns observable differences in HTTP response length for valid 
versus invalid usernames during authentication. Combined with no rate limiting or 
account lockout, this allows an attacker to enumerate valid usernames via automated 
requests and subsequently brute force account passwords.


## Discovery
- Lab prompts that vulnerability is in the predictability of username and password
- Attempted to login with username=username and password=password to confirm schema: username=user&password=password
- Send request to BURP intruder and apply wordlist to username: Username identified by 2 byte longer response
- Password enumerated against list: Password identified by 302 return.
- Access confirmed


## Exploitation
**Phase 1 — Username enumeration:**
Payload: Sniper attack against username field with PortSwigger username wordlist.
Valid username identified via response length anomaly — one response differed from 
the uniform length of all invalid username responses.

**Phase 2 — Password brute force:**
Payload: Sniper attack against password field with valid username set as static value.
Successful login identified via HTTP 302 redirect response versus 200 for failed attempts. 

## Impact
Valid username confirmed without authentication. Full account takeover via 
credential brute force. No rate limiting or lockout prevented automated attack.

## Mitigations
**Primary:** Return identical error messages and response lengths for invalid 
username and invalid password. Never reveal which field failed.

**Defense in depth:**
- Account lockout after N failed attempts
- CAPTCHA on login forms
- Rate limiting per IP
- Multi-factor authentication
- Generic error: "Invalid username or password" regardless of which failed

## OWASP Reference
[A07:2025 Identification and Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)

## CWE REFERENCE
[CWE-204 Observable Response Discrepancy](https://cwe.mitre.org/data/definitions/204.html)
[CWE-307 Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
