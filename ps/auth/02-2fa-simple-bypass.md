# Authentication -  2FA Simple Bypass
**Platform:** PortSwigger Web Security Academy
**Date:** 2026-07-09
**Category:** Authentication

## Vulnerability
The application returns observable differences in HTTP response length for valid 
versus invalid usernames during authentication. Combined with no rate limiting or 
account lockout, this allows an attacker to enumerate valid usernames via automated 
requests and subsequently brute force account passwords.


## Discovery
- Lab prompts that vulnerability is in bypassing the 2FA feature
- Logged in with given credentials and recorded the 2FA workflow
- Urls transfer between /login, /login2, then /my-account?id=username
- Attempted to bypass to /my-account?id=target from home screen, and failed
- Attempted to bypass after successful /login to /my-account and it was successful.


## Exploitation
Payload: Bypassed from /login2 to /my-account 

## Impact# Authentication - 2FA Simple Bypass
**Platform:** PortSwigger Web Security Academy
**Date:** 2026-07-09
**Category:** Authentication

## Vulnerability
Two-factor authentication is enforced via client-side navigation flow rather than 
server-side session state. The application marks a session as authenticated after 
the first login factor without requiring MFA completion, allowing direct navigation 
to authenticated endpoints.

## Discovery
- Mapped authentication flow: /login → /login2 → MFA verification
- Completed first factor with valid credentials
- Observed session cookie set after /login before MFA completion
- Navigated directly to /my-account bypassing /login2 entirely
- Access granted without MFA code

## Exploitation
Complete first factor login with valid credentials. Before submitting MFA code, 
navigate directly to authenticated endpoint /my-account. Server grants access 
without MFA verification.

## Impact
Complete MFA bypass. Attacker with valid credentials can bypass second factor 
entirely, rendering MFA ineffective as a security control.

## Mitigations
**Primary:** Enforce MFA completion server-side before granting access to any 
authenticated endpoint. Session state must not be marked fully authenticated 
until all factors are verified.

**Defense in depth:**
- Validate MFA completion on every authenticated request, not just /login2
- Implement server-side session flags distinguishing partial and full authentication
- Redirect unauthenticated sessions to /login2 if MFA is incomplete

## OWASP Reference
A07:2021 Identification and Authentication Failures

## CWE Reference
CWE-287 Improper Authentication
CWE-306 Missing Authentication for Critical Function

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
A07:2021 Identification and Authentication Failures

## CWE REFERENCE
CWE-204 Observable Response Discrepancy
CWE-307 Improper Restriction of Excessive Authentication Attempts
