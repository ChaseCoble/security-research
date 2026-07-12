# Authentication - 2FA Simple Bypass
**Platform:** PortSwigger Web Security Academy
**Date:** 2026-07-09
**Category:** Authentication

## Vulnerability
Two-factor authentication is enforced via client-side navigation flow rather than
server-side session state. The application marks a session as authenticated after
the first login factor without requiring MFA completion, allowing direct navigation
to authenticated endpoints.

## Discovery
- Lab prompt indicated the vulnerability is in bypassing the 2FA feature
- Logged in with given credentials and recorded the 2FA workflow
- Mapped authentication flow: `/login` → `/login2` → `/my-account?id=username`
- Attempted direct navigation to `/my-account?id=target` from the home screen (unauthenticated) — failed
- Completed first factor with valid credentials via `/login`
- Observed session cookie set after `/login`, before MFA completion at `/login2`
- Navigated directly to `/my-account` from `/login2`, bypassing MFA entirely — access granted

## Exploitation
Complete first factor login with valid credentials via `/login`. Before submitting the MFA code at `/login2`, navigate directly to the authenticated endpoint `/my-account`. Server grants access without MFA verification, since the session was already marked authenticated after the first factor.

## Impact
Complete MFA bypass. An attacker with valid credentials (but no access to the second factor) can reach fully authenticated endpoints, rendering MFA ineffective as a security control.

## Mitigations
**Primary:** Enforce MFA completion server-side before granting access to any authenticated endpoint. Session state must not be marked fully authenticated until all factors are verified.

**Defense in depth:**
- Validate MFA completion on every authenticated request, not just at `/login2`
- Implement server-side session flags distinguishing partial and full authentication
- Redirect sessions with incomplete MFA to `/login2` if a fully authenticated endpoint is requested

## OWASP Reference
[A07:2025 – Identification and Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)

## CWE Reference
- [CWE-287](https://cwe.mitre.org/data/definitions/287.html) — Improper Authentication
- [CWE-306](https://cwe.mitre.org/data/definitions/306.html) — Missing Authentication for Critical Function
