# SQL Injection - Vulnerability Allowing Login Bypass
**Platform:** PortSwigger Web Security Academy
**Date:** 2026-07-08
**Category:** SQL Injection
**Difficulty:** Apprentice

## Vulnerability
SQL injection in the login form's username parameter. User-supplied input is
concatenated directly into a SQL query without sanitization or parameterization,
allowing an attacker to manipulate query logic and bypass authentication entirely.

## Discovery
- Lab prompt indicated the vulnerability is in the login handler
- Login redirects to `/my-account` on success
- Attempted login with `admin`/`password` — failed
- Added `'` into the username/password fields — server returned 500, confirming injection
- Tried `csrf=[token]&'+OR+1=1--` — returned missing parameter error
- Tried `username='+OR+1=1--+-&password=password` — gained access to the administrator account

## Exploitation
Payload: `'+OR+1=1--+-`

Injected query breaks out of the string literal, `OR 1=1` makes the `WHERE` clause always evaluate true, and `--` comments out the remainder of the query — including the password check. The query returns all rows in the `users` table; the application authenticates as the first row in the result set. This lab is structured so the administrator account occupies that first row, so the bypass lands directly on `admin`. Against a target where row order isn't controlled or known, the same technique still achieves a full authentication bypass, but the resulting account would be whichever row the database returns first — not guaranteed to be a privileged one without further recon (e.g. confirming row order or refining the payload to target a specific username).

## SQL Query (before/after)
Before: `SELECT * FROM users WHERE username = 'foo' AND password = 'bar'`
After:  `SELECT * FROM users WHERE username = '' OR 1=1--'`

## Impact
Authentication bypass allowing unauthenticated access to an administrator account.
Full account takeover without valid credentials.

## Mitigations
**Primary:** Use parameterized queries (prepared statements). This eliminates SQLi
regardless of input content.

**Defense in depth:**
- Input validation and allowlisting
- WAF rules for common SQLi patterns
- Least privilege database accounts
- Account lockout policies

## OWASP Reference
[A05:2025 – Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)

## CWE Reference
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html) — SQL Injection
- [CWE-287](https://cwe.mitre.org/data/definitions/287.html) — Improper Authentication
