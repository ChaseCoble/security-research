# SQL Injection - Vulnerability allowing login bypass
**Platform:** PortSwigger Web Security Academy
**Date:** 2026-07-08
**Category:** SQL Injection

## Vulnerability
SQL injection in the login form's username parameter. User-supplied input is 
concatenated directly into a SQL query without sanitization or parameterization, 
allowing an attacker to manipulate query logic and bypass authentication entirely.

## Discovery
- Lab prompts that vulnerability is in the login handler
- Selected my profile path is /my-account redirects to login
- Attempted to login with admin/password
- Added `'` into the body of the username/password query. Returns 500
- Tried csrf=[token]&'+OR_1=1-- returned missing parameter
- Tried username='+OR+1=1--+-&password=password Attained access to administrator account


## Exploitation
Payload: `'+OR+1=1--+-`

Injected query breaks out of string, OR 1=1 makes WHERE clause always true,
-- comments out remainder including password check.
Returns first user in the table which is often admin. 

## Impact
Authentication bypass allowing unauthenticated access to administrator account.
Full account takeover without valid credentials

## Mitigations
**Primary:** Use parameterized queries (prepared statements). This eliminates SQLi 
regardless of input content.

**Defense in depth:**
- Input validation and allowlisting
- WAF rules for common SQLi patterns
- Least privilege database accounts
- Account lockout policies

## SQL Query (before/after)
Before: `SELECT * FROM users WHERE username = 'foo' AND password = 'bar'`
After:  `SELECT * FROM users WHERE username = '' OR 1=1--'`

## OWASP Reference
A03:2021 Injection

## CWE REFERENCE
CWE-89 SQL Injection
CWE-287 Improper Authentication
