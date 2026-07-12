# SQL Injection - WHERE Clause Filter Bypass
**Platform:** PortSwigger Web Security Academy
**Date:** 2026-07-08
**Category:** SQL Injection
**Difficulty:** Apprentice

## Vulnerability
SQL injection in the `category` parameter of `/filter?category=`. User input is concatenated directly into a SQL `WHERE` clause with no parameterization or sanitization, allowing an attacker to alter query logic.

## Discovery
- Browsed to a specific product
- Identified `productId=7` parameter
- Added single quote `'` — server returned 200, non-injectable
- Browsed to product filter
- Added single quote `'` to `category` parameter — server returned 500, confirming an unhandled SQL syntax error and an injection point

## Exploitation
Payload: `'+OR+1=1--+-`

Injected query breaks out of the string literal, `OR 1=1` makes the `WHERE` clause always evaluate true, and `--` comments out the remainder of the original query — including the `released=1` filter. Returns all products, including unreleased ones.

## SQL Query (before/after)
Before: `SELECT * FROM products WHERE category = 'Gifts' AND released = 1`
After:  `SELECT * FROM products WHERE category = '' OR 1=1--`

## Impact
Full bypass of the application's intended data-visibility filter. In this lab, exposes unreleased products; the same primitive on a real target extends to unauthorized data disclosure, authentication bypass, or — depending on DB permissions and injectable context — data modification/deletion via stacked queries or `UNION`-based extraction of unrelated tables.

## Mitigations
**Primary:** Use parameterized queries / prepared statements for all database access — never concatenate user input directly into SQL strings.

**Defense in depth:**
- Least-privilege database account for the application (no access to tables/data beyond what's required)
- Input validation/allowlisting where the expected value set is known (e.g. category names)
- Disable verbose SQL error messages in production — the 500 error here is what confirmed the injection point
- Web application firewall rules to flag common injection syntax as a detection layer, not a primary control

## OWASP Reference
[A05:2025 – Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)

## CWE Reference
[CWE-89](https://cwe.mitre.org/data/definitions/89.html) — Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
