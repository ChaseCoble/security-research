# SQL Injection - WHERE Clause Filter Bypass
**Platform:** PortSwigger Web Security Academy
**Date:** 2026-07-08
**Category:** SQL Injection

## Vulnerability
SQL injection in the `category` parameter of `/filter?category=`

## Discovery
- Browsed to specific product
- Identified productId=7 parameter
- Added single quote `'`
- Server returned 200 - non injectable
- Browsed to product filter
- Added single quote `'` to category parameter
- Server returned 500 — confirmed injection point

## Exploitation
Payload: `'+OR+1=1--+-`

Injected query breaks out of string, OR 1=1 makes WHERE clause always true,
-- comments out remainder including released=1 filter.
Returns all products including unreleased.

## SQL Query (before/after)
Before: `SELECT * FROM products WHERE category = 'Gifts' AND released = 1`
After:  `SELECT * FROM products WHERE category = '' OR 1=1--`

## OWASP Reference
A03:2021 Injection
