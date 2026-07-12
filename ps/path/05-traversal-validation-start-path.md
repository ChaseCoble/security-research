# Path Traversal - Validation of Start of Path
**Platform:** PortSwigger Web Security Academy
**Date:** 2026-07-12
**Category:** Path Traversal
**Difficulty:** Practitioner

## Vulnerability
Static image pathing vulnerable to path traversal via the `filename` parameter. The application validates that the input *begins with* an expected base directory prefix (`/var/www/images/`), but performs no further validation on the remainder of the string — traversal sequences appended after a valid prefix are not inspected, allowing the resolved path to escape the intended directory entirely.

## Discovery
- Identified `filename` parameter on `/image?filename=` as the injection point
- Lab description implies a validation check specifically on the start of the path — reasoned this meant the app checks for an expected prefix rather than validating the full resolved path
- Tried `/var/` + relative traversal — failed
- Tried `/var/www/` + relative traversal — failed
- Tried `/var/www/images/` + relative traversal — succeeded, indicating the validation requires an exact match against the full expected base directory rather than a partial/fuzzy prefix check
- Constructed a payload beginning with `/var/www/images/` followed by relative traversal sequences to walk back out and up to filesystem root, targeting `/etc/passwd`
- Sent via Repeater — returned `/etc/passwd` contents

## Exploitation
Intercepted the image request in Burp Proxy and rewrote the `filename` parameter to satisfy the start-of-path validation check while appending a relative traversal sequence to escape the validated directory.

```http
GET /image?filename=/var/www/images/../../../../../../etc/passwd HTTP/2
Host: 0a2400bc04b68603820e4c0f00f8000a.web-security-academy.net
Cookie: session=[REDACTED]
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a2400bc04b68603820e4c0f00f8000a.web-security-academy.net/
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: same-origin
Priority: u=5
Te: trailers
```

Mechanism: the validation logic only confirms the string starts with `/var/www/images/` and stops there — it never re-checks the fully resolved path. The filesystem, however, resolves the entire string including the traversal sequences that follow the valid-looking prefix, walking back out past the validated directory and up to root before descending into `/etc/passwd`. Satisfying a prefix check says nothing about where the path actually ends up once resolved.

## Impact
Arbitrary file read on the underlying filesystem, identical in scope to prior path traversal labs — demonstrated against `/etc/passwd`, extends to any file readable by the web server process.

## Mitigations
**Primary:**
- Canonicalize the resolved path (`realpath()` or equivalent) and verify the *fully resolved* path falls within the intended base directory — a prefix check on the raw input string is not equivalent to validating the resolved path
- Use an allowlist of valid filenames or an indirect reference (e.g. database ID → filename mapping) rather than accepting a raw path component from the client

**Defense in depth:**
- Never treat "starts with an expected value" as sufficient validation for filesystem paths — this lab demonstrates why: everything after the prefix is still attacker-controlled and still resolved by the OS
- Run the web server process with least-privilege filesystem permissions
- Containerization/chroot to physically limit filesystem access independent of application-layer validation

## OWASP Reference
[A01:2025 – Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/) — path traversal is explicitly listed under Mapped CWEs for this category.

## CWE Reference
[CWE-22](https://cwe.mitre.org/data/definitions/22.html) — Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
