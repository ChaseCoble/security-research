# Path Traversal - Traversal Sequences Blocked with Absolute Path Bypass
**Platform:** PortSwigger Web Security Academy
**Date:** 2026-07-12
**Category:** Path Traversal
**Difficulty:** Practitioner

## Vulnerability
Static image pathing vulnerable to path traversal via the `filename` parameter. The application blocks relative traversal sequences (`../`) but performs no validation restricting the parameter to relative paths within the intended base directory — an absolute path is accepted and resolved directly against filesystem root.

## Discovery
- Tasked with retrieving `/etc/passwd`, given an image-loading endpoint at `/image?filename=`
- Lab description states traversal sequences are blocked, but implies an absolute-path bypass is possible
- Noted product ratings load from `/resources/images/rating2.png` — a second potential filesystem entry point, not pursued further once the primary parameter proved viable
- Set `filename=/etc/passwd` (absolute path, no `../` sequences) via the actual endpoint — returned file contents, confirming the block only inspects for relative traversal sequences and not for absolute paths escaping the intended directory

## Exploitation
Intercepted the image request in Burp Proxy and rewrote the `filename` parameter to an absolute path, bypassing the relative-traversal-sequence filter entirely since the block only inspected for `../` patterns and did not restrict the parameter to relative paths within the intended directory. Sent via Repeater to inspect the raw response body directly.

```http
GET /image?filename=/etc/passwd HTTP/2
Host: 0a0e00450440501681e689fe005900b9.web-security-academy.net
Cookie: session=[REDACTED]
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: *
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a0e00450440501681e689fe005900b9.web-security-academy.net/
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: same-origin
Priority: u=5
Te: trailers
```

## Impact
Arbitrary file read on the underlying filesystem. Demonstrated against `/etc/passwd`, but the same primitive extends to any file readable by the web server process — application source, configuration files, credentials, or SSH keys depending on server configuration and process permissions.

## Mitigations
**Primary:**
- Canonicalize the resolved path (`realpath()` or equivalent) and verify it falls within the intended base directory before file access — reject any resolved path outside that boundary, whether reached via relative traversal or a direct absolute path
- Use an allowlist of valid filenames or an indirect reference (e.g. database ID → filename mapping) rather than accepting a raw path component from the client

**Defense in depth:**
- Run the web server process with least-privilege filesystem permissions — no read access to sensitive files outside the web root
- Containerization/chroot to physically limit what the process can reach, independent of application-layer validation
- Do not rely on blocklisting traversal sequences (`../`) alone — this lab demonstrates why: filtering `../` does nothing to stop an absolute path pointed directly at the target file

## OWASP Reference
[A01:2025 – Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/) — path traversal is explicitly listed under Mapped CWEs for this category.

## CWE Reference
[CWE-22](https://cwe.mitre.org/data/definitions/22.html) — Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
