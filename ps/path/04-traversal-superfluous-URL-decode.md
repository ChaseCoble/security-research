# Path Traversal - Traversal Sequences Stripped with Superfluous URL-Decode
**Platform:** PortSwigger Web Security Academy
**Date:** 2026-07-12
**Category:** Path Traversal
**Difficulty:** Practitioner

## Vulnerability
Static image pathing vulnerable to path traversal via the `filename` parameter. The application checks the raw input for traversal sequences (`../`) and strips/rejects them, then performs a URL-decode of the input afterward — an extra ("superfluous") decode pass that runs after the security check rather than before it. A doubly-encoded traversal sequence evades the check (which sees no literal `../`) and resolves into a working traversal sequence once the application's own decode step fires.

## Discovery
- Identified `filename` parameter on `/image?filename=` as the injection point
- Lab description states the application blocks traversal sequences, then URL-decodes the input before use — implying the check happens prior to decoding
- Tried a single-encoded traversal sequence (`%2e%2e%2f`) — failed, confirming the filter catches a payload that decodes to `../` in a single pass
- Reasoned that a second layer of encoding (encoding the `%` character itself, `%` → `%25`) would produce a string with no literal or single-decoded `../` present at filter-check time, but that would fully resolve to `../` after the application's decode pass
- Constructed a payload using `%252e%252e%252f` per directory level, five segments deep, targeting `/etc/passwd`
- Sent via Repeater — returned `/etc/passwd` contents

## Exploitation
Intercepted the image request in Burp Proxy and rewrote the `filename` parameter to a double-URL-encoded traversal sequence. The traversal-sequence filter inspects the raw parameter value and finds no literal `../`; the application's subsequent decode step then resolves the double-encoded string into a valid traversal path, after the security check has already passed.

```http
GET /image?filename=%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd HTTP/2
Host: 0a1c005d045d98be81672a4a0005006f.web-security-academy.net
Cookie: session=[REDACTED]
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a1c005d045d98be81672a4a0005006f.web-security-academy.net/
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: same-origin
Priority: u=5
Te: trailers
```

Mechanism: `%25` decodes to `%`, so `%252e` decodes once to `%2e`, then decodes again to `.`. Since the security check only sees the raw, once-still-encoded string, it never observes a literal `../` and passes the input through. The application's own decode logic then performs the second decode pass, fully resolving the payload into a working traversal sequence — the order of operations (check, then decode) is the root cause, independent of how the stripping/blocking logic itself is implemented.

## Impact
Arbitrary file read on the underlying filesystem, identical in scope to prior path traversal labs — demonstrated against `/etc/passwd`, extends to any file readable by the web server process.

## Mitigations
**Primary:**
- Canonicalize the resolved path (`realpath()` or equivalent) and verify it falls within the intended base directory *after* all decoding has occurred, not before
- Perform any necessary decoding first, then validate the fully-decoded result — never validate a value that will be transformed afterward
- Use an allowlist of valid filenames or an indirect reference (e.g. database ID → filename mapping) rather than accepting a raw path component from the client

**Defense in depth:**
- Avoid multiple/nested decode passes on user input entirely where possible — each additional decode layer is an additional opportunity for an encoding-based filter bypass
- Run the web server process with least-privilege filesystem permissions
- Containerization/chroot to physically limit filesystem access independent of application-layer validation

## OWASP Reference
[A01:2025 – Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/) — path traversal is explicitly listed under Mapped CWEs for this category.

## CWE Reference
[CWE-22](https://cwe.mitre.org/data/definitions/22.html) — Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
