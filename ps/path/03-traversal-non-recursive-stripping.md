# Path Traversal - Traversal Sequences Stripped Non-Recursively
**Platform:** PortSwigger Web Security Academy
**Date:** 2026-07-12
**Category:** Path Traversal
**Difficulty:** Practitioner

## Vulnerability
Static image pathing vulnerable to path traversal via the `filename` parameter. The application strips traversal sequences (`../`) from user input, but only in a single non-recursive pass — removing an inner `../` from a larger crafted sequence leaves a valid traversal sequence behind.

## Discovery
- Identified `filename` parameter on `/image?filename=` as the injection point
- Lab description indicates traversal sequences are stripped, implying a non-recursive (single-pass) filter
- Tried an absolute path (`/etc/passwd`) — 404, blank response, no further detail
- Tried a basic relative traversal (`../../../etc/passwd`) — 404, blank response, no visibility into whether/how the string was altered server-side
- Reasoned that if the strip is non-recursive, embedding `../` inside a larger sequence would survive a single pass: stripping the inner `../` from `....//` leaves `../` behind, reassembling into a working traversal sequence
- Constructed `....//....//....//....//....//....//....//etc/passwd` and sent via Repeater — returned `/etc/passwd` contents

## Exploitation
Intercepted the image request in Burp Proxy and rewrote the `filename` parameter to a nested traversal sequence designed to survive a single-pass strip of `../`. Sent via Repeater to inspect the raw response body directly.

```http
GET /image?filename=....//....//....//....//....//....//....//etc/passwd HTTP/2
Host: 0a7d0064039384db80ce2bc300480044.web-security-academy.net
Cookie: session=[REDACTED]
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a7d0064039384db80ce2bc300480044.web-security-academy.net/
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: same-origin
Priority: u=5
Te: trailers
```

Mechanism: each `....//` segment contains `../` embedded within it. A non-recursive filter that removes one instance of `../` per pass strips the inner sequence and leaves `../` behind — reassembling into a functional traversal sequence after filtering. Seven segments were used, more than the minimum required for this lab's directory depth, but the payload still succeeded — indicating some tolerance for over-traversal (excess `../` beyond filesystem root does not break resolution).

## Impact
Arbitrary file read on the underlying filesystem, identical in scope to the simple-case and absolute-path-bypass labs — demonstrated against `/etc/passwd`, extends to any file readable by the web server process.

## Mitigations
**Primary:**
- Canonicalize the resolved path (`realpath()` or equivalent) and verify it falls within the intended base directory before file access
- Use an allowlist of valid filenames or an indirect reference (e.g. database ID → filename mapping) rather than accepting a raw path component from the client

**Defense in depth:**
- Do not rely on stripping traversal sequences as a sanitization method at all — this lab demonstrates why single-pass stripping is trivially bypassed by nesting the sequence. Recursive stripping is marginally better but still fragile compared to canonicalization + allowlisting
- Run the web server process with least-privilege filesystem permissions
- Containerization/chroot to physically limit filesystem access independent of application-layer validation

## OWASP Reference
[A01:2025 – Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/) — path traversal is explicitly listed under Mapped CWEs for this category.

## CWE Reference
[CWE-22](https://cwe.mitre.org/data/definitions/22.html) — Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
