# Path Traversal - Validation of File Extension with Null Byte Bypass
**Platform:** PortSwigger Web Security Academy
**Date:** 2026-07-12
**Category:** Path Traversal
**Difficulty:** Practitioner

## Vulnerability
Static image pathing vulnerable to path traversal via the `filename` parameter. The application validates that the supplied filename *ends with* an expected file extension (e.g. `.png`), but the underlying filesystem call terminates string processing at a null byte — allowing an attacker to satisfy the extension check while the actual file lookup targets a different, unintended file.

## Discovery
- Identified `filename` parameter on `/image?filename=` as the injection point
- Tried a basic relative traversal sequence to `/etc/passwd` with no extension — failed, consistent with an extension-validation check rejecting the request
- Lab title confirmed the defense mechanism as file-extension validation with a null byte bypass
- Reasoned that many lower-level file-handling routines (historically common in C-based/legacy PHP stacks) treat a null byte as a string terminator — a string-based extension check would still see the full string including the fake extension, while the actual file-open call would stop at the null byte and ignore everything after it
- Constructed a payload combining a relative traversal sequence to `/etc/passwd`, followed by a URL-encoded null byte (`%00`), followed by a valid image extension (`.png`)
- Sent via Repeater — returned `/etc/passwd` contents

## Exploitation
Intercepted the image request in Burp Proxy and rewrote the `filename` parameter to a relative traversal sequence targeting `/etc/passwd`, appended with a URL-encoded null byte and a trailing fake extension to satisfy the application's extension check.

```http
GET /image?filename=../../../../../../etc/passwd%00.png HTTP/2
Host: 0a8500a704e213c780581c88009700fa.web-security-academy.net
Cookie: session=[REDACTED]
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a8500a704e213c780581c88009700fa.web-security-academy.net/
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: same-origin
Priority: u=5
Te: trailers
```

Mechanism: the application's extension-validation logic performs a string-based check (e.g. confirming the filename ends in `.png`) against the full supplied string, which does end in `.png` and therefore passes. The subsequent file-open operation, however, is handled by a lower-level routine that treats the null byte as a string terminator — it stops reading the filename at that point and never processes the `.png` suffix at all, resolving the traversal sequence and opening `/etc/passwd` directly. The two components of the system (the validation layer and the file-access layer) disagree on where the string ends, and that disagreement is the exploitable gap.

## Impact
Arbitrary file read on the underlying filesystem, identical in scope to prior path traversal labs — demonstrated against `/etc/passwd`, extends to any file readable by the web server process, regardless of what extension the application expects.

## Mitigations
**Primary:**
- Canonicalize the resolved path (`realpath()` or equivalent) and verify it falls within the intended base directory — extension checks alone are not a security boundary
- Use an allowlist of valid filenames or an indirect reference (e.g. database ID → filename mapping) rather than accepting a raw path component from the client

**Defense in depth:**
- Do not rely on string-based extension validation as a security control — this lab demonstrates the classic null-byte disagreement between validation and file-access layers. Modern language runtimes with proper string types (rather than null-terminated C-style strings) are less susceptible, but the underlying pattern (two layers disagreeing on input boundaries) generalizes beyond null bytes specifically
- Run the web server process with least-privilege filesystem permissions
- Containerization/chroot to physically limit filesystem access independent of application-layer validation

## OWASP Reference
[A01:2025 – Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/) — path traversal is explicitly listed under Mapped CWEs for this category.

## CWE Reference
- [CWE-22](https://cwe.mitre.org/data/definitions/22.html) — Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- [CWE-158](https://cwe.mitre.org/data/definitions/158.html) — Improper Neutralization of Null Byte or NUL Character
