# Secure Server
**Platform:** Hack The Box
**Date:** 2026-07-19
**Category:** Secure Coding
**Difficulty:** Easy
**Status:** Solved — [REDACTED: active challenge, <6 months]

## Vulnerability
Unrestricted local file inclusion via `include()` in `our-projects.php`, where a user-controlled `project` GET parameter was concatenated directly into an include path with no path validation. The same flaw was checker-tested two distinct ways — direct traversal to a system file, and a two-step chain (poison a log file via a header, then traverse to and execute it) — both closed by a single directory-scoping fix, since both attack demonstrations shared the same root cause.

## Discovery
- Challenge format: full source access via CIFS mount (`//<IP>/app`), edits validated by a separate checker service; no shell access to the running instance
- Review of the PHP source: `index.php`, `about-us.php`, `navbar.php`, `our-projects.php` — small, fully enumerable file set
- Vulnerable line identified in `our-projects.php`:
```php
  include "../projects/" . $project;
```
  `$project` taken from `$_GET['project']`, lowercased, otherwise unvalidated
- A declared `$allProjects` allowlist array existed in the same file but was never actually used to gate the include — confirmed dead code by testing an arbitrary nonsense project name against the checker's functionality suite, which required it to still return a page (ruling out a simple allowlist-based fix)
- Provided exploit script demonstrated two ostensibly separate vectors:
  1. Direct traversal (`project=../../../../var/log` or equivalent) to read arbitrary files
  2. A chained attack: a PHP payload (`<?php system('whoami') ?>`) sent as the `User-Agent` header to `/`, followed by a traversal request targeting nginx's own `access.log` — reasoning being that nginx logs the `User-Agent` header verbatim on every request, and if that log file could subsequently be `include()`'d, the embedded PHP would execute
- Significant investigation time spent misattributing the second vector to `index.php` specifically, based on the checker script returning that only one vulnerability had been patched, that fueled an assumption that the checker's "Vulnerability 2" required a distinct fix location from Vulnerability 1. This hypothesis was tested and ultimately disproven:
  - Confirmed no PHP file in the application reads `$_SERVER['HTTP_USER_AGENT']`, `getallheaders()`, or any request header data anywhere
  - Confirmed no accessible nginx or PHP-FPM configuration existed within the provided file set
  - A defensive header-validation block was added to `index.php` (rejecting requests containing `<?php` in the `User-Agent` string).
  - Root cause of the extended dead end: Earlier testing sessions had already injected into the log and checker script continued to assert the second vulnerability was unpatched. A new session and identical patch to our-projects.php cleared both vulnerabilities.
- Direct log evidence (captured mid-session, from the checker's own validation traffic) confirmed the full chain was genuinely exploitable pre-fix: a request bearing `User-Agent: www-data` was observed in `access.log`, itself the output of a prior, successful `whoami` execution being reused as a subsequent request's header, concrete proof the log-poisoning-to-RCE chain worked end-to-end on the unpatched application
- Renewal of the instance and reapplication of the `our-projects.php`  patch cleared both vulnerabilities.

## Exploitation
[Redacted: exact traversal depth and payload strings, per active-challenge policy]

The vulnerable `include()` accepted any value for `project`, resolved relative to the application directory, with no boundary check. Two demonstration paths existed:

1. Direct traversal to a sensitive file, causing its contents to be returned as page content (and, since `include()` executes PHP rather than merely displaying it, causing any embedded PHP to run if the target file's content happened to be interpretable as such)
2. A header-poisoning chain: send a PHP payload as `User-Agent` to any endpoint (nginx logs it into `access.log` regardless of what the PHP application does with the request), then traverse to and `include()` that log file, causing the embedded payload to execute as part of PHP parsing the "file"

## Fix
Replaced the raw string-concatenation include with canonicalized path resolution, scoping all includes to the intended `projects/` directory regardless of input:

```php
$baseDir = realpath(__DIR__ . "/../projects");
$candidate = realpath($baseDir . "/" . $project);

if ($candidate === false || strpos($candidate, $baseDir) !== 0) {
    // reject — resolves outside intended directory, or does not exist
} else {
    include $candidate;
}
```

`realpath()` fully resolves the candidate path (collapsing any `../` sequences, following the real filesystem structure) before any decision is made — the check validates the *destination*, not the *input string*, which is not bypassable by encoding tricks, nested traversal sequences, or similar blocklist-evasion techniques (all previously demonstrated as effective against naive string-filtering defenses in a separate set of path traversal labs this same prep cycle).

This single fix closed both checker-reported vulnerabilities simultaneously, confirmed via direct before/after comparison: the unpatched instance returned full log contents (including embedded proof of prior successful code execution) through the traversal endpoint; the patched instance returned an empty response body at the same injection point, with the `realpath()`/prefix check correctly rejecting a path resolving outside `projects/`.

## Impact
Arbitrary local file inclusion, escalating to remote code execution when combined with any file the attacker could influence the content of, in this case, the web server's own access log, populated via a completely unauthenticated header value on any request.

## Mitigations
**Primary:**
- Canonicalize the resolved path (`realpath()` or equivalent) and verify it falls within the intended base directory before any file operation — never validate the raw input string, only the fully-resolved destination
- Never use a code-executing function (`include`/`require`) to display content that is meant to be inert — a strict content/display separation (e.g. `readfile()` or `file_get_contents()` + `echo`) removes the RCE escalation path entirely, independent of whether the traversal boundary itself is ever bypassed by some future bug

**Defense in depth:**
- Enforce and actually apply an allowlist for known-valid values where the legitimate value set is genuinely fixed — note this challenge specifically required dynamic, non-allowlisted filenames to remain functional, illustrating that allowlisting isn't always available as a defense and canonicalization is the more broadly applicable control
- Least-privilege filesystem permissions for the web server process, limiting blast radius even if a traversal boundary is bypassed
- Avoid resolving application include paths relative to an ambient working directory (`../projects/`) in favor of an absolute reference anchored to the script's own known location (`__DIR__`), removing ambiguity about what the base path actually resolves to at runtime

## OWASP Reference
[A01:2025 – Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/) — path traversal / local file inclusion is a recognized access-control failure pattern under this category.

## CWE Reference
- [CWE-22](https://cwe.mitre.org/data/definitions/22.html) — Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- [CWE-98](https://cwe.mitre.org/data/definitions/98.html) — Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')

## Lessons Learned (Methodology)
The largest time cost in this challenge was not identifying the vulnerable code, that was found very quickly, but that the instance was not as closely  monitored as it should have been. Since logging was involved, the instance should have been renewed alot earlier when any change was made to the behaviour of the checker script. Trusting the checker's result without accounting fora  mutable, already-pooisoned log meant a correct fix appeared to fail, sending the investigation down an uneccesary alternate path.
