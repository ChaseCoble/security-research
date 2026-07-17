# Web Secure Notes
**Platform:** Hack The Box
**Date:** 2026-07-17
**Category:** Web Exploitation
**Difficulty:** Easy
**Status:** Solved — [REDACTED: active challenge, <6 months]

## Vulnerability
Prototype pollution via an unsanitized `$rename` operator in the `/update` endpoint's MongoDB update path, escalating to authentication bypass on a separate `/flag` endpoint. The pollution targets a specific internal property (`_peername.address`/`_peername.family`) that Node's HTTP/net internals use to resolve `req.connection.remoteAddress` — allowing the reported "remote address" of any subsequent request to be overridden without an actual loopback connection.

## Discovery
- Full source provided via downloadable archive (standard HTB practice, zip password `hackthebox`)
- `app.js` reviewed in full: Express + Mongoose, single-file backend, no template engine, no outbound-HTTP libraries (`axios`/`fetch`/`http.get` all absent), no `child_process`/`eval`/`Function`/`vm`/`fs` usage anywhere in the source tree
- `/flag` route confirmed to gate access via `req.connection.remoteAddress`, accepting only `127.0.0.1`, `::1`, or `::ffff:127.0.0.1`
- Deployment config (`supervisord.conf`) confirmed no reverse proxy — `node app.js` and `mongod` run directly under supervisord, ruling out proxy-based header spoofing or SSRF-via-intermediary
- Extensive dead-end investigation before the actual vector was found, documented here for methodology transparency:
  - **SSRF** — ruled out; no outbound-request-capable library exists anywhere in the codebase
  - **SSTI** — ruled out; notes are stored/returned as raw strings with zero server-side template processing, confirmed by round-tripping `{{7*7}}` through `/create` and `/get/:id` unevaluated
  - **NoSQL injection via `noteId`** — confirmed real (arbitrary document match/enumeration via query-operator injection, e.g. `{"$ne": null}`), but does not by itself reach the flag
  - **Arbitrary field injection into the Note document** — ruled out; Mongoose's default `strict: true` schema silently drops unrecognized fields (tested with an `isAdmin` probe field, confirmed absent from the response)
  - **Generic prototype pollution probe** — initially tested with an arbitrary key (`{"__proto__":{"polluted":"yes"}}`) checked against an unrelated `/create` response; came back negative, incorrectly ruling out pollution as a category rather than recognizing the test needed to target a specific, real internal property name rather than an arbitrary probe key
  - **`$where` operator / Mongo server-side JS RCE** — considered but not fully pursued once recognized that even successful `$where` execution would run inside `mongod`'s JS context, a separate process from Node, with no access to `process.env.FLAG`
  - **Direct Docker/network-level bypass** (`--resolve`, forged headers) — ruled out on reasoning; `req.connection.remoteAddress` reads the actual TCP socket, not any client-supplied header, and `--resolve` cannot forge a real source IP over a real network connection
- Precise prototypes attained after web research. [Snyk Prototype Pollution](https://security.snyk.io/vuln/SNYK-JS-MONGOOSE-5777721)

## Exploitation
`/update`'s handler passes the entire raw request body into `Note.findByIdAndUpdate()` as the update document, with no filtering beyond Mongoose's schema-field strictness — which blocks *new* arbitrary fields on the Note schema itself, but does not block MongoDB update operators (`$rename`, `$set`, etc.) from being processed as valid update syntax, nor does it prevent those operators from targeting `__proto__`.

**Step 1 — create a note whose fields hold the values to be relocated:**
```json
POST /create
Content-Type: application/json

{"title":"127.0.0.1","content":"IPv4"}
```

**Step 2 — use `$rename` to move those field values onto `__proto__`'s internal connection-address properties:**
```json
POST /update
Content-Type: application/json

{"noteId":"<id_from_step_1>","$rename":{"title":"__proto__._peername.address","content":"__proto__._peername.family"}}
```

`$rename` is a native MongoDB update operator; because the update document is passed through unsanitized, `__proto__` is reachable as a target path. This pollutes `Object.prototype._peername`, setting `.address` and `.family` globally across the running Node process — including on the internal socket object that Node's HTTP layer consults when resolving `req.connection.remoteAddress` for any subsequent, unrelated request.

**Step 3 — request `/flag` normally, from outside:**
```json
GET /flag
Content-Type: application/json
```

With `Object.prototype._peername.address` now polluted to `127.0.0.1`, the `remoteAddress` check on the `/flag` handler reads the polluted value rather than the true (external) source address, and the check passes.

## Impact
Full authentication-boundary bypass on an IP-restricted internal endpoint, without ever establishing a genuine loopback connection. Demonstrates that IP-based access control implemented via `req.connection.remoteAddress` is not a reliable trust boundary when the application has any prototype-pollution-reachable code path — the check itself was correctly written, but the surrounding application's unsanitized MongoDB update logic undermined the property it relied on.

## Mitigations
**Primary:**
- Never pass raw, client-controlled request bodies directly into MongoDB update operations. Explicitly allowlist accepted fields and reject any body containing `$`-prefixed keys or `__proto__`/`constructor`/`prototype` before it reaches the database driver
- Use `Object.freeze(Object.prototype)` at application startup as a blanket defense against prototype pollution, or use a library (e.g. `mongo-sanitize`) that strips dangerous keys from user input before it reaches Mongoose/MongoDB

**Defense in depth:**
- Do not rely on `req.connection.remoteAddress` (or any single mutable-at-runtime object property) as a sole trust boundary for sensitive endpoints — pair it with a genuinely independent verification layer (e.g. a reverse proxy that strips/sets trusted headers before the app ever sees the request, with the app itself unable to reach or influence that layer)
- MongoDB driver-level or Mongoose-level protections against operator injection in update documents (reject `$`-prefixed top-level keys in any user-supplied update body by default)
- Regularly audit any endpoint that passes `req.body` (or any subset of it) directly into a database write operation without an explicit allowlist

## Conclusion
This challenge underscored the importance of tracking supply-chain security alongside application-level logic — the vulnerability wasn't a mistake unique to this app's code, but a known CVE (CVE-2023-3696) in Mongoose itself, patched in 7.3.4. The core failure predates any specific challenge: passing unsanitized user input into a recursive merge or update operation violates a basic secure-coding principle regardless of language or framework — mutable global state (here, `Object.prototype`) should never be reachable from untrusted input.

The deeper lesson was methodological, not just technical. Several plausible attack surfaces (SSRF, SSTI, generic pollution probing) were tested and correctly ruled out before the actual vector was found — that dead-end work wasn't wasted, it narrowed the problem space and built confidence in the eventual finding. The specific exploitation path (`$rename` targeting `_peername`) came from directed research into known Mongoose CVEs once the general pollution hypothesis was confirmed plausible, not from first-principles guessing. It is importable to be honest about that distinction, since recognizing when to pull from documented prior work versus continuing to brute-force a novel path is itself a skill worth building.

## OWASP Reference
[A01:2025 – Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/) — the finding's ultimate impact is an authorization/access-control bypass on an IP-restricted endpoint; the 2025 edition's expanded scope for this category explicitly covers authorization-failure patterns of this shape. Note: no OWASP source consulted gives an explicit, unambiguous category assignment for prototype pollution specifically — this mapping reflects the vulnerability's impact rather than a confirmed OWASP categorization, and is worth revisiting if OWASP publishes clearer guidance.

## CWE Reference
- [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html) — Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')
- [CWE-943](https://cwe.mitre.org/data/definitions/943.html) — Improper Neutralization of Special Elements in Data Query Logic

## Relevant CVEs
-[CVE-2023-3696](https://www.cve.org/CVERecord?id=CVE-2023-3696)
