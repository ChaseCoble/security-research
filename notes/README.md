# CTF & Lab Writeup Index
**Maintained by:** Chase Coble (CobleSecurity)
**Repo:** github.com/ChaseCoble/security-research

Personal index of notes constructed while studying the discipline, tagged by technology/category so a specific technique can be found fast without re-reading full writeups. Click a tag to jump to that section; each entry links to the full writeup file.

## How to use this
- **Tags** are technologies/concepts present in the finding — a single note usually carries several
- **Cheat sheet** column links to a condensed personal-reference file, if one exists for that technique — these are the fast-recall notes, not the full writeup, the notes will link to the writeup

---

## Jump to tag
[Web](#web) · [Express](#express) · [MongoDB](#mongodb) · [NoSQL Injection](#nosql-injection) · [Prototype Pollution](#prototype-pollution) · [Path Traversal](#path-traversal) · [SQL Injection](#sql-injection) · [Authentication](#authentication) · [SSRF](#ssrf) · [SSTI](#ssti) · [Command Injection](#command-injection) · [Crypto](#crypto) · [PWN](#pwn) · [Reverse Engineering](#reverse-engineering) · [Forensics](#forensics) · [Mongoose](#mongoose) · [Deserialization Exploits](#deserialization-exploits)

---

## Master

| Date | Tags | Cheat Sheet | Red Flag |
|---|---|---|---|
| 2026-07-17 | Web, Express, MongoDB, NoSQL Injection, Prototype Pollution, Mongoose, Deserialization | [Mongo Operators](mongo-operators.md) | Mongoose <7.3.4 in same container as the web app |

## Web
- [Mongo Operators](mongo-operators.md) - NoSql injection for Object Prototype Pollution

## Express
- [Mongo Operators](mongo-operators.md) - Tangential - Express is used with MongoDB in MERN stack

## MongoDB
- [Mongo Operators](mongo-operators.md) - Exploit found in Mongoose, a MongoDB ORM

## NoSQL Injection
- [Mongo Operators](mongo-operators.md) — `$ne`/`$rename` operator injection via unsanitized `req.body`

## Prototype Pollution
- [Mongo Operators](mongo-operators.md) — `$rename` → `__proto__._peername` → auth bypass

## Path Traversal
*(none  yet)*

## SQL Injection
*(none  yet)*

## Authentication
*(none  yet)*

## SSRF
*(none yet)*

## SSTI
*(none yet — ruled out during Web Secure Notes investigation, see writeup Discovery section)*

## Command Injection
*(none yet this cycle)*

## Crypto
*(none yet this cycle)*

## PWN
*(none yet — insurance prep pending)*

## Reverse Engineering
*(none yet — insurance prep pending)*

## Forensics
*(none  yet)*

## Mongoose
ORM for MongoDB in Express
- [Mongo Operators](mongo-operators.md) - Mongoose unsafely deserializes mongo commands inside fields

## Deserialization Errors
- [Mongo Operators](mongo-operators.md) - Targets Mongoose < 7.3.4 deserialization process allowing unsafe operators to execute in the enviroment.
*Update this file after every writeup — add the row to the relevant platform table above, add a line under each applicable tag section, and add/update a cheat sheet entry if the finding produced one.*
