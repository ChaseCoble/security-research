## Mongo Operator Cheat Sheet — Personal Reference

| Operator | Reach for it when... | Danger shape |
|---|---|---|
| `$ne`/`$gt`/`$lt` | a field expects an exact string/ID match | bypass filter, match arbitrary doc |
| `$regex` | a field takes a string, no type check | enumerate/extract char-by-char |
| `$in`/`$nin` | small guessable candidate set | batch existence-check |
| `$rename` | raw body reaches an unsanitized write call | relocate value → `__proto__.X` |
| `$set` | raw body reaches an unsanitized write call | overwrite arbitrary field incl. `__proto__` |
| `$where`/`$function` | need code exec, target is Mongo itself | RCE in **mongod**, NOT the app process |
| `$expr` (in `$match`) | aggregation pipeline built from input | same risk as `$where`, aggregation context |

**The actual trigger, every time:** raw `req.body` (or a piece of it) reaches a write endpoint(for rename/set) or read endpoint(for regex,ne, etc)  with no allowlist. That's the thing to grep for first, not the operator list.

**The mistake I made:** tested pollution with a throwaway probe key (`polluted`) and got a false negative — schema strictness blocks *new* fields, but not operators like `$rename` targeting `__proto__`. Pollution tests need to target a **real property name something downstream actually reads** (e.g. `_peername.address`), not an arbitrary probe.

**Relevant Initial Writeup**
- [Secure Notes](../htb/challenges/01-secure-notes.md)
