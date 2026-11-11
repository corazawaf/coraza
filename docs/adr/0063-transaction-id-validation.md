# ADR-0063: Replace transaction IDs that cannot be a path element or a log field

- **Status:** proposed
- **Date:** 2026-10-18 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** [#1743](https://github.com/corazawaf/coraza/pull/1743)
- **Issue(s):** [#1686](https://github.com/corazawaf/coraza/issues/1686)
- **Deciders:** @adilalperenciftci
- **Category:** Feature (security hardening)

## Context and Problem

`concurrentWriter.Write` builds the audit record file name as
`<timestamp>-<transaction id>` and passes it through `path.Join`, so an ID such
as `../../../../ESCAPED` writes the record outside `SecAuditLogStorageDir`. The
same ID is printed verbatim in the concurrent index line, where a `\n` forges a
second entry. Coraza's own IDs come from `RandomString` and are safe, but
`NewTransactionWithID` and `experimental.Options{ID}` accept anything, and
connectors that take the ID from an upstream request header (coraza-caddy#248)
hand attacker input to both sinks.

Nothing told a caller what an acceptable ID is. `NewTransactionWithID` did not
document that the value ends up in a file name, and `NewTransactionWithOptions`
(the path used by `http/middleware.go`) skips the `TrimSpace` that the wrapper
applies.

## Decision Drivers

- Close the traversal at the one place every ID passes through, so a fourth
  sink does not need its own fix.
- Keep the file name, the record's `id` field and the index line identical; the
  concurrent index exists to correlate them.
- Not a breaking change for real IDs: UUIDs, Envoy `x-request-id`, Caddy IDs,
  W3C `traceparent` values must keep working unchanged.

## Considered Options

- Map unsafe bytes to `_` in the concurrent writer only (proposed in the issue).
- Return an error / refuse the transaction when the ID is unsafe.
- Define an ID grammar (for example the W3C Trace Context format) and enforce it.
- Refuse only the bytes that break a path element or a single-line log field
  (`/`, `\`, ASCII control characters), and generate a random ID in their place.

## Decision Outcome

Chosen: **refuse only path separators and control characters, and replace the
ID with a generated one**, checked in `WAF.NewTransactionWithOptions`, which
both `NewTransactionWithID` and the experimental options API go through. A
warning is logged without copying the rejected value into the log sink.

Sanitizing in the writer would rename the file while the record and the index
kept the raw value, breaking the correlation the format is for. Returning an
error is not possible without changing the `NewTransaction*` signatures, and a
nil transaction would panic in every existing caller. A grammar would reject
IDs connectors already pass today. `..` alone is not refused: the ID is always
appended to a `<timestamp>-` prefix, so it can never be a complete path element.

The concurrent writer additionally refuses to write a record whose ID contains
a separator or a control character and escapes the ID in the index line with the same `logEscaper` the
native formatter uses for Part A. These are not reachable through the public
API after the check above, but `AuditLogWriter` is a plugin surface and can be
handed an `AuditLog` built elsewhere.

## Technical Discussion

> "[…] Rejecting the ID, or substituting a generated one and logging a warning, keeps the three representations consistent. A caller passing path separators or control characters in a transaction ID is already misusing the API, so failing loudly seems better than silently rewriting.
>
> Suggested shape: constrain the ID once in `newTransaction`, and keep escaping at the two log sinks as defence in depth, since those stay relevant even for a valid-but-odd ID that no longer threatens the filesystem."
> — @fzipi ([comment](https://github.com/corazawaf/coraza/issues/1686#issuecomment-5396251238))

> "[…] The constraint should follow from what Coraza does with the value: it becomes a path element and a single-line log field. So "no path separators, no control characters, no `..`", not "must be 32 lowercase hex"."
> — @fzipi ([comment](https://github.com/corazawaf/coraza/issues/1686#issuecomment-5396289118))

> "Looks reasonable to me to sanitize it in order to prevent any path traversal attempts. Still, I would avoid being strict about the syntax to keep this from becoming a breaking change."
> — @M4tteoP ([comment](https://github.com/corazawaf/coraza/issues/1686#issuecomment-5440035991))

## Consequences

- For an ID with `/`, `\` or a control character, the transaction,
  `UNIQUE_ID`, the audit record and the index all carry the generated ID; the
  rejected value is not logged. Connectors that relied on such IDs lose
  correlation for those requests.
- Every other ID is used byte for byte, as before.

## References

- [#1686](https://github.com/corazawaf/coraza/issues/1686)
- [coraza-caddy#248](https://github.com/corazawaf/coraza-caddy/pull/248)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)

## Participants

- @adilalperenciftci — author
- @fzipi — issue triage and proposed shape
- @M4tteoP — issue review
