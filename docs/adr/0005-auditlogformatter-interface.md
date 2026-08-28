# ADR-0005: `AuditLogFormatter` becomes an interface

- **Status:** accepted
- **Date:** 2023-08-06
- **Version:** v3.0.3
- **PR:** [#850](https://github.com/corazawaf/coraza/pull/850)
- **Issue(s):** No linked issue (follows PR [#826](https://github.com/corazawaf/coraza/pull/826))
- **Deciders:** @jptosso, @anuraaga, @jcchavezs
- **Category:** Refactor (breaking within experimental plugin surface)

## Context and Problem

The HTTPS audit log writer ([ADR-0003](0003-https-audit-log-writer.md))
needed to set a `Content-Type` per formatter. The existing formatter API was a
bare function type:

```go
type AuditLogFormatter func(plugintypes.AuditLog) ([]byte, error)
```

A function cannot carry a MIME type. The formatter needed to become
self-describing.

## Decision Drivers

- The HTTPS writer must know the formatter's content type.
- The formatter plugin API is still experimental, so a breaking shape change
  is acceptable now — cheaper than later.
- Keep plugin implementation effort minimal (two methods per formatter).

## Considered Options

- Keep the function type and ship a parallel lookup table for MIME types.
- Replace the function type with an interface carrying `Format()` + `MIME()`.
- Attach metadata via a wrapper struct that still embeds the function.

## Decision Outcome

Chosen: **replace the function type with an interface.** `anuraaga` proposed
it directly; `jcchavezs` accepted in one line.

> "I think content type should be on the formatter, not https writer. Since
> it's still experimental API, we can change formatter, how about making it an
> actual type with `Format()` and `ContentType()` methods?"
> — @anuraaga ([review](https://github.com/corazawaf/coraza/pull/850#discussion_r1274245227))

> "Brilliant. Let's do it."
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/850#discussion_r1275034260))

The PR renamed `ContentType()` to `MIME()` during iteration. All built-in
formatters (`nativeFormatter`, `jsonFormatter`, `legacyJSONFormatter`, and the
test formatter) implement the interface. Compile-time assertions were added.

## Technical Discussion

@jcchavezs argued against permissive matching on the writer side:

> "Is HasPrefix accurate? Can't we do direct comparison equality?"
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/850#discussion_r1274124841))

@jptosso defended prefix matching for parameterised content types:

> "Im most cases yes, but at some point it would be right to use
> `application/json;encoding=utf-8`, like the automatic mime detection does"
> — @jptosso ([review](https://github.com/corazawaf/coraza/pull/850#discussion_r1274134624))

Prefix matching on MIME was kept; strict equality would have misfired on
parameterised content types.

## Participants

- @jptosso — author
- @anuraaga — review (proposed the interface shape)
- @jcchavezs — review (many formatter conformance suggestions)

## Consequences

- **Positive:** Formatters are self-describing for MIME type; new transport
  writers (HTTPS now, syslog later — [ADR-0028](0028-syslog-audit-log-writer.md))
  can decide framing from the formatter alone.
- **Negative:** One-time breaking change for out-of-tree formatter plugins —
  they must grow a `MIME()` method. Acceptable because the plugin API is
  declared experimental.

## References

- PR: https://github.com/corazawaf/coraza/pull/850
- Related ADRs: ADR-0003 (HTTPS audit log writer), ADR-0028 (syslog audit
  writer), ADR-0018 (OCSF audit log format)
