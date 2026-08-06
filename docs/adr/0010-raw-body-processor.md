# ADR-0010: `raw` request body processor

- **Status:** accepted
- **Date:** 2024-02-06
- **Version:** v3.1.0
- **PR:** [#983](https://github.com/corazawaf/coraza/pull/983)
- **Issue(s):** Discussion [#938](https://github.com/corazawaf/coraza/issues/938)
- **Deciders:** @blotus, @jcchavezs, @anuraaga
- **Category:** Feature

## Context and Problem

The existing body processors (URLENCODED, MULTIPART, XML, JSON) all attempt to
parse the body. For content types without a dedicated parser — or for rules
that simply want to inspect bytes — Coraza had no way to skip parsing while
still retaining the raw body for `REQUEST_BODY` rules.

## Decision Drivers

- Let rule authors opt *out* of structured parsing for specific content types
  (e.g. `application/octet-stream`, vendor-proprietary payloads).
- Provide a fallback processor that can be wired in via
  `ctl:requestBodyProcessor=RAW`.
- Minimise allocations — the processor is on the request hot path.

## Considered Options

- Make "no processor" implicit when no match is found.
- Ship an explicit `RAW` processor that copies the body into a
  `REQBODY_PROCESSOR=RAW`-marked transaction.

## Decision Outcome

Chosen: **explicit `RAW` processor**, switchable via
`ctl:requestBodyProcessor=RAW`. The PR body shows the canonical CRS-style
configuration that catches "anything not handled":

```
SecRule REQBODY_PROCESSOR "!@rx (?:URLENCODED|MULTIPART|XML|JSON)"
  "id:105,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=RAW"
```

## Technical Discussion

Discussion focused on allocation hygiene and interface cleanup. @anuraaga
suggested a `strings.Builder` + `io.Copy` path for lower allocation pressure:

> "`var buf strings.Builder; if _, err := io.Copy(&buf, reader); err != nil { … }`
> — Generally can't be sure of eliding heap allocations but worth trying"
> — @anuraaga ([review](https://github.com/corazawaf/coraza/pull/983#discussion_r1479118293))

@jcchavezs pushed for `b.Len()` over a manual length tracker and unused
parameter cleanup:

> "Shall we use `b.Len` here? https://pkg.go.dev/strings#Builder.Len"
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/983#discussion_r1478399917))

> "nit: you can remove the param names as they aren't used."
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/983#discussion_r1478401110))

Both were applied.

## Participants

- @blotus — author
- @jcchavezs — review (API cleanup, `Len()`)
- @anuraaga — review (allocation pattern)

## Consequences

- **Positive:** Rule authors can inspect unparsed bodies for any content
  type; CRS-style fallback configuration becomes expressible.
- **Negative / follow-up:** RAW bodies go through memory — large-body
  protections (`SecRequestBodyLimit`) become the only guardrail.

## References

- PR: https://github.com/corazawaf/coraza/pull/983
- Motivating discussion: https://github.com/corazawaf/coraza/issues/938
- Related ADRs: ADR-0030 (`SecRequestBodyJsonDepthLimit`), ADR-0048 (NDJSON
  body processor)
