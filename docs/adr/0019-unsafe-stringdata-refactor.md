# ADR-0019: `reflect.StringHeader` → `unsafe.StringData`

- **Status:** accepted
- **Date:** 2024-10-04
- **Version:** v3.3.0
- **PR:** [#1162](https://github.com/corazawaf/coraza/pull/1162)
- **Issue(s):** [#1147](https://github.com/corazawaf/coraza/issues/1147)
- **Deciders:** @Juneezee, @jcchavezs, @fzipi
- **Category:** Refactor

## Context and Problem

`internal/corazawaf/rule.go` used `reflect.StringHeader` for zero-copy
string/byte reinterpretation. Go 1.20 introduced `unsafe.StringData`, and
`reflect.StringHeader` was officially deprecated in Go 1.21. The lint
exception carried over from the OCSF Go-version bump
([ADR-0018](0018-ocsf-audit-log.md)) was a temporary band-aid.

## Decision Drivers

- Correctness: `reflect.StringHeader` is deprecated and its Godoc explicitly
  warns about GC-unsafe pointer handling.
- Remove the lint-exception debt left behind in PR #1089.
- Keep performance identical — the replacement is the GC-safe pointer
  accessor.

## Considered Options

- Keep the `StringHeader` pattern with a permanent lint exception.
- Port to `unsafe.StringData` as the upstream proposal suggests.

## Decision Outcome

Chosen: **port to `unsafe.StringData`.** The PR body cites the Godoc warnings
directly:

> "The Godoc of `reflect.StringHeader` states: 'the Data field is not
> sufficient to guarantee the data it references will not be garbage
> collected, so programs must keep a separate, correctly typed pointer to
> the underlying data.' … The replacement `unsafe.StringData` is a more
> correct way to get the pointer to the string data. The original proposal
> can be seen in golang/go#53003."
> — @Juneezee (PR body)

## Technical Discussion

No substantive architectural debate on the thread. One-line approval from
the reviewer:

> "The change looks very reasonable to me."
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/1162#issuecomment-2389453051))

## Participants

- @Juneezee — author
- @jcchavezs — review (approval)
- @fzipi — review

## Consequences

- **Positive:** Removes a deprecated API usage; GC-safe string/byte
  reinterpretation; lint exception deleted.
- **Negative:** None.

## References

- PR: https://github.com/corazawaf/coraza/pull/1162
- Issue: https://github.com/corazawaf/coraza/issues/1147
- Upstream proposal: https://github.com/golang/go/issues/53003
- Related ADRs: ADR-0018 (OCSF audit log)
