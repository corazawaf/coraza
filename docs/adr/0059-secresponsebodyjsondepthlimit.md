# ADR-0059: `SecResponseBodyJsonDepthLimit` directive

- **Status:** proposed
- **Date:** 2026-09-26 (expected; update before merge)
- **Version:** unreleased (post-v3.7.0)
- **PR:** GHSA-3c6w-j9xm-8h2h fix — developed on the advisory's private fork;
  no public PR exists yet (see [Security](../../AGENTS.md#security))
- **Issue(s):** No linked issue — reported through the private security
  advisory GHSA-3c6w-j9xm-8h2h
- **Deciders:** @fzipi
- **Category:** Feature

## Context and Problem

`jsonBodyProcessor.ProcessResponse` parsed response bodies with no recursion
limit: it called `readJSON(ss, ignoreJSONRecursionLimit)` where
`ignoreJSONRecursionLimit = -1`, and the depth guard in `readItems` only fires
on `maxRecursion == 0`. Counting down from `-1` never reaches `0`, so the
guard was dead on the response path. `ProcessRequest` has been bounded since
ADR-0030 (`SecRequestBodyJsonDepthLimit`, default 1024); there was never an
equivalent directive or default for responses, and `ProcessResponse` even
discarded its `BodyProcessorOptions` parameter (`_`), so a caller could not
set a limit even if it wanted to.

Because each nesting level re-parses the remaining document through
`gjson.ForEach`, total work is `O(depth²)`. A 512 KiB nested JSON response
(the default `ResponseBodyLimit`) holds about 87,000 levels and measured
~12s of single-core CPU time to process — a CPU-exhaustion DoS for any
deployment with `SecResponseBodyAccess On` and a backend whose JSON response
structure is shaped by attacker input (e.g. an echo/validation-error
endpoint, GraphQL response nesting mirroring query nesting, or a
store-and-retrieve JSON blob API).

## Decision Drivers

- Bound response-side JSON recursion the same way ADR-0030 bounded the
  request side, instead of designing a new shape for the same problem.
- Keep the fix backward compatible: `BodyProcessorOptions` is public API
  (`experimental/plugins/plugintypes`), so the new field must be additive.
- Preserve operator control: the limit must be directive-tunable, not just a
  hardcoded constant, matching the request-side precedent.

## Considered Options

- Reuse `RequestBodyRecursionLimit` / `SecRequestBodyJsonDepthLimit` for both
  directions (single knob).
- Hardcode a fixed internal limit for responses with no directive.
- Add a dedicated `SecResponseBodyJsonDepthLimit` directive, a
  `ResponseBodyJsonDepthLimit` WAF field, and a `ResponseBodyRecursionLimit`
  option, mirroring ADR-0030's request-side shape exactly.

## Decision Outcome

Chosen: **dedicated `SecResponseBodyJsonDepthLimit` directive** (default
1024, same default as the request side), plumbed through a new
`ResponseBodyRecursionLimit` field on `BodyProcessorOptions` and a new
`ResponseBodyJsonDepthLimit` field on `WAF`, exactly mirroring the reviewed
request-side design instead of reusing one knob for two independently
configurable resource budgets (a single `Request...`-named directive
governing response traffic would also be a confusing SecLang surface).

## Technical Discussion

No substantive technical discussion recorded for this ADR — it was authored
directly against a private security advisory, before any PR review. The
shape it reuses was already argued and settled in ADR-0030's review thread,
including the objection this fix specifically resolves for the response
side:

> "I think it should never be -1 and always force a limit."
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1110#discussion_r1685791885))

## Participants

- @fzipi — author (fix authored against GHSA-3c6w-j9xm-8h2h)

## Consequences

- **Positive:** the response-body JSON DoS class (unbounded `O(depth²)`
  recursion) is neutralised by default, symmetric with the request path.
  The new `BodyProcessorOptions` field is additive and does not break
  existing callers of the public plugin API.
- **Negative / follow-up:** operators with backends that legitimately return
  very deeply nested JSON responses will need to raise
  `SecResponseBodyJsonDepthLimit`, same operational tradeoff already
  accepted for `SecRequestBodyJsonDepthLimit` in ADR-0030.

## References

- Advisory: GHSA-3c6w-j9xm-8h2h (private at the time of writing)
- Related ADRs: ADR-0030 (`SecRequestBodyJsonDepthLimit`)
