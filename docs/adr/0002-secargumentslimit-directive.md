# ADR-0002: `SecArgumentsLimit` directive

- **Status:** accepted
- **Date:** 2023-06-14
- **Version:** v3.0.2
- **PR:** [#812](https://github.com/corazawaf/coraza/pull/812)
- **Issue(s):** No linked issue
- **Deciders:** @potats0, @jptosso, @jcchavezs, @fzipi, @M4tteoP, @anuraaga, @airween, @theseion
- **Category:** Parity (ModSecurity parity)

## Context and Problem

Coraza accepted unbounded numbers of parsed arguments, leaving it open to
parameter-pollution and resource-exhaustion attacks. ModSecurity documents a
`SecArgumentsLimit` directive (default 1000) for this; Coraza had none.

## Decision Drivers

- ModSecurity parity — the directive already exists in the reference
  implementation.
- Hard bound on argument count to protect against DoS.
- Keep the cost of enforcement close to the public entrypoint rather than
  duplicating it in every body processor.

## Considered Options

- Enforce the limit inside every body processor (JSON, urlencoded, XML, …).
- Enforce the limit only on the public `addArguments` helper that feeds the
  `ARGS_GET`/`ARGS_POST` collections, and leave body-processor-internal writes
  for a follow-up.
- Implement a new bounded collection type that self-enforces the cap.

## Decision Outcome

Chosen: **enforce on the public helper that wraps `ARGS_GET` / `ARGS_POST`**,
default 1000, documented as a known gap for body-processor writes. A helper
function was introduced so the check is not duplicated across the three writer
call sites.

## Technical Discussion

Extensive review (30+ inline comments). Three themes drove the final shape.

**1. Scope of enforcement.** @jptosso flagged early that body processors bypass
the helper and therefore the limit:

> "Internally coraza doesn't consume this functions, as we directly write into
> de collections, so even with this implementation we would still get unlimited
> arguments from body processors. It will only apply for ArgsGet and ArgsPath.
> My idea would be to create a new collection that implements Map, and add a
> validation." — @jptosso ([comment](https://github.com/corazawaf/coraza/pull/812#issuecomment-1588401916))

@jcchavezs accepted the narrower scope to unblock the merge:

> "I believe we can accept this PR as it is now and tackle the lack of internal
> validation in a next PR."
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/812#issuecomment-1589536399))

**2. Default value.** @jptosso asked for the missing default of 1000 per
ModSecurity docs; the PR was updated to match.

**3. API shape.** A `Len()` method was added to the collection. @jptosso noted
idiomatic Go:

> "`Len() int` is the standard for Length in golang"
> — @jptosso ([review comment](https://github.com/corazawaf/coraza/pull/812#discussion_r1227428689))

`Length` was renamed to `Len` accordingly, and a helper was extracted so the
check is not duplicated across the three writer call sites.

## Participants

- @potats0 — author
- @jptosso — review, drove scope clarification and API naming
- @jcchavezs — review, approved narrower scope, asked for `0` validation
- @fzipi — review, suggestion edits on `Len()` call sites
- @M4tteoP, @anuraaga, @airween, @theseion — review

## Consequences

- **Positive:** Public argument intake is bounded by default; `ARGS_GET` and
  `ARGS_POST` cannot grow unboundedly from attacker-supplied inputs.
- **Negative / follow-up:** Body-processor-internal writes are still unbounded
  until a bounded `Map` collection lands. This was explicitly deferred.

## References

- PR: https://github.com/corazawaf/coraza/pull/812
- ModSecurity reference: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#secargumentslimit
- Related ADRs: ADR-0001 (RESPONSE_ARGS collection)
