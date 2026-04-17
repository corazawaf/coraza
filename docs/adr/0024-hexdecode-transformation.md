# ADR-0024: `hexDecode` transformation

- **Status:** accepted
- **Date:** 2025-01-24
- **Version:** v3.3.2
- **PR:** [#1275](https://github.com/corazawaf/coraza/pull/1275)
- **Issue(s):** [#1253](https://github.com/corazawaf/coraza/issues/1253)
- **Deciders:** @tty2, @fzipi, @jptosso
- **Category:** Parity (ModSecurity parity)

## Context and Problem

ModSecurity exposes a `hexDecode` transformation (reverse of hex/base-16
encoding). Coraza had `hexEncode` but not its counterpart, which left a small
parity gap.

## Decision Drivers

- ModSecurity parity.
- Behaviour on malformed input — follow the existing "best-effort" precedent
  set by other transformations.

## Considered Options

- Strict parse: reject on any non-hex character.
- Best-effort: trim odd trailing nibbles, decode what's valid.

## Decision Outcome

Chosen: **best-effort decode**, following the existing pattern used by sibling
transformations. This was a question explicitly raised and resolved in review.

> "This PR is mostly based on assumptions cause I didn't get any reply here
> [#1253]. The main assumption is that coraza wants to go 'best effort
> approach'. This assumption is based on the tests … Relying on tests we
> need to remove the last symbol."
> — @tty2 ([review](https://github.com/corazawaf/coraza/pull/1275#discussion_r1905517040))

## Technical Discussion

The substantive discussion was about how to interpret an odd-length input
(technically malformed per hex/base-16 encoding):

> "What does this mean? Can you provide pointers? 'hex' enconding, in the
> RFC you are mentioning, is just Base16 where each byte is represented as
> two four bits. So, AFAIU, we are only removing the _last_ input to make an
> effort to fix a broken input, right? Could the problem be the first
> instead?"
> — @fzipi ([review](https://github.com/corazawaf/coraza/pull/1275#discussion_r1905465117))

The decision was to follow the precedent set by other transformations'
existing test expectations (best-effort, trim trailing).

## Participants

- @tty2 — author
- @fzipi — review (behaviour on malformed input)
- @jptosso — review

## Consequences

- **Positive:** `t:hexDecode` works for ModSecurity-migrated rulesets.
- **Negative:** The "best-effort" choice on malformed input matches existing
  coraza behaviour but is not strictly RFC-correct. Documented inline.

## References

- PR: https://github.com/corazawaf/coraza/pull/1275
- Issue: https://github.com/corazawaf/coraza/issues/1253
