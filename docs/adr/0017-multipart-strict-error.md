# ADR-0017: Set `MULTIPART_STRICT_ERROR` on multipart parse failure

- **Status:** accepted
- **Date:** 2024-07-18
- **Version:** v3.3.0
- **PR:** [#1098](https://github.com/corazawaf/coraza/pull/1098)
- **Issue(s):** No linked issue
- **Deciders:** @fzipi, @M4tteoP
- **Category:** Parity (ModSecurity variable parity + recommended-config alignment)

## Context and Problem

`coraza.conf-recommended` referenced `MULTIPART_STRICT_ERROR` to detect
multipart evasions, but Coraza never actually set it — the variable was dead,
so any rule using it was silently inert. Coraza's multipart parser also does
not implement every ModSecurity sub-variable, so a single "something went
wrong" signal was needed as a replacement.

## Decision Drivers

- The recommended config must actually work out of the box.
- Provide a single global failure signal when the parser cannot fully trust
  a multipart body, regardless of which sub-variable fired in ModSecurity.

## Considered Options

- Implement every ModSecurity multipart sub-variable (large effort).
- Set a single `MULTIPART_STRICT_ERROR=1` on any parse failure; rewrite the
  recommended config rules to use it.

## Decision Outcome

Chosen: **single global failure signal + rewrite recommended rules**.
@M4tteoP pushed for the recommended config to show only variables Coraza
actually supports, so operators are not misled:

> "I would also make the rule output more aligned to Coraza removing all
> these variables that can confuse a user without the context of where this
> rule is coming from."
> — @M4tteoP ([comment](https://github.com/corazawaf/coraza/pull/1098#issuecomment-2236872455))

> "We are also recommending this rule: `SecRule MULTIPART_UNMATCHED_BOUNDARY
> \"@eq 1\" …` But that variable is never set, so that rule cannot be
> triggered by any means."
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1098#issuecomment-2236896425))

> "Updated the coraza.conf-recommended to a more realistic one."
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1098#issuecomment-2237381208))

## Technical Discussion

Follow-up for an engine-level regression test was captured for a future PR:

> "Eventually for a follow-up PR, would be great to also have an engine test
> (under `testing/engine`) that triggers this rule, for an e2e-like test of
> the feature"
> — @M4tteoP ([review](https://github.com/corazawaf/coraza/pull/1098#discussion_r1683405673))

## Participants

- @fzipi — author
- @M4tteoP — review (pushed for recommended-config realism)

## Consequences

- **Positive:** Multipart evasion detection in the recommended config
  actually works; operators get a truthful config out of the box.
- **Negative / follow-up:** ModSecurity sub-variables remain unimplemented;
  the single signal is coarse by design.

## References

- PR: https://github.com/corazawaf/coraza/pull/1098
