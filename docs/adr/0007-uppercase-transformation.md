# ADR-0007: `uppercase` transformation

- **Status:** accepted
- **Date:** 2023-12-18
- **Version:** v3.1.0
- **PR:** [#935](https://github.com/corazawaf/coraza/pull/935)
- **Issue(s):** No linked issue
- **Deciders:** @blotus, @fzipi, @jptosso
- **Category:** Parity (closes documented-but-missing transformation)

## Context and Problem

Coraza's public documentation listed an `uppercase` transformation, but the
transformation was never actually implemented — rules relying on it silently
did nothing. A documentation/implementation drift bug that is, strictly, also
a tiny feature addition.

## Decision Drivers

- Close the documented-but-missing gap.
- Mirror `lowercase`, which already existed, including its test data layout.

## Considered Options

- Leave the docs in place and drop `uppercase`.
- Implement the transformation and align test layout with `lowercase`.

## Decision Outcome

Chosen: **implement to match the documented behaviour**. Test data added in
the standard `internal/transformations/testdata/` JSON format per reviewer
request.

## Technical Discussion

The review was terse. The only substantive request concerned test-suite
consistency:

> "LGTM, but to keep testing consistency, can you also add the tests to
> `internal/transformations/testadata`?"
> — @jptosso ([comment](https://github.com/corazawaf/coraza/pull/935#issuecomment-1849541214))

> "Thanks for your contribution! LGTM. Unless @anuraaga has other opinions,
> it's good to merge." — @fzipi
> ([comment](https://github.com/corazawaf/coraza/pull/935#issuecomment-1847219766))

No architectural debate.

## Participants

- @blotus — author
- @fzipi — review / approval
- @jptosso — review (test layout)

## Consequences

- **Positive:** The `uppercase` transformation now behaves as documented;
  rulesets that used it start working as intended.
- **Negative / follow-up:** None of note.

## References

- PR: https://github.com/corazawaf/coraza/pull/935
