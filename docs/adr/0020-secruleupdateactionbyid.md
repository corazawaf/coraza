# ADR-0020: `SecRuleUpdateActionById` directive

- **Status:** accepted
- **Date:** 2024-10-31
- **Version:** v3.3.0
- **PR:** [#1071](https://github.com/corazawaf/coraza/pull/1071)
- **Issue(s):** [#929](https://github.com/corazawaf/coraza/issues/929)
- **Deciders:** @fzipi, @jcchavezs
- **Category:** Parity (ModSecurity / CRS parity)

## Context and Problem

Operators using CRS needed a way to mutate a rule's action list by ID without
reloading or editing upstream rule files. ModSecurity ships
`SecRuleUpdateActionById` for exactly this; Coraza had the target-mutating
directives but not the action-mutating one.

## Decision Drivers

- CRS tuning parity.
- Minimal surface growth — mirror the shape of the existing
  `SecRuleUpdateTargetById` implementation.

## Considered Options

- Extend existing `SecRuleUpdateTargetById` to also cover actions.
- Ship a distinct `SecRuleUpdateActionById` directive.

## Decision Outcome

Chosen: **distinct directive, mirroring ModSecurity**. This keeps the CRS
migration path straightforward.

## Technical Discussion

Two minor style requests were the entire review:

> "nit: use `idsOrRangesLen` to avoid generic variable names"
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1071#discussion_r1823795090))

> "nit: flip the conditional to avoid indentation."
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1071#discussion_r1823800325))

The author had earlier flagged a separate blocker — tests were failing on an
unrelated bug that was fixed in PR #1183:

> "After finding why my tests didn't worked (#1183), now this is ready to
> go."
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1071#issuecomment-2448645235))

No architectural debate took place — the directive's shape followed the
existing pattern and was uncontroversial.

## Participants

- @fzipi — author
- @jcchavezs — review (nits)

## Consequences

- **Positive:** Operators can tune CRS rule actions in-place (e.g. turn a
  `deny` into `pass` for a specific rule) without re-generating ruleset
  files.
- **Negative / follow-up:** A later fix (PR #1471) was needed to ensure the
  directive correctly replaces disruptive actions rather than appending.

## References

- PR: https://github.com/corazawaf/coraza/pull/1071
- Issue: https://github.com/corazawaf/coraza/issues/929
- Test-blocker: https://github.com/corazawaf/coraza/pull/1183
- Follow-up: https://github.com/corazawaf/coraza/pull/1471
- Related ADRs: ADR-0012 (`SecRuleUpdateTargetByTag`)
