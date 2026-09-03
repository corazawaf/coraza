# ADR-0055: Register the `accuracy` metadata action

- **Status:** accepted
- **Date:** 2026-08-27
- **Version:** unreleased (post-v3.7.0)
- **PR:** [#1693](https://github.com/corazawaf/coraza/pull/1693)
- **Issue(s):** [#1104](https://github.com/corazawaf/coraza/issues/1104)
- **Deciders:** @ChrisJr404, @fzipi
- **Category:** Parity

## Context and Problem

> "The `accuracy` action is documented and there is already an `Accuracy_` field
> on the rule metadata that gets emitted to the audit log, but the action itself
> was never registered. So a rule using `accuracy` fails to parse with `invalid
> action "accuracy"` and the field always stays zero."
> — @ChrisJr404, PR description ([#1693](https://github.com/corazawaf/coraza/pull/1693))

## Decision Drivers

- Rules using the documented `accuracy` metadata action currently fail to parse.
- The `Accuracy_` field already exists on rule metadata and in audit log output,
  but nothing can set it.
- `maturity` is the sibling metadata action and already establishes the shape
  to follow: parse, validate a 1–9 range, store on the rule.

## Considered Options

Only one option was pursued: register `accuracy` the same way as `maturity` —
a metadata action that validates the value and stores it, with no evaluation
side effect. No alternative implementation was discussed.

## Decision Outcome

Chosen: **register `accuracy` as a metadata action mirroring `maturity`**,
validating that the value is an integer from 1 to 9 and storing it on the rule.
Error wrapping was refined during review so invalid input produces a clear
message.

## Technical Discussion

> "Line 32 returns a raw conversion error. Include the action name and input
> value so invalid rules have a clear error message."
> — @coderabbitai[bot] ([review](https://github.com/corazawaf/coraza/pull/1693#discussion_r3858135949))

> "Done. Wrapped the strconv error with the accuracy context and the original
> input so invalid rules give a clear message."
> — @ChrisJr404 ([comment](https://github.com/corazawaf/coraza/pull/1693#issuecomment-5427862652))

## Participants

- @ChrisJr404 — author
- @fzipi — review (asked for CodeRabbit's comments to be addressed; approved)
- @coderabbitai[bot] — reviewer bot (flagged the unwrapped conversion error)

## Consequences

- **Positive:** Rules using `accuracy` now parse; the `Accuracy_` metadata
  field is populated and appears in the audit log as originally documented.
- **Negative / follow-up:** None identified — a localized, single-action change.

## References

- PR: https://github.com/corazawaf/coraza/pull/1693
- Issue: https://github.com/corazawaf/coraza/issues/1104
- Related ADRs: none (mirrors the pre-existing, undocumented-in-ADR `maturity` action)
