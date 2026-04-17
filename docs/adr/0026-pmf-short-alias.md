# ADR-0026: `@pmf` short alias for `@pmFromFile`

- **Status:** accepted
- **Date:** 2025-05-12
- **Version:** v3.4.0
- **PR:** [#1356](https://github.com/corazawaf/coraza/pull/1356)
- **Issue(s):** [#1283](https://github.com/corazawaf/coraza/issues/1283)
- **Deciders:** @dmefs, @M4tteoP, @fzipi, @jcchavezs
- **Category:** Parity (ModSecurity parity — operator alias)

## Context and Problem

ModSecurity documents `@pmf` as the short-form alias of `@pmFromFile`.
Rulesets relying on that alias did not work in Coraza. This ADR captures
the straightforward addition of the alias registration.

## Decision Drivers

- ModSecurity parity.
- Zero behaviour cost — operator aliases register the same implementation
  under two names.

## Considered Options

- Register the alias.
- Leave rule authors to rename `@pmf` → `@pmFromFile` in their configs.

## Decision Outcome

Chosen: **register the alias.**

## Technical Discussion

No substantive technical discussion recorded on the PR or issue thread. The
author introduced themselves:

> "This is my first PR. I'm happy to make contribution!🥳"
> — @dmefs ([comment](https://github.com/corazawaf/coraza/pull/1356#issuecomment-2875425220))

…and no code-level review comments were posted. The PR merged after
approvals.

## Participants

- @dmefs — author
- @M4tteoP — review
- @fzipi — review
- @jcchavezs — review

## Consequences

- **Positive:** `@pmf` works verbatim in Coraza; ModSecurity rulesets carry
  over cleanly.
- **Negative:** None.

## References

- PR: https://github.com/corazawaf/coraza/pull/1356
- Issue: https://github.com/corazawaf/coraza/issues/1283
- Related ADRs: ADR-0027 (`@ipMatchF` short alias)
