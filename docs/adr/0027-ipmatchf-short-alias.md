# ADR-0027: `@ipMatchF` short alias for `@ipMatchFromFile`

- **Status:** accepted
- **Date:** 2025-05-13
- **Version:** v3.4.0
- **PR:** [#1357](https://github.com/corazawaf/coraza/pull/1357)
- **Issue(s):** No linked issue
- **Deciders:** @dmefs, @M4tteoP, @fzipi, @jcchavezs
- **Category:** Parity (ModSecurity parity — operator alias)

## Context and Problem

ModSecurity supports `@ipMatchF` as a short-form alias for
`@ipMatchFromFile`. Like [ADR-0026](0026-pmf-short-alias.md), Coraza was
missing the alias registration.

## Decision Drivers

- ModSecurity parity.
- Keep test coverage symmetric: add tests for both the new alias and its
  canonical form.

## Considered Options

- Register the alias.
- Leave rule authors to rename.

## Decision Outcome

Chosen: **register the alias, add tests for both forms** per review
feedback.

## Technical Discussion

Minor reviewer request for test symmetry:

> "I see that you are adding a couple of rules to be tested with
> `@ipMatchF`. Could you also add the same lines for `@ipMatchFromFile`?
> Just like we have now the same matching for `@pmFromFile` and `@pmf`"
> — @M4tteoP ([review](https://github.com/corazawaf/coraza/pull/1357#discussion_r2086599002))

> "Thanks for pointing that out. I'll add the rules for @ipMatchFromFile as
> well."
> — @dmefs ([review](https://github.com/corazawaf/coraza/pull/1357#discussion_r2087011488))

No architectural debate.

## Participants

- @dmefs — author
- @M4tteoP — review (test symmetry)
- @fzipi — review
- @jcchavezs — review

## Consequences

- **Positive:** `@ipMatchF` works; operator coverage matches ModSecurity's
  alias table.
- **Negative:** None.

## References

- PR: https://github.com/corazawaf/coraza/pull/1357
- Related ADRs: ADR-0026 (`@pmf` short alias)
