# ADR-0036: Remove root package dependency on `experimental`

- **Status:** accepted
- **Date:** 2026-02-24
- **Version:** v3.4.0
- **PR:** [#1494](https://github.com/corazawaf/coraza/pull/1494)
- **Issue(s):** No linked issue (surfaced by [#1478](https://github.com/corazawaf/coraza/pull/1478))
- **Deciders:** @fzipi
- **Category:** Refactor

## Context and Problem

The root `github.com/corazawaf/coraza/v3` package imported
`experimental`, which made it impossible for the `experimental` package to
import back into the root — the kind of thing that blocks clean
assertion-helper patterns. The cycle bit the rule-observer work
([ADR-0034](0034-rule-observer-callback.md)), where @heaven had to fall
back to reflection.

## Decision Drivers

- Let `experimental` reference root-package types so assertion helpers
  (e.g. `WAFConfigWithRuleObserver`) can be implemented without reflection.
- `experimental` should depend on stable; stable should not depend on
  experimental.

## Considered Options

- Keep the status quo, continue using reflection-based workarounds.
- Invert the direction: root no longer imports `experimental`; `experimental`
  imports root.

## Decision Outcome

Chosen: **invert the direction.** This is the preparatory refactor that
unblocks clean helpers (#1478) and future additions.

## Technical Discussion

No substantive technical discussion recorded on the PR thread — the
refactor is mechanical and reviewers approved it as a plumbing fix. The
*why* is documented explicitly in the follow-up PR:

> "Because the core `coraza` package already depends on `experimental`, the
> experimental helper cannot reference the `WAFConfig` directly without
> creating a cyclic import. … Of course, the best long-term solution would
> be to remove the dependency from the core `coraza` to `experimental`."
> — @heaven, ahead of this refactor, in
> [PR #1478 comment](https://github.com/corazawaf/coraza/pull/1478#issuecomment-3828189778)

## Participants

- @fzipi — author

## Consequences

- **Positive:** `experimental` helpers can use root types directly;
  reflection-based workarounds become unnecessary.
- **Negative:** None.

## References

- PR: https://github.com/corazawaf/coraza/pull/1494
- Related ADRs: ADR-0034 (rule observer callback — motivating use case)
