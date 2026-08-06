# ADR-0034: Optional rule observer callback on `WAFConfig`

- **Status:** accepted
- **Date:** 2026-02-24
- **Version:** v3.4.0
- **PR:** [#1478](https://github.com/corazawaf/coraza/pull/1478)
- **Issue(s):** No linked issue
- **Deciders:** @heaven, @fzipi, @jcchavezs
- **Category:** Feature (plugin surface)

## Context and Problem

UIs and ops tooling around Coraza wanted a way to introspect the exact
rules loaded by a running WAF (for display, metrics, audit). Previously
they had to maintain a parallel copy of the ruleset — a drift hazard.

## Decision Drivers

- Expose the loaded ruleset to the embedder without breaking the existing
  `WAF`/`Transaction` interfaces.
- Zero cost when unused.
- Stage the API through `experimental` so future shape changes aren't
  blocked by semver.

## Considered Options

- Add `WithRuleObserver` directly on `WAFConfig` (non-experimental).
- Add the type-level method + an `experimental.WAFConfigWithRuleObserver`
  helper that does the type assertion.
- Expose rules via a pull API (`RulesCount()` etc.) — tackled separately in
  [ADR-0035](0035-wafwithrules-interface.md).

## Decision Outcome

Chosen: **type-level method + `experimental` helper**, mirroring the
existing `WithErrorCallback` pattern. @fzipi initially preferred putting
the whole thing under `experimental`:

> "I like this idea. But maybe moving it to the `experimental` package
> first?"
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1478#issuecomment-3770237942))

@jcchavezs articulated the final shape and the v4-safety rationale:

> "I like the idea too but I was thinking we should move this to
> experimental. We could 1. Do not add the method in the interface but the
> type only 2. create a function in `experimental` called
> `WAFConfigWithRuleObserver` which does the interface assertion and calles
> the type method."
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/1478#issuecomment-3787116970))

> "To avoid future breaking changes, we usually land new features that are
> still in development under the experimental package so we won't break
> anyone if we decide to change it later."
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/1478#issuecomment-3814374587))

## Technical Discussion

**Circular-import hurdle.** @heaven hit an unexpected cyclic import:

> "Because the core `coraza` package already depends on `experimental`, the
> experimental helper cannot reference the `WAFConfig` directly without
> creating a cyclic import. So I had to use reflection to preserve the
> immutable builder semantics."
> — @heaven ([comment](https://github.com/corazawaf/coraza/pull/1478#issuecomment-3828189778))

The cyclic-import finding motivated the separate refactor in
[ADR-0036](0036-remove-root-experimental-dep.md) that removed the root →
`experimental` direction.

**Immutability preservation.** @heaven opted for the minimum-footprint
path, mimicking the existing `WithErrorCallback`:

> "My goal was to make the footprint as small as possible, though, so I
> tried the opposite – to avoid new types and other exports."
> — @heaven ([comment](https://github.com/corazawaf/coraza/pull/1478#issuecomment-3798817597))

## Participants

- @heaven — author
- @fzipi — review (experimental-package proposal)
- @jcchavezs — review (shape: type + experimental assertion helper)

## Consequences

- **Positive:** UIs can observe the loaded ruleset directly; no parallel
  dataset to keep in sync.
- **Negative / follow-up:** Reflection in the experimental helper is a
  temporary wart — cleaned up by the package-dependency flip in
  [ADR-0036](0036-remove-root-experimental-dep.md).

## References

- PR: https://github.com/corazawaf/coraza/pull/1478
- Related ADRs: ADR-0035 (`WAFWithRules` / `RulesCount()`), ADR-0036
  (remove root→experimental dep)
