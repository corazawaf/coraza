# ADR-0033: `@strmatch` operator

- **Status:** accepted
- **Date:** 2026-01-15
- **Version:** v3.4.0
- **PR:** [#1473](https://github.com/corazawaf/coraza/pull/1473)
- **Issue(s):** [#1350](https://github.com/corazawaf/coraza/issues/1350)
- **Deciders:** @fzipi, @jcchavezs, @Copilot (reviewer)
- **Category:** Parity (ModSecurity parity — operator)

## Context and Problem

ModSecurity's `@strmatch` is a substring-search operator — cheaper than
`@rx` for literal substring checks. Coraza had no equivalent, forcing rule
authors to use `@rx` (regex engine) even for trivial "contains" tests.

## Decision Drivers

- ModSecurity parity.
- Offer a cheaper path than `@rx` for literal substring checks.
- Reuse Go's `strings.Contains` (well-optimised hybrid substring search).

## Considered Options

- Naive byte-by-byte matcher.
- Wrap `strings.Contains`.
- Ship hand-rolled BMH or Rabin-Karp implementations.

## Decision Outcome

Chosen: **wrap `strings.Contains`.** Benchmark-comparison implementations
(BMH, naive) that were part of the initial PR were removed from the final
merge:

> "The benchmark file includes two complete string search algorithm
> implementations (BMH and naive search) that are only used for
> performance comparison and are not part of the actual operator. This
> adds unnecessary code complexity and maintenance burden to the
> repository."
> — @Copilot ([review](https://github.com/corazawaf/coraza/pull/1473#discussion_r2694162335))

> "Benchmark removed."
> — @fzipi ([review](https://github.com/corazawaf/coraza/pull/1473#discussion_r2695378627))

The initial doc comment incorrectly claimed `strings.Contains` is Rabin-Karp
and used SIMD; Copilot pointed out both were inaccurate:

> "The documentation states that `strings.Contains` implements the
> Rabin-Karp algorithm, but this is inaccurate. Go's standard library uses
> a hybrid approach that includes Boyer-Moore for longer patterns and
> optimized byte search for shorter patterns."
> — @Copilot ([review](https://github.com/corazawaf/coraza/pull/1473#discussion_r2694162310))

The doc comment was updated to remove the claims.

## Technical Discussion

**Empty-string handling.** @jcchavezs asked whether the operator handles
empty input; @fzipi confirmed `NewMacro` guards it upstream:

> "does this check if data is empty?"
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1473#discussion_r2695698112))

> "Yes, NewMacro checks for empty strings."
> — @fzipi ([review](https://github.com/corazawaf/coraza/pull/1473#discussion_r2695754879))

## Participants

- @fzipi — author
- @jcchavezs — review (empty-data check)
- @Copilot — PR reviewer bot (drove doc-accuracy + dead-code removal)

## Consequences

- **Positive:** Rule authors get a cheap literal-substring operator; cuts
  regex overhead on the many CRS rules that do substring matching.
- **Negative:** None beyond maintaining a thin wrapper over a stdlib
  function.

## References

- PR: https://github.com/corazawaf/coraza/pull/1473
- Issue: https://github.com/corazawaf/coraza/issues/1350
