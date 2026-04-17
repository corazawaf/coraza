# ADR-0049: `@rx` operator literal pre-filter (build-tag opt-in)

- **Status:** accepted
- **Date:** 2026-03-31
- **Version:** v3.6.0 (gated by `coraza.rule.rx_prefilter`)
- **PR:** [#1534](https://github.com/corazawaf/coraza/pull/1534)
- **Issue(s):** No linked issue (superseded by runtime directive — [ADR-0050](0050-secrxprefilter-directive.md))
- **Deciders:** @jptosso, @fzipi, @M4tteoP
- **Category:** Perf

## Context and Problem

`@rx` is the largest hot path in Coraza. CRS loads hundreds of `@rx` rules
and 95%+ of evaluations return `false` for benign traffic — but the regex
engine still runs to completion before concluding "no match". Compile-time
analysis can cheaply short-circuit clear non-matches.

## Decision Drivers

- Skip the regex engine entirely when a pattern's required literals are
  absent from the input.
- **Safety first:** a prefilter may only say "definitely no match" or
  "maybe match" — any uncertainty must fall through to the full regex.
  A missed attack is worse than a missed optimisation.
- Opt-in via a build tag so existing deployments don't change behaviour
  silently.

## Considered Options

- Ship only the allocation reduction from
  [ADR-0045](0045-findstringsubmatchindex-noalloc.md).
- Add compile-time AST walking to extract min-length + required-literal
  pre-checks, gated by build tag.

## Decision Outcome

Chosen: **build-tag-gated AST prefilter with three optimizations:**

1. **Minimum match length check** — walk `regexp/syntax` AST to compute
   minimum input bytes; skip if `len(input) < minLen`.
2. **Required literal pre-filtering (highest impact)** — extract literals
   that *must* appear; check with `strings.Contains` (single) or
   Aho-Corasick (alternation), reusing the `@pm` dependency.
3. **Allocation reduction in capturing path** — `FindStringSubmatchIndex`,
   shipped always-on in [ADR-0045](0045-findstringsubmatchindex-noalloc.md).

**Safety rule** quoted from the PR body:

> "When in doubt, fall back to the regex. The prefilter is purely an
> optimization. If there is **any** uncertainty about whether the input
> could match — non-ASCII input with `(?i)` patterns, unknown AST nodes,
> unparseable patterns, or any other ambiguity — we return 'maybe match'
> and let the full regex engine make the final decision. **A missed
> optimization is free; a missed attack is a security vulnerability.**"
> — @jptosso, PR body

**Unicode case-folding safety.** The prefilter only knows ASCII case
folding (A-Z ↔ a-z), so `(?i)` patterns that see non-ASCII input
conservatively return "maybe match" to avoid missing `s`↔`ſ`, `k`↔`K`
edge cases:

> "In practice, 99%+ of WAF traffic is pure ASCII, so the optimization
> still applies for the vast majority of requests."
> — @jptosso, PR body

## Technical Discussion

Runtime vs. build-time activation was the unresolved question. It was
deferred to a separate PR ([ADR-0050](0050-secrxprefilter-directive.md))
because build-tag gating made testing harder for embedders wanting
per-instance opt-in without a rebuild.

## Participants

- @jptosso — author
- @fzipi — review
- @M4tteoP — review (followed up with the runtime directive)

## Consequences

- **Positive:** For typical traffic, most `@rx` evaluations short-circuit
  before touching the regex engine.
- **Negative / follow-up:** Build-tag gating requires a rebuild to toggle —
  addressed by [ADR-0050](0050-secrxprefilter-directive.md)
  (`SecRxPreFilter` directive) in v3.7.0.

## References

- PR: https://github.com/corazawaf/coraza/pull/1534
- Related ADRs: ADR-0045 (FindStringSubmatchIndex), ADR-0050
  (`SecRxPreFilter` directive), ADR-0052 (Aho-Corasick → bitmap matcher
  for this prefilter)
