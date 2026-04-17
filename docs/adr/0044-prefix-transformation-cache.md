# ADR-0044: Prefix-based transformation cache with inline values

- **Status:** accepted
- **Date:** 2026-03-11
- **Version:** v3.5.0
- **PR:** [#1544](https://github.com/corazawaf/coraza/pull/1544)
- **Issue(s):** No linked issue
- **Deciders:** @fzipi, @jptosso
- **Category:** Perf

## Context and Problem

Two rules that share a common transformation prefix
(e.g. `t:lowercase,t:urlDecodeUni` and `t:lowercase`) redundantly recomputed
the prefix. The existing cache stored only the final result, not the
intermediate steps, and used pointer values (extra heap allocs).

## Decision Drivers

- Reuse intermediate transformation results across rules.
- Fix `ClearTransformations` (t:none) so it resets the cached ID.
- Cut heap allocations on the request hot path.

## Considered Options

- Cache only the final result per rule (status quo).
- Cache every intermediate step, keyed by the transformation chain prefix,
  with inline values.

## Decision Outcome

Chosen: **cache every intermediate step with inline values**, adding a
`transformationPrefixIDs` field to `Rule` for backward prefix search. The
key insight: transformations are deterministic, so two rules sharing the
first K transformations can share the cached result after step K.

PR-body benchmark against full CRS v4 (8 runs, benchstat):

- Allocations: −2% (small payloads) to −19% (30 args)
- Memory: −2% to −12%
- Timing: −5% small/large, neutral mid-range

No regressions on any metric.

## Technical Discussion

No substantive technical discussion recorded on the PR thread. The design
and the benchmark results are in the PR body; reviewers approved on that
basis.

## Participants

- @fzipi — author
- @jptosso — review

## Consequences

- **Positive:** Fewer redundant transformation runs across CRS; inline
  values avoid heap allocation; `t:none` semantics corrected.
- **Negative / follow-up:** None noted.

## References

- PR: https://github.com/corazawaf/coraza/pull/1544
