# ADR-0038: `map[int]struct{}` for per-transaction `ruleRemoveByID` lookup

- **Status:** accepted
- **Date:** 2026-03-06
- **Version:** v3.4.0
- **PR:** [#1524](https://github.com/corazawaf/coraza/pull/1524)
- **Issue(s):** No linked issue
- **Deciders:** @jptosso, @fzipi
- **Category:** Perf

## Context and Problem

Every rule evaluation consulted a per-transaction `[]int` of excluded rule
IDs (populated by `ctl:ruleRemoveById`). In CRS workloads with many exclusion
directives, the linear scan is hit once per rule per phase.

## Decision Drivers

- O(1) lookup for rule-exclusion checks on a hot path.
- Lazy allocation so the zero-exclusion case stays allocation-free.
- No external API change.

## Considered Options

- Sorted slice + binary search.
- `map[int]struct{}` with lazy init.
- Bitset / roaring bitmap.

## Decision Outcome

Chosen: **`map[int]struct{}` with lazy init**. Benchmarked on the actual
hot path (`BenchmarkRuleEvalWithRemovedRules`):

```
main ([]int linear scan):  135.0 ns/op
branch (map O(1) lookup):  114.5 ns/op   (~15% faster)
```

Scales with the number of removed IDs — the improvement grows with real CRS
exclusion loads.

## Technical Discussion

No substantive technical discussion recorded on the PR or issue thread
beyond approvals. The rationale and measurement live in the PR body:

> "`BenchmarkRuleEvalWithRemovedRules` — 1 rule loaded, 100 rule IDs
> removed via `RemoveRuleByID`, benchmarks `Eval(PhaseRequestHeaders)` …
> ~15% faster with 100 removed rule IDs. The improvement scales with the
> number of removed rules and the number of rules evaluated — in CRS
> workloads with many `ctl:ruleRemoveById` directives and hundreds of
> rules, each rule evaluation benefits from the O(1) lookup."
> — @jptosso, [PR body](https://github.com/corazawaf/coraza/pull/1524)

## Participants

- @jptosso — author
- @fzipi — review
- @Copilot — PR reviewer bot

## Consequences

- **Positive:** Rule-evaluation hot path drops ~15% for exclusion-heavy
  configs; no cost when no rules are excluded.
- **Negative / follow-up:** Paired with [ADR-0041](0041-ruleremovebyid-range-storage.md)
  (range storage) to also avoid map bloat when ranges are used.

## References

- PR: https://github.com/corazawaf/coraza/pull/1524
- Related ADRs: ADR-0041 (`ruleRemoveById` range storage)
