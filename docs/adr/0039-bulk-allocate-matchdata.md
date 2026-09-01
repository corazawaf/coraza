# ADR-0039: Bulk-allocate `MatchData` in collection `Find*` methods

- **Status:** accepted
- **Date:** 2026-03-11
- **Version:** v3.4.0
- **PR:** [#1530](https://github.com/corazawaf/coraza/pull/1530)
- **Issue(s):** No linked issue
- **Deciders:** @jptosso, @fzipi
- **Category:** Perf

## Context and Problem

`Map.FindRegex`, `Map.FindString`, `Map.FindAll` and the `NamedCollectionNames`
counterparts allocated one `MatchData` per result via `&corazarules.MatchData{}`
literals. At N results that is N+1 heap allocations. These methods run
per-request, so the allocator pressure compounds.

## Decision Drivers

- Reduce heap allocations on the rule-evaluation hot path.
- Preserve public semantics — returned slices are independently owned.
- Avoid a double regex pass in `FindRegex`.

## Considered Options

- Pre-allocate a contiguous `[]MatchData` buffer and return pointers into it.
- `sync.Pool` of `MatchData` slices.
- Leave as-is, rely on escape analysis.

## Decision Outcome

Chosen: **pre-allocated contiguous buffer, pointers into the buffer.**

Benchmark from the PR body:

```
FindAll    608 → 405 ns/op  (-33%)  26 → 2 allocs (-92%)
FindRegex 1008 → 965 ns/op  (-4%)   15 → 6 allocs (-60%)
FindString 495 → 221 ns/op  (-55%)  26 → 2 allocs (-92%)
```

`FindRegex` was also rewritten to single-pass collection (no regex
re-evaluation).

## Technical Discussion

No substantive technical discussion recorded beyond the benchmark data. The
change is localised, covered by `TestFindAllBulkAllocIndependence` and
siblings to prove results remain independent after the pool redesign.

## Participants

- @jptosso — author
- @fzipi — review

## Consequences

- **Positive:** Heavy allocation drop on hot-path collection finds; up to
  55% faster for `FindString`.
- **Negative / follow-up:** None flagged in review.

## References

- PR: https://github.com/corazawaf/coraza/pull/1530
