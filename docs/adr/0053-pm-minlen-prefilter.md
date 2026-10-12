# ADR-0053: `@pm` operator `minLen` prefilter

- **Status:** accepted
- **Date:** 2026-04-13
- **Version:** unreleased (post-v3.7.0)
- **PR:** [#1601](https://github.com/corazawaf/coraza/pull/1601)
- **Issue(s):** No linked issue
- **Deciders:** @fzipi
- **Category:** Perf

## Context and Problem

`@pm` (and `@pmFromFile`, `@pmFromDataset`) dispatches into the upstream
`aho-corasick` library even for inputs shorter than the shortest pattern.
That library has its own prefilter (rare-byte scanning) but no
minimum-length early exit — so calling `matcher.Iter("ab")` with a set
whose shortest pattern is 4 chars still copies the string, allocates a
`*prefilterState`, allocates a `*findIter`, and walks some automaton
states before concluding "no match".

## Decision Drivers

- Cut the cost of short-input `@pm` evaluations — common on headers,
  cookies, single-token query params.
- Zero-alloc on the early-exit path.

## Considered Options

- Push the fix upstream into `aho-corasick`.
- Compute the shortest-pattern length at init, add a trivial `len(value)
  < minLen` gate inside the `@pm` operator.

## Decision Outcome

Chosen: **`minLen` field on the `pm` struct, checked before the upstream
matcher.** Applies uniformly to `pm`, `pmFromFile`, `pmFromDataset`.

**Why not upstream:**

> "The aho-corasick library has its own prefilter (`startBytes`/`rareBytes`
> — scanning for rare start bytes to skip automaton states), but it does
> **not** have a minimum-length early exit. Calling `matcher.Iter(value)`
> always: 1. Copies the string to `[]byte` (allocation) 2. Creates a
> `*prefilterState` (heap allocation) 3. Creates a `*findIter` (heap
> allocation via interface) 4. Walks the automaton on `Next()` before
> concluding 'no match'."
> — @fzipi, PR body

## Technical Discussion

No substantive technical discussion recorded on the PR thread. The
benchmarks, CRS-workload numbers, and allocation analysis are all in the
PR body. Reviewers approved on that basis.

Micro-benchmark from the PR body:

| Input | ns/op | allocs |
|---|---:|---:|
| below minLen (3 chars) | **2** | 0 |
| at minLen, no match (4 chars) | 98 | 4 |
| longer, no match (62 chars) | 317 | 4 |

CRS benchmark: −3% memory / −3% wall-time on simple GET/POST.

## Participants

- @fzipi — author

## Consequences

- **Positive:** Short inputs (shorter than any `@pm` pattern) skip the
  upstream matcher entirely — roughly 50× faster on the pure skip path;
  CRS wall-time drops several percent end-to-end.
- **Negative:** `minLen` adds state on the `pm` struct; unchanged if
  the pattern list is dynamic.

## References

- PR: https://github.com/corazawaf/coraza/pull/1601
- Upstream library: https://github.com/petar-dambovaliev/aho-corasick
- Related ADRs: ADR-0049 (rx literal prefilter — analogous `minMatchLength`
  for `@rx`)
