# ADR-0043: `WAF.Close()` + per-owner memoize cache tracking

- **Status:** accepted
- **Date:** 2026-03-11
- **Version:** v3.5.0
- **PR:** [#1541](https://github.com/corazawaf/coraza/pull/1541)
- **Issue(s):** No linked issue (follows [ADR-0006](0006-regex-ahocorasick-memoize.md))
- **Deciders:** @jptosso
- **Category:** Feature (new lifecycle API)

## Context and Problem

The memoize cache ([ADR-0006](0006-regex-ahocorasick-memoize.md)) was
process-global with no way to release entries when a specific WAF instance
was destroyed. In long-running processes that construct and discard many
WAFs (reload-heavy embedders, multi-tenant hosts), this was a slow leak.
ADR-0006 had noted the absence of `WAF.Close()` as the reason for the
global-plus-experimental-reset shape; this PR fixes the root cause.

## Decision Drivers

- Release compiled regex/Aho-Corasick memory when a WAF goes away.
- Preserve the speed benefit of the shared cache across live WAFs.
- Safe concurrent access during Close (tombstone-based cleanup).
- Minimal API break — expose via `experimental.WAFCloser` so stable
  consumers are unaffected.

## Considered Options

- Simple refcount per entry.
- Per-owner (per-WAF) `uint64` IDs tracked against cache entries;
  `Release(owner)` clears the owner's refs with tombstones.
- Full WAF-scoped cache (no sharing across WAFs — kills the benefit).

## Decision Outcome

Chosen: **per-owner ID tracking + tombstone-based `Release`**, exposed via
`experimental.WAFCloser.Close()`. Two helpers: `memoize.Release(ownerID)`
and `memoize.Reset()`.

Benchmark evidence from the PR body:

```
BenchmarkCompileWithoutMemoize/WAFs=100  54,030,097 ns/op
BenchmarkCompileWithMemoize/WAFs=100      2,227,625 ns/op   24× speedup

CRS cold→warm WAF: 58ms → 9ms  (6.3× speedup)
Close() memory release: 28MiB peak → 1MiB after Close()
```

## Technical Discussion

No substantive technical discussion recorded on the PR or issue thread
beyond reviewer approvals. The PR body is the design document:

> "Add per-owner tracking to the memoize cache using `uint64` owner IDs
> for efficient WAF lifecycle management. Implement `WAF.Close()` (via
> `experimental.WAFCloser`) to release cached regex/aho-corasick entries
> when a WAF instance is destroyed. Add `Release()` and `Reset()`
> functions with tombstone-based cleanup to safely handle concurrent
> access."
> — @jptosso, [PR body](https://github.com/corazawaf/coraza/pull/1541)

> "At 100 WAFs: **24× speedup** (54ms → 2.2ms). CRS integration: Cold vs
> warm WAF compilation: 58ms vs 9ms (**6.3× speedup**). Close() memory
> release: 28MiB peak → 1MiB after Close() (**27MiB released**)."
> — @jptosso, [PR body](https://github.com/corazawaf/coraza/pull/1541)

## Participants

- @jptosso — author

## Consequences

- **Positive:** Reload-heavy or multi-tenant embedders can free ~27MiB per
  WAF after `Close()`; first-WAF compile cost is still paid once, shared
  across all subsequent WAFs.
- **Negative / follow-up:** Release is O(entries × owners-to-clean) at
  tombstone-scan time — benchmarked at ~900μs for 300 entries × 100 owners,
  acceptable for a rare-event path.

## References

- PR: https://github.com/corazawaf/coraza/pull/1541
- Related ADRs: ADR-0006 (memoize initial), ADR-0042 (default-on)
