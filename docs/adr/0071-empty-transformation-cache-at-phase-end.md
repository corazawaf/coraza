# ADR-0071: Empty the transformation cache when a phase ends

- **Status:** proposed
- **Date:** 2026-11-26 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** [#1865](https://github.com/corazawaf/coraza/pull/1865)
- **Issue(s):** No linked issue in this repository; reported in [corazawaf/coraza-nginx#173](https://github.com/corazawaf/coraza-nginx/issues/173)
- **Deciders:** @M4tteoP, @fzipi
- **Category:** Perf

## Context and Problem

The transformation cache (ADR-0044, keyed by value identity since ADR-0061) is
only valid within a phase. It was emptied when the *next* phase started. In a
connector, the request phases and the response phases are separated by the wait
for the upstream, so each request in flight kept its whole phase 2 cache alive
during that time.

With CRS and a large JSON body this adds up. A 230 KB JSON body (220 objects,
about 66,000 cache entries) kept about 11 MB per transaction. Behind a slow
upstream, nginx workers ran out of memory (corazawaf/coraza-nginx#173).

Emptying the map is not enough on its own: deleting the entries keeps the map's
table, and the table is what holds the memory.

## Decision Drivers

- A transaction waiting for the upstream should not keep memory from a phase
  that has already finished.
- Normal traffic must keep reusing the same map, as it does today: the CRS
  benchmarks stay under about 2,500 entries per phase.
- No new configuration.

## Considered Options

- **A. Empty the cache when the next phase starts** (status quo).
- **B. Empty it in place when the phase ends.** The map's table stays, so the
  memory stays too.
- **C. Replace the map when the phase ends, always.** Every transaction
  would grow a new table, including the small ones.
- **D. Empty it when the phase ends: in place up to a threshold, by
  replacing the map past it.** `maxRetainedTransformationCacheEntries` is 8192.
- **E. Like D, but size the new map from the last size seen.**

## Decision Outcome

Chosen: **D**. Below 8192 entries nothing changes for the map, which is still
reused. Past it, the map is replaced, so its table can be collected while the
request waits for the upstream. An emptied map kept at 8192 entries holds about
1.1 MiB.

Live heap with 10 transactions held after phase 2, with the 230 KB body:

| | per transaction |
|---|---|
| A (main) | 10.9 MB |
| B | 10.2 MB |
| D | 0.7 MB |

The CRS benchmarks (SimpleGET, SimplePOST, LargePOST, TransformationCache) show
the same B/op and allocs/op as main.

The cost is on bodies past the threshold: each such transaction grows a new
table. In a closed loop on that same body, allocations went from 29 to 47 MB
per transaction and the number of GC cycles about tripled (GC CPU 0.5% to
0.9%). Throughput stayed within noise.

E halved that cost in the same loop, but only because every request had the
same body. With real traffic, the size would come from whichever request last
used that pooled transaction, so a small request could allocate a large table
for nothing. It was not kept.

The emptying at the start of `RuleGroup.Eval` is removed, since every phase now
ends with an empty cache. The one in `Transaction.Close()` is kept as a safety
net, for a phase that did not finish, for instance after a panic in a rule that
the caller recovers.

## Technical Discussion

On the delete loops left at the start of `Eval` and in `Close()`:

> Now that the cache is emptied here, is the delete loop at the start of `Eval` still useful in any case? Same question for the one in `Close()`.
> — @M4tteoP ([comment](https://github.com/corazawaf/coraza/pull/1865#discussion_r4575762861))

> Good point, thanks! The one at the start of `Eval` isn't needed anymore, since every phase now ends with an empty cache, so I removed it in d564bda8. I'd like to keep the one in `Close()` as a safety net: entries can only be left there if a phase didn't finish, for instance after a panic in a rule that the caller recovers (net/http does), and the transaction would then go back to the pool with them. […]
> — @ppomes ([comment](https://github.com/corazawaf/coraza/pull/1865#discussion_r4576618513))

On the overlap with #1751, which bounds the same cache at the start of each
phase:

> […] #1865 is narrower and fixes an OOM in production, so what about landing it first and rebasing this one on top? […]
> — @M4tteoP ([comment](https://github.com/corazawaf/coraza/pull/1751#issuecomment-6884652281))

@segflaunt measured the change in Envoy with CRS and the same body size (live
heap 389 MB on main, 184 MB with this change, 32 connections) and saw about
three times as many GC cycles, which led to the profile summarised above:

> Thanks for profiling it, and for trying the sized map too. The extra collections come from rebuilding the table past 8192 entries, and emptying it in place would keep the table through the upstream wait, which is the memory this pull request is about. Keeping the replacement as it is makes sense to me.
> — @segflaunt ([comment](https://github.com/corazawaf/coraza/pull/1865#issuecomment-7168217931))

## Participants

- @ppomes — author
- @M4tteoP — review
- @segflaunt — PR thread, Envoy measurements

## Consequences

- **Positive:** A request waiting for the upstream no longer keeps its phase 2
  cache. Normal traffic keeps reusing the same map.
- **Negative / follow-up:** Bodies past 8192 cache entries allocate a new table
  on every transaction, with more GC cycles. #1751 may lower the threshold to
  4096 (an emptied map keeps about 576 KiB there), with the reasoning in
  ADR-0064.

## References

- PR: https://github.com/corazawaf/coraza/pull/1865
- Report: https://github.com/corazawaf/coraza-nginx/issues/173
- Related PR: https://github.com/corazawaf/coraza/pull/1751
- Related ADRs: ADR-0044, ADR-0061, ADR-0064
