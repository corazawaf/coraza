# ADR-0061: Key the transformation cache by value identity

- **Status:** accepted
- **Date:** 2026-10-15
- **Version:** unreleased (post-v3.8.1)
- **PR:** [#1682](https://github.com/corazawaf/coraza/pull/1682)
- **Issue(s):** [#1681](https://github.com/corazawaf/coraza/issues/1681)
- **Deciders:** @M4tteoP, @fzipi
- **Category:** Perf

## Context and Problem

The per-phase transformation cache (ADR-0044) was keyed by the argument's key
pointer, its variable and its **position** in the `tx.GetField()` result.
Map-backed collections (`ARGS_GET`, `ARGS_POST`, `REQUEST_HEADERS`,
`REQUEST_COOKIES`) build that result by ranging over a Go map, so the position
of an argument changes from one rule to the next inside the same phase. Rules
that share a target and a transformation chain therefore missed each other's
entries, re-ran the chain and stored duplicates.

The duplicates cost memory, and Go maps do not shrink, so a pooled transaction
keeps a table sized for the largest phase it ever ran.

## Decision Drivers

- Rules sharing a target and a chain must share cache entries, whatever order
  a collection returns its values in.
- The key must stay a fixed-size struct with no string field, which is what
  keeps hashing cheap on TinyGo (the reason the key is pointer-based at all).
- No new `unsafe` import; the existing `unsafe.StringData` use (ADR-0019) is
  repointed, not extended.

## Considered Options

- Keep the positional key (status quo).
- Key by value identity (data pointer + length) and keep the variable in the
  key.
- Key by value identity alone.

## Decision Outcome

Chosen: **key by value identity alone**. The key is the value's data pointer,
its length and the transformation prefix ID. Transformations are functions of
the input string only, so neither the variable nor the argument name can change
the result, and dropping the variable takes the key from 32 to 24 bytes.

Correctness rests on pointer identity alone: the pointer in the key keeps the
value's memory alive, so within a phase the same pointer and length always mean
the same bytes, whichever variable the value came from.

Which variables go through the cache is therefore a question of usefulness, not
of safety: an entry pays off only when a later rule sees the same string again.
Three kinds of variable are evaluated without the cache, decided once per
variable in `transformationCacheable`:

- `&VARIABLE` counts and `ARGS_COMBINED_SIZE`: the value is a new string on
  every lookup, so an entry would never be found again.
- `TX`, as before: `setvar` replaces its values mid-phase, and each replaced
  value would leave its entries behind.

`MATCHED_VAR`, `MATCHED_VAR_NAME`, `MATCHED_VARS_NAMES` and `RULE` also get
fresh strings during a phase and stay cached. That is accepted: the cost is
entries that are never read again, never a wrong result (see the review
summarised below).

A rule that resumes from a cached prefix now caps the cached error slice
(`cached.errs[:n:n]` in `rule.go`) before appending to it. Before, two rules
sharing a transformation prefix appended into the same backing array and could
overwrite each other's last cached error; `TestTransformArgPrefixSharingKeepsErrors`
guards it.

`Transaction.Close()` empties the cache, so a transaction waiting in the pool
does not keep the last phase's values alive through the cache keys.

PR-body measurements against CRS 4.25, urlencoded POST, entries counted after
phase 2:

| params | entries before (5 runs) | entries after (5 runs) |
|---|---|---|
| 10 | 2,291 – 2,564 | 843 |
| 30 | 10,287 – 10,590 | 2,423 |
| 100 | 46,269 – 50,778 | 7,953 |

`BenchmarkCRSTransformationCache/LargePOST_30params` allocates about 4% less;
wall-clock time is within noise. The gain is in map entries, not in time.

## Technical Discussion

An independent reproduction on a downstream fork reported the same effect and
chose the more conservative key:

> […] Our local variant keeps argVariable, keys by value pointer + length and bypasses
> cache for synthesized counts. […]
> — @frankii91 ([comment](https://github.com/corazawaf/coraza/pull/1682#issuecomment-6049232916))

The author noted what the change does not solve:

> […] **Pooled transactions keep the cache's high-water capacity.** Entries are deleted at each phase, but the map never shrinks, so a pooled tx keeps a table sized for the largest phase it ever ran. This PR lowers the peak but doesn't bound it. […]
> — @M4tteoP ([comment](https://github.com/corazawaf/coraza/pull/1682#issuecomment-5832289282))

@fzipi's [review](https://github.com/corazawaf/coraza/pull/1682#pullrequestreview-5495501862)
pointed out that `TX` is not the only variable whose values change within a
phase, and that for the others the cost is unread entries and not wrong
results. That is why the exclusions are framed above as hygiene. It is
summarised here and not quoted, because a review body has no comment permalink.

@fzipi had earlier asked to land the key change first:

> […] If the two follow-ups you listed on Sept 25 (bounding the pooled map's high-water capacity, and the second point) can be split into a separate issue, I would rather land this fix first and iterate. […]
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1682#issuecomment-6006656087))

## Participants

- @M4tteoP — author
- @fzipi — review
- @frankii91 — PR thread, independent measurements

## Consequences

- **Positive:** One entry per value and transformation prefix, however many
  rules ask for it; the entry count is the same on every run for the same
  request.
- **Negative / follow-up:** The map's table capacity is still not bounded: a
  pooled transaction keeps the table of its largest phase, and a long-lived
  stream holds it for its whole lifetime. Cache keys now keep the untransformed
  value alive until the phase ends, where they used to reference the
  argument's name. A collection that starts synthesizing its values per lookup
  should be added to `transformationCacheable`, or it leaves unread entries
  behind.

## References

- PR: https://github.com/corazawaf/coraza/pull/1682
- Issue: https://github.com/corazawaf/coraza/issues/1681
- Related PR: https://github.com/corazawaf/coraza/pull/1680
- Related ADRs: ADR-0019, ADR-0044
