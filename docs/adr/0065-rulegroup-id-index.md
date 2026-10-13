# ADR-0065: Index RuleGroup IDs to reduce complexity of compilation

- **Status:** proposed
- **Date:** 2026-07-21 (PR merge date)
- **Version:** unreleased (post-v3.8.1)
- **PR:** [#1645](https://github.com/corazawaf/coraza/pull/1645)
- **Issue(s):** [#1644](https://github.com/corazawaf/coraza/issues/1644)
- **Deciders:** @racheedevel, @fzipi, @M4tteoP
- **Category:** Perf

## Context and Problem

 `RuleGroup.Add` calls `FindByID` for rules one-by-one to enforce unique IDs,
 which is basically a linear scan over the existing rules. Compiling N rules
 adds up to O(N^2) complexity, which at small number of rules (CRS or similar)
 is barely noticeable, but with 100k rules it takes about 30 seconds, which is
 long enough that it can lead to failed healthchecks at startups/reloads.

## Decision Drivers

- Compile time must scale linearly with ruleset size. `Add` runs once per rule, and its duplicate-ID
  check through `FindByID` scanned every earlier rule, making it `O(N^2)`, quadratic.
- `FindByID`, `Add` and the delete paths must behave exactly as it did before, so first match wins, duplicate rejection, no-ID rule resolution (`ID_ == 0` e.g. `SecMarker`) should still work.
- No public API change, `NewRuleGroup` stays as-is
- No new cost for rule groups that don't index rules
- No codepath currently constant-time can become `O(n)` after the change (deletion path is most complex to get right)

## Considered Options

- Keep linear scan in `FindByID` (no change)
- Add an ID-to-index map to `RuleGroup` and rebuild it in full after mutations
- Add ID-to-index map and keep it up-to-date per-operation (`Add`, `DeleteByID`, `DiscardPendingChain`), rebuild only in the bulk filters (`DeleteByRange`, `DeleteByMsg`, `DeleteByTag`), which already cost linear time today

For the map options, we store indices instead of `*Rule`. `append` can reallocate `rules`, so pointers to `Rule` could dangle. The ID-to-index map is created on the first `Rule` with an `ID`, not in `NewRuleGroup` immediately.

## Decision Outcome

Chosen: **ID-to-index map, kept up-to-date per-mutation**, because this way, we get the advantage of `O(1)` lookups through
`FindByID`, solving quadratic complexity reduction to linear `O(N)`. The end-to-end compile benchmark for 100 000 rules shows the improvement:

| Rules             | Before    | After  | Speedup |
|-------------------|-----------|--------|---------|
| 100,000 (CRS off) | 30,616 ms | 299 ms | 102x    |
| 100,000 (CRS on)  | 29,151 ms | 362 ms | 80x     |

Heap usage, allocation cost are basically noise. Rejected the full-rebuild option because it made each `DiscardPendingChain` call cost `O(N)`.
Popping 50k rules one-by-one took 17 895ms with a rebuild on every pop, compared to 1.96ms with incremental maintenance of the ID-to-index map.

One trade-off is that removing the rule at position `i` has to update the stored indices of rules that shifted down.
Finding the rule itself is `O(1)`, but the maintenance of the map costs `O(N-i)`. The actual cost of this depends on the position of the deleted rules,
meaning the start of the rules array cost slightly more to delete (429ms -> 800ms), while from the back of the array deletions get faster (163ms to 0.13ms).
Deletes are rare at configuration time, and this trade-off is well-worth the deletion cost considering `Add` is unavoidable to run for every single rule in every case.

## Technical Discussion

No substantive technical discussion recorded, it's an algorithmic optimization, where the results were included in the PR
as reasoning. The full numbers show clearly the improvement, trade-offs, and PR includes the algorithmic reasoning for the change.

## Participants

- @racheedevel - author
- @fzipi — review

## Consequences

- **Positive:** WAF compilation is faster, `FindByID` search is faster, deletions *can* be faster
- **Negative / follow-up:** deletions *can* be slightly slower as a consequence of the optimization, described as a trade-off worth taking, even if we look at it conservatively

## References

- PR: https://github.com/corazawaf/coraza/pull/1645
- Issue: https://github.com/corazawaf/coraza/issues/1644
- Related ADRs: ADR-0038 (map lookup for `ruleRemoveByID`), ADR-0035 (`RuleGroup.Merge` `FindByID` cost raised in review)
