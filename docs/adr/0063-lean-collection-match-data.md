# ADR-0063: Lean match data for collection reads

- **Status:** proposed
- **Date:** 2026-10-19 (expected merge date)
- **Version:** unreleased (post-v3.8.1)
- **PR:** [#NNNN](https://github.com/corazawaf/coraza/pull/NNNN)
- **Issue(s):** [#1749](https://github.com/corazawaf/coraza/issues/1749)
- **Deciders:** @fzipi
- **Category:** Perf

## Context and Problem

Every rule that reads a variable gets a fresh `[]types.MatchData` from the
collection: `Map.FindAll`, `Map.FindString`, `NamedCollectionNames.FindAll` and
`Single.FindAll` together were 31% of all bytes allocated by a CRS request
(#1749, `-memprofilerate=1` profile of `BenchmarkCRS*`). Three things made that
bigger than it needs to be:

- The element type was `corazarules.MatchData`: 80 bytes, of which `Message_`,
  `Data_` and `ChainLevel_` (40 bytes) are always zero on a collection read. They
  are only set on the *separate* `MatchData` a rule builds when its operator
  matches (`Rule.doEvaluate`), so every collection read paid for fields it
  never used.
- `Single.FindAll` allocated a one-element slice and an 80-byte struct per call,
  and `REQUEST_URI`, `REQUEST_METHOD`, … are read by hundreds of rules.
- `ConcatKeyed.FindAll` (`ARGS`, `ARGS_NAMES`) grew its result with three
  `append`s over the sub-collections' fresh slices, re-copying every element
  (19.5 MB flat in the profile).

Separately, macro expansion (`%{tx.foo}`) and `setvar` read one value through
`Map.Get`, which copies the whole value slice to return element 0: 5.5 MB and
364k objects per benchmark run.

## Decision Drivers

- Keep the public `types.MatchData` interface and the `collection` interfaces
  untouched: integrators implement and consume them.
- Rule evaluation must see no behavioural difference; only the allocation shape
  changes.
- The shortest change that removes the waste, no new abstraction layers.

## Considered Options

- **A. A second internal struct, `corazarules.VariableMatch` (variable, key,
  value), returned by collection reads; `MatchData` stays for match results.**
  `ConcatKeyed.replaceVariable` is the only code that type-asserts on a
  collection result and now handles both.
- **B. Shrink `MatchData` itself**: not possible, the match-time fields are
  consumed by `MatchRule`, the error log and multiphase evaluation.
- **C. Pool the result slices**: callers (`GetField`, `ConcatKeyed`) compact and
  append into them, and plugins may retain them; ownership would have to be
  tracked through every consumer.

For the single-value reads there was one option: `Single` keeps one
`VariableMatch` and rewrites it on every `FindAll`; a `First(key)` method on
`Map` (and the views over it) returns one value without copying, discovered by
macro expansion and `setvar` through an optional interface so `collection.Keyed`
does not change.

## Decision Outcome

Chosen: **A**, plus the single-value reads. `ConcatKeyed` adopts the first
sub-collection's slice as its result instead of copying it, which makes the
common case (`ARGS` on a GET request: only `ARGS_GET` is non-empty) free.

Contract added to `Single.FindAll`: the returned element is owned by the
`Single` and rewritten by the next call; callers must not retain it. Every
in-tree consumer copies what it needs into the match-time `MatchData` before
the next read.

Measured on `main` 03989243 vs the branch (`testing/coreruleset`, M5 Max):
see the PR description.

## Technical Discussion

No substantive technical discussion recorded on the PR thread at the time of
writing.

## Participants

- @fzipi — author

## Consequences

- **Positive:** collection reads allocate half the bytes; `Single` reads and
  `ARGS` on GET requests allocate nothing beyond the slice header; macro and
  `setvar` lookups stop copying value slices.
- **Negative / follow-up:** two internal match types instead of one; code that
  needs to mutate a collection result must handle both (today only
  `replaceVariable`). A plugin that retained a `Single` element across reads
  would now see it change; none is known.

## References

- PR: https://github.com/corazawaf/coraza/pull/NNNN
- Issue: https://github.com/corazawaf/coraza/issues/1749
- Related ADRs: ADR-0061, ADR-0062 (same tracking issue)
