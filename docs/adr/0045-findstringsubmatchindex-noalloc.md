# ADR-0045: `FindStringSubmatchIndex` replaces `FindStringSubmatch` on capture path

- **Status:** accepted
- **Date:** 2026-03-11
- **Version:** v3.5.0
- **PR:** [#1547](https://github.com/corazawaf/coraza/pull/1547)
- **Issue(s):** Extracted from [#1534](https://github.com/corazawaf/coraza/pull/1534)
- **Deciders:** @jptosso, @fzipi
- **Category:** Perf

## Context and Problem

`@rx` captures used `FindStringSubmatch`, which allocates a `[]string` per
match. With CRS loading hundreds of `@rx` rules, this allocation compounds
across every capturing evaluation on every request.

## Decision Drivers

- Eliminate the per-match `[]string` allocation.
- Keep behaviour identical for all capture cases, including
  non-participating optional groups.
- Ship independently of the build-tagged prefilter work in
  [ADR-0049](0049-rx-literal-prefilter.md).

## Considered Options

- Keep `FindStringSubmatch` and tolerate the allocs.
- Switch to `FindStringSubmatchIndex`, materialise substrings as slices of
  the original input (zero-alloc).

## Decision Outcome

Chosen: **`FindStringSubmatchIndex` + slice-into-input substrings**,
passing `""` for non-participating optional groups (negative index).

PR-body benchmark:

```
FindStringSubmatch       355.9 ns/op  128 B/op  2 allocs
FindStringSubmatchIndex  316.0 ns/op   64 B/op  1 alloc     (~11% faster)
```

Allocations halved; memory halved.

## Technical Discussion

No substantive technical discussion recorded on the PR thread. The code
change is small and self-contained; reviewers approved on the benchmark
evidence.

## Participants

- @jptosso — author
- @fzipi — review

## Consequences

- **Positive:** Always-on perf win on the rule-evaluation capture path;
  this shipped outside any build tag because it is semantically identical.
- **Negative:** None.

## References

- PR: https://github.com/corazawaf/coraza/pull/1547
- Extracted from: https://github.com/corazawaf/coraza/pull/1534
