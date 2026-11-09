# ADR-0070: Cache the rules a ctl selects, keyed by the rule group's version

- **Status:** proposed
- **Date:** 2026-11-08 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** [#1849](https://github.com/corazawaf/coraza/pull/1849)
- **Issue(s):** [#1848](https://github.com/corazawaf/coraza/issues/1848)
- **Deciders:** @rforced
- **Category:** Perf

## Context and Problem

Five ctl actions select rules: `ruleRemoveTargetById`, `ruleRemoveTargetByTag`
and `ruleRemoveTargetByMsg`, and `ruleRemoveByTag` and `ruleRemoveByMsg`. Each
walked `GetRules()` by value on every evaluation, copying every `Rule`, to find
the rules it applies to. `ruleRemoveTargetById` walked the whole list even for a
single ID. A target removal then appended to `tx.ruleRemoveTargetByID` once per
selected rule, and each append allocated a slice of its own.

The cost grows with what the ctl selects.
`ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:x`, a common way to write an
application exclusion, selects every CRS rule (about 600) on each request it
runs. CRS itself runs `ctl:ruleRemoveTargetByTag=xss-perf-disable;REQUEST_FILENAME`
on every request.

## Decision Drivers

- The rules are fixed once `coraza.NewWAF` returns, so what a ctl selects only
  changes while directives are parsed.
- Concurrent transactions share the ctl action, so the cache must work without
  a lock on the request path.
- No allocation per transaction for the cache, and none for the removals beyond
  the map.
- Behaviour stays the same, including the "Invalid range" log on every
  evaluation of a ctl whose ID range does not parse.
- The TinyGo build stays green.

## Considered Options

- **Select once in `Init`.** Not possible: `Init` runs while the rule holding
  the ctl is parsed, and the rules it selects usually come later (CRS
  exclusions sit before the rules they exclude).
- **Cache keyed by the rule slice** (its backing array and length). The first
  version of this PR. A removal followed by an addition can leave the same
  array and length with different rules, so the cache would return a stale
  selection. It also kept the old array alive.
- **Cache keyed by a version of the rule group.** `RuleGroup` takes a new
  version on every addition or removal.
- **A tag index on `RuleGroup`.** It would shorten the walk but still run it on
  every transaction, and it does not help selection by msg.

## Decision Outcome

Chosen: **a cache keyed by the rule group's version**, because it is exact for
every change to the group's membership and costs one load and one comparison
per evaluation.

- `RuleGroup.Add`, `DiscardPendingChain`, `DeleteByID`, `DeleteByRange`,
  `DeleteByMsg` and `DeleteByTag` set a new version. Versions come from one
  package-wide atomic counter, so two groups never share a version once either
  has changed. That matters because a ctl action can sit in two WAFs: a
  `*Rule` passed through `WAFConfig.WithRules` is added to every WAF the config
  builds.
- Each selecting ctl keeps an `atomic.Pointer` to the version it walked and the
  IDs it found. Two transactions that miss at the same time both walk and store
  the same result. The walk takes `&rules[i]` instead of copying each rule.
- A failed ID range parse is not cached, so it is still logged on every
  evaluation.
- `Transaction.RemoveRuleTargetByIDs` adds one removal to many rules. Rules with
  no removal yet share one slice whose length equals its capacity, so a later
  append for one rule copies instead of writing into the others. The map is
  made on the first removal, sized for it, instead of on every transaction
  reset. `RemoveRuleTargetByID` calls it with one ID.

Edits made in place are not versioned. `SecRuleUpdateActionById` can change a
rule's tags or msg without adding or removing a rule. Through the public API
directives only run while `NewWAF` builds the WAF, before any transaction, so
no selection exists yet. Internal callers that parse more directives after
transactions ran must not rely on such an edit being seen.

`BenchmarkCRSCtlRuleRemoveTarget` sends `BenchmarkCRSSimpleGET`'s request
through CRS with no ctl, with ten `ctl:ruleRemoveTargetById`, and with one
`ctl:ruleRemoveTargetByTag=OWASP_CRS`. benchstat over 10 runs each, alternating
between main (08aa511) and this change, Go 1.26.10 on amd64:

```
                                         │    main     │               branch                │
                                         │   sec/op    │   sec/op     vs base                │
CRSCtlRuleRemoveTarget/none-32             501.3µ ± 6%   482.0µ ± 7%        ~ (p=0.063 n=10)
CRSCtlRuleRemoveTarget/byId10-32           533.7µ ± 3%   497.1µ ± 4%   -6.85% (p=0.000 n=10)
CRSCtlRuleRemoveTarget/byTagOWASP_CRS-32   564.9µ ± 2%   505.2µ ± 5%  -10.58% (p=0.000 n=10)
geomean                                    532.7µ        494.7µ        -7.13%

                                         │     main     │                branch                │
                                         │     B/op     │     B/op      vs base                │
CRSCtlRuleRemoveTarget/none-32             188.1Ki ± 1%   184.1Ki ± 1%   -2.14% (p=0.000 n=10)
CRSCtlRuleRemoveTarget/byId10-32           188.3Ki ± 1%   188.1Ki ± 1%        ~ (p=0.986 n=10)
CRSCtlRuleRemoveTarget/byTagOWASP_CRS-32   310.4Ki ± 1%   231.5Ki ± 1%  -25.41% (p=0.000 n=10)
geomean                                    222.4Ki        200.2Ki        -9.98%

                                         │    main     │               branch                │
                                         │  allocs/op  │  allocs/op   vs base                │
CRSCtlRuleRemoveTarget/none-32             3.657k ± 0%   3.620k ± 0%   -1.00% (p=0.000 n=10)
CRSCtlRuleRemoveTarget/byId10-32           3.672k ± 0%   3.639k ± 0%   -0.89% (p=0.000 n=10)
CRSCtlRuleRemoveTarget/byTagOWASP_CRS-32   4.378k ± 0%   3.738k ± 0%  -14.62% (p=0.000 n=10)
geomean                                    3.888k        3.666k        -5.73%
```

## Technical Discussion

The automated review found the stale selection that moved the key from the
rule slice to a version:

> "If rule 10 is deleted and matching rule 11 is added between evaluations, the slice can retain its address and length. The ctl then reuses ID 10, so a request may be blocked by rule 11. Track rule-group mutations and refresh the selection after replacement."
> — @coderabbitai ([review](https://github.com/corazawaf/coraza/pull/1849#discussion_r4508885557))

## Participants

- @rforced — author
- @coderabbitai — reviewer bot

## Consequences

- **Positive:** a selecting ctl walks the rules once per WAF instead of once per
  transaction, and a target removal over many rules allocates one slice. The
  tag case drops about a quarter of its bytes and a seventh of its allocations.
- **Negative / follow-up:** what is left of the tag case is evaluation: each
  selected rule appends the exception to its variable's list, and `GetField`
  filters on it. In-place edits after transactions ran are not seen (above).
  [#1782](https://github.com/corazawaf/coraza/pull/1782) changes the same loops
  to skip rules without an ID; whichever lands second puts the skip into the
  selection walk. [#1645](https://github.com/corazawaf/coraza/pull/1645) touches
  the same `RuleGroup` methods.

## References

- PR: https://github.com/corazawaf/coraza/pull/1849
- Issue: https://github.com/corazawaf/coraza/issues/1848
- Related ADRs: none
