# ADR-0012: `SecRuleUpdateTargetByTag` + ID ranges for `SecRuleUpdateTargetByID`

- **Status:** accepted
- **Date:** 2024-03-28
- **Version:** v3.2.0
- **PR:** [#1020](https://github.com/corazawaf/coraza/pull/1020)
- **Issue(s):** [#1018](https://github.com/corazawaf/coraza/issues/1018)
- **Deciders:** @M4tteoP, @jcchavezs, @anuraaga
- **Category:** Parity (ModSecurity / CRS parity)

## Context and Problem

CRS's false-positive-tuning workflow relies on `SecRuleUpdateTargetByTag`
(update targets on every rule carrying a tag) and on `SecRuleUpdateTargetByID`
with numeric ranges (e.g. `1000-2000`). Coraza shipped with the ById variant
but not the ByTag one, and ById could not take ranges — blocking idiomatic
CRS configuration.

## Decision Drivers

- Close an explicit CRS-compatibility gap flagged by the community.
- Reuse existing list-walking code rather than introduce a new lookup
  structure — the operation happens at bootstrap only.
- Maintain pattern-parity with existing `ruleRemoveById` range handling.

## Considered Options

- Linear walk over the rule list, as existing code does.
- Binary search over a sorted ID index.

## Decision Outcome

Chosen: **linear walk, matching the existing `rulegroup.go` pattern**. The
operation fires once at boot so the O(n·m) cost is acceptable; a future
binary search was explicitly deferred.

> "Since this is happens on bootstrap, probably not worth to explore the
> binary search ATM. I am happy to merge this."
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/1020#issuecomment-2022085264))

@M4tteoP pointed at the existing precedent to justify the shape:

> "This is something we are also already doing for other ID ranges: …
> [`rulegroup.go#L83`](https://github.com/corazawaf/coraza/blob/d6a6959df1a3f0b481929fee62ea058c0a811e6b/internal/corazawaf/rulegroup.go#L83)
> Just to address also that one if we come up with a better solution"
> — @M4tteoP ([comment](https://github.com/corazawaf/coraza/pull/1020#issuecomment-2021610897))

## Technical Discussion

Code-level review asked for refactor extraction + defensive parsing:

> "I'd extract this into a function and then reuse it in the else block
> `start == end`"
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1020#discussion_r1531101959))

> "What if start < 0?"
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1020#discussion_r1531103184))

@M4tteoP added an explicit range-bound check with a better error message and
tests:

> "It was implicitly already handled because `idx` ends up being `0` and
> failing Atoi. Still, I added an explicit check to provide a better error
> message and tests."
> — @M4tteoP ([review](https://github.com/corazawaf/coraza/pull/1020#discussion_r1537372801))

## Participants

- @M4tteoP — author
- @jcchavezs — review (extraction, bounds, bootstrap-scope argument)
- @anuraaga — review

## Consequences

- **Positive:** CRS tuning flows (tag-based exclusions, ID-range exclusions)
  now work in Coraza without post-processing.
- **Negative / follow-up:** Bootstrap cost grows linearly with ruleset size
  and number of `SecRuleUpdateTarget*` directives; at CRS scale (~1000 rules)
  this is not a bottleneck. Range compile-time work was later optimised in
  ADR-0041.

## References

- PR: https://github.com/corazawaf/coraza/pull/1020
- Issue: https://github.com/corazawaf/coraza/issues/1018
- Related ADRs: ADR-0041 (`ruleRemoveById` range storage), ADR-0038
  (`map` for `ruleRemoveByID`)
