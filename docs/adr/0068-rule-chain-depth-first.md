# ADR-0068: Global depth-first rule-chain evaluation

- **Status:** proposed
- **Date:** 2026-10-30 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** [#1744](https://github.com/corazawaf/coraza/pull/1744)
- **Issue(s):** [#1608](https://github.com/corazawaf/coraza/issues/1608)
- **Deciders:** pending maintainer acceptance
- **Category:** Feature

## Context and Problem

A chain starter is matched against every target before the chained rules run, and
the chained rules run once. `MATCHED_VAR`, `MATCHED_VAR_NAME` and the capture
groups `TX:0`-`TX:9` are overwritten on each match, so chained rules see only
the final match:

```apache
SecRule ARGS "@rx (attack\d+)" "id:1,capture,chain"
    SecRule TX:1 "@rx attack2" "deny"
```

With `a=attack2&b=attack1`, the chained rule sees `TX:1=attack1` and the
chain does not match although `a` alone satisfies it. ModSecurity v2 and v3
behave the same way, and existing rulesets rely on breadth-first evaluation, so
the default cannot change.

## Decision Drivers

- Existing rulesets, CRS first, must evaluate exactly as before by default.
- Operators on a parent rule must not be evaluated more than once per target.
- Nested chains must preserve each parent match context at every link.
- Administrators must be able to opt in without rewriting individual rules.
- The disabled path must add no allocations and only one flag check per chain.

## Considered Options

- A. A per-rule action on the chain starter.
- B. A global `SecRuleEvalDepthFirst On|Off` directive.
- C. A new `SecRuleDepthFirst` directive.
- D. Preserve each match context and replay chained rules once per context.
  This is an implementation mechanism that can be combined with A-C.

## Decision Outcome

Chosen: **B as the opt-in and D as the mechanism.**

`SecRuleEvalDepthFirst On` sets an immutable WAF configuration flag that is
copied into each transaction. When enabled, every chain starter records a
`chainContext` snapshot for each accepted match. The chained rules are then
evaluated per snapshot after restoring it. A chained rule that has further links
records its own snapshots and recurses. Evaluation stops at the first context
whose entire remaining path matches. Only that path is reported to
`MatchRule`, so `msg`, `logdata` and logged match data describe the path
that satisfied the chain.

The directive defaults to `Off`, preserving the existing breadth-first
semantics. A configuration-level switch avoids a Coraza-only action in rule
files and lets an administrator enable the behavior without rewriting CRS or
another loaded ruleset. A separate `SecRuleDepthFirst` directive would
duplicate the `SecRule` parser while leaving chain children as ordinary
`SecRule` directives.

Collection and map iteration order remains unspecified. Depth-first evaluation
therefore does not define which path wins when several paths satisfy a chain.

Semantics that follow from reusing the existing evaluation path:

- Non-disruptive actions on a chain starter still run once per match. Actions on
  a chained rule run for every matching parent context attempted, including
  contexts whose remaining path later fails.
- `multiMatch` continues to create one context per matching transformation
  result.
- With `coraza.rule.multiphase_evaluation`, snapshots are recorded after the
  double-evaluation check and bookkeeping is kept per branch.
- When no path matches, transaction match state remains that of the final
  attempt, matching the existing breadth-first behavior.
- A snapshot records which of `TX:0`-`TX:9` existed; restore removes captures
  that did not exist instead of creating empty entries.
- `MATCHED_VARS` and `MATCHED_VARS_NAMES` are not restored per attempt. They
  accumulate attempted matches until the next top-level rule.
- The chained rules of one starter have a soft budget of 10000 operator
  evaluations. The budget is checked between parent contexts, so one evaluation
  may overshoot it. Once exhaustion is observed, the remaining chain is
  evaluated once breadth first using the final parent context, and a warning is
  logged. Correlation is therefore best-effort when target cardinality exhausts
  the budget.

## Technical Discussion

> "in case of a directive it is easier to implement as it doesn't involve rewritting CRS."
> — @jptosso ([comment](https://github.com/corazawaf/coraza/pull/1744#issuecomment-6519907967))

## Consequences

- **Positive:** Administrators can enable correct per-match chain correlation for
  an entire WAF without changing rule files.
- **Positive:** The default path remains allocation-free and behavior-compatible.
- **Negative:** Enabling the directive changes every chain in the WAF and can
  multiply chained operator evaluations.
- **Negative:** Each parent match stores a snapshot of twelve strings while the
  setting is enabled.
- **Compatibility:** This is a Coraza extension. A configuration containing
  `SecRuleEvalDepthFirst` does not load unchanged in ModSecurity.

## References

- PR: https://github.com/corazawaf/coraza/pull/1744
- Issue: https://github.com/corazawaf/coraza/issues/1608

## Participants

- @adilalperenciftci — author
- @jptosso — architecture review
- @fzipi — issue author and review
