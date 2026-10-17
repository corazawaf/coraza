# ADR-0064: `evalDepth` action for depth first chain evaluation

- **Status:** proposed
- **Date:** 2026-10-18 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** [#1744](https://github.com/corazawaf/coraza/pull/1744)
- **Issue(s):** [#1608](https://github.com/corazawaf/coraza/issues/1608)
- **Deciders:** @adilalperenciftci
- **Category:** Feature

## Context and Problem

A chain starter is matched against every target before the chained rules run,
and the chained rules run once. `MATCHED_VAR`, `MATCHED_VAR_NAME` and the
`capture` groups `TX:0`-`TX:9` are overwritten on each match, so the chained
rules only see the last one:

```apache
SecRule ARGS "@rx (attack\d+)" "id:1,capture,chain"
    SecRule TX:1 "@rx attack2" "deny"
```

With `a=attack2&b=attack1` the chained rule sees `TX:1=attack1` and the chain
does not match, although `a` alone satisfies it. ModSecurity v2 and v3 behave
the same way, and CRS rules are written against that behaviour, so changing
the default is not an option.

## Decision Drivers

- Existing rulesets, CRS first, must evaluate exactly as before.
- The parent operator must not be evaluated more than once per target.
- Nested chains (a chained rule that also matches several targets) must get
  the same treatment, not only the first link.
- No cost on the default path beyond a flag check.

## Considered Options

The issue lists four:

- A. A per-rule action on the chain starter.
- B. A global directive switching every chain to depth first.
- C. A new `SecRuleDepthFirst` directive.
- D. Keep the per-match context (`MATCHED_VAR`, `MATCHED_VAR_NAME`,
  `TX:0`-`TX:9`) of each parent match and replay the chained rules once per
  context; combinable with any of A-C as the opt-in.

## Decision Outcome

Chosen: **A as the opt-in, D as the mechanism.** The flow action `evalDepth`
on the chain starter sets `Rule.EvalDepth`. When it is set, each accepted
match records a `chainContext` snapshot. The chained rules are then evaluated
per snapshot, restoring it first; a chained rule that has further links
records its own snapshots and recurses. Evaluation stops at the first
snapshot for which the whole remaining chain matches, and only that path
(the parent match plus the matches below it) is reported to `MatchRule`, so
`msg`/`logdata` expansion and the logged `MatchedDatas` describe the match
that actually satisfied the chain.

B changes semantics for every loaded ruleset at once, which is the risk the
issue flags for CRS. C duplicates the whole `SecRule` parsing path for one
flag and leaves chain children as plain `SecRule` anyway. An action keeps the
choice next to the rule that needs it and costs nothing elsewhere. `evalDepth`
on a chained rule is a parse error, like disruptive actions there.

Semantics that follow from reusing the existing evaluation path:

- Non-disruptive actions of the chain starter still run once per match, as
  they do today. Those of a chained rule run every time it matches, so a
  chained rule can run its `setvar` once per parent context it is tried with.
  Rules relying on counting should keep their `setvar` on the chain starter.
- `multiMatch` keeps working per target; each matching transformation result
  is one context.
- Under `coraza.rule.multiphase_evaluation` the snapshots are taken after the
  double-evaluation check, so a variable chain that already matched in an
  earlier phase is not replayed. The matches that check compares are kept per
  branch (the path above plus one parent match), so a branch that failed
  cannot make a sibling look like a chain that already matched.
- When no path matches, the transaction is left with the state of the last
  attempt, as the breadth first loop leaves the state of the last match.
- A snapshot records which of `TX:0`-`TX:9` existed; restoring it removes
  the ones that did not instead of creating them empty.
- The work has a soft bound. Every match of a rule can make the rules after it
  run again, so a three link chain over `ARGS` is cubic in the number of
  arguments. The chained rules of one chain starter get a budget of 10000
  operator evaluations (`depthFirstEvaluationLimit`). The budget is checked
  between parent contexts, so one rule evaluation may take the count past
  10000. Once exhaustion is observed, the rest of the chain is evaluated once,
  breadth first, with the last parent match, and a warning is logged. Falling
  back to the default evaluation
  rather than declaring no match keeps padding a request with arguments from
  turning the bound into a bypass: past the limit the rule behaves exactly as
  without `evalDepth`.

## Technical Discussion

No substantive technical discussion recorded on #1608 at the time of writing;
the options and trade-offs above come from the issue body.

## Consequences

- One new action, `evalDepth`. Rules without it are evaluated by the same
  loop as before.
- Each parent match costs one snapshot of twelve strings while `evalDepth` is
  set. The chained rules may run up to once per parent match instead of once.
  The soft budget is 10000 evaluations, with the possible single-evaluation
  overshoot described above.
- A Coraza extension: a ruleset using `evalDepth` does not load on
  ModSecurity.

## References

- [#1608](https://github.com/corazawaf/coraza/issues/1608)

## Participants

- @adilalperenciftci — author
- @fzipi — issue author
