# ADR-0037: `ctl:ruleRemoveTargetById` whole-collection exclusion

- **Status:** accepted
- **Date:** 2026-03-05
- **Version:** v3.4.0
- **PR:** [#1495](https://github.com/corazawaf/coraza/pull/1495)
- **Issue(s):** No linked issue
- **Deciders:** @app/copilot-swe-agent (author), @fzipi (review)
- **Category:** Parity (closes ModSecurity-compatible exclusion gap)

## Context and Problem

`ctl:ruleRemoveTargetById=RULE_ID;COLLECTION` (no `:key` suffix) had no
effect — only the keyed form `COLLECTION:key` worked. This meant an operator
could not say "exclude the entire `ARGS` collection from rule 941390" — a
common CRS tuning pattern.

Root cause (from the PR body):

> "In `GetField()`, exception matching evaluated:
> `(ex.KeyRx != nil && ex.KeyRx.MatchString(lkey)) || strings.ToLower(ex.KeyStr) == lkey`
> When no key is specified, `ex.KeyStr == \"\"` and `ex.KeyRx == nil`. The
> second condition only matched parameters with an empty name, so all real
> parameters passed through unfiltered."
> — PR body

## Decision Drivers

- Match ModSecurity's whole-collection exclusion semantics.
- Minimal surface change — one additional wildcard branch in the match
  expression.

## Considered Options

- Treat empty-key exceptions as wildcards in the existing match expression.
- Introduce a separate code path for whole-collection exclusion.

## Decision Outcome

Chosen: **extend the match expression with an empty-key wildcard branch:**

```go
(ex.KeyRx != nil && ex.KeyRx.MatchString(lkey)) ||
  strings.ToLower(ex.KeyStr) == lkey ||
  (ex.KeyStr == "" && ex.KeyRx == nil)
```

Tests added at both unit (`TestNoMatchEvaluateBecauseOfWholeCollectionException`)
and integration (`testing/engine/ctl.go`) levels.

## Technical Discussion

No substantive technical discussion recorded on the PR thread. The Copilot
SWE agent authored the change in response to a human-filed bug; reviewers
approved the one-line fix on the strength of the root-cause analysis in the
PR body.

## Participants

- @app/copilot-swe-agent — author
- @fzipi — review

## Consequences

- **Positive:** Whole-collection exclusions work; CRS tuning idiom
  `ctl:ruleRemoveTargetById=941390;ARGS` now has effect.
- **Negative:** None — purely additive behaviour.

## References

- PR: https://github.com/corazawaf/coraza/pull/1495
- Related ADRs: ADR-0047 (regex keys in `ctl:ruleRemoveTarget*`)
