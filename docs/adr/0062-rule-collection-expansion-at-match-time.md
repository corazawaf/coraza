# ADR-0062: Expand RULE:msg and RULE:logdata at match time

- **Status:** proposed
- **Date:** 2026-10-19 (expected merge date)
- **Version:** unreleased (post-v3.8.1)
- **PR:** [#1750](https://github.com/corazawaf/coraza/pull/1750)
- **Issue(s):** [#1749](https://github.com/corazawaf/coraza/issues/1749)
- **Deciders:** @fzipi
- **Category:** Perf (parity-driven)

## Context and Problem

#1606 made `%{rule.msg}` and `%{rule.logdata}` usable from `setvar` by expanding
both macros into the `RULE` collection at the top of `Rule.doEvaluate`, for every
rule that is evaluated, before its operator runs. The PR described this as
"matching ModSecurity behavior".

Profiling `BenchmarkCRSSimpleGET` with `-memprofilerate=1` (#1749) showed that
expansion as the single largest allocation of a CRS request: ~600 rules are
evaluated per request, most carry `logdata`, and each one built a
`strings.Builder` result that was discarded unless the rule matched. 7% of all
bytes allocated, for values only consumed by the actions of a matching rule.

The parity claim does not hold either. ModSecurity v2 `var_rule_generate`
([`apache2/re_variables.c`](https://github.com/owasp-modsecurity/ModSecurity/blob/v2/master/apache2/re_variables.c))
returns the *raw* action string; libmodsecurity v3 `Rule_DictElement::logdata`
([`src/variables/rule.h`](https://github.com/owasp-modsecurity/ModSecurity/blob/v3/master/src/variables/rule.h))
expands lazily when the variable is read. Neither pre-expands for every rule.

## Decision Drivers

- Remove the per-evaluated-rule allocation without losing what #1606 provides
  (`setvar:'tx.msg=%{rule.msg}'` sees the expanded message).
- `%{MATCHED_VAR*}` inside `msg`/`logdata` should resolve against the current
  match, which the eager version could not do (it ran before the operator).
- Stay at least as close to ModSecurity as before.
- No new surface: no directive, no option.

## Considered Options

- **A. Expand once the rule matches, after `MATCHED_*` are set and before its
  actions run** (`Rule.expandRuleCollection`, called from the two places actions
  run: `Rule.matchVariable` and the multiphase branch of `doEvaluate`).
- **B. Lazy collection**: a `RULE` collection that expands on read, exact v3
  parity. Needs a new collection type and touches the public `collection`
  interfaces for a case no known rule set exercises.
- **C. Keep eager expansion, cache per rule**: the expansion depends on
  transaction state (`TX`, `MATCHED_*`), so a cache would be invalidated on
  almost every evaluation.
- **D. Revert #1606** and expose the raw strings like v2: breaks the `setvar`
  use case #1606 was written for.

## Decision Outcome

Chosen: **A**. It keeps the #1606 contract for every consumer that reads
`%{rule.*}` from actions, fixes `MATCHED_*` resolution inside those macros, and
removes the allocation entirely for rules that do not match.

Timing contract after this change: `RULE:id`, `RULE:rev` and `RULE:severity`
are set when evaluation of a rule starts (unchanged); `RULE:msg` and
`RULE:logdata` are set when the rule matches, immediately after `MATCHED_VAR`,
`MATCHED_VARS`, `MATCHED_VAR_NAME` and `MATCHED_VARS_NAMES` and before any of the
rule's actions. A rule whose *operator* reads its own `RULE:msg` therefore sees
the previously matched rule's value; v2 would hand it the raw macro string, v3
the lazily expanded one. No rule in CRS or in any known rule set does this.

Two smaller allocations from the same profile ride along: the per-chain-child
`logger.With(fmt.Sprintf(...))` is guarded by `IsEnabled` like the parent's
already was, `GetField` skips key lowercasing when the rule has no exceptions,
and `stopWatches` becomes a fixed array instead of a per-transaction map.

Measured on `main` 03989243 vs the branch (`testing/coreruleset`, M5 Max,
n=4+6): SimpleGET −16.8% B/op, −24.0% allocs/op; SimplePOST −13.4% time,
−11.4% B/op; LargePOST −5.8% time, −15.7% B/op.

## Technical Discussion

No substantive technical discussion recorded on the PR thread at the time of
writing beyond the request for this record.

## Participants

- @fzipi — author

## Consequences

- **Positive:** the largest avoidable allocation of a CRS request is gone;
  `%{MATCHED_VAR*}` inside `msg`/`logdata` now refer to the current match.
- **Negative / follow-up:** the (theoretical) `SecRule RULE:msg ...` pattern
  changes meaning as described above. Option B remains available if a rule set
  ever needs exact v3 semantics.

## References

- PR: https://github.com/corazawaf/coraza/pull/1750
- Issue: https://github.com/corazawaf/coraza/issues/1749
- Supersedes the rationale in #1606 (no ADR was written for it)
- Related ADRs: ADR-0061 (bounded transaction retention, same tracking issue)
