# ADR-0062: `ctl:ruleEngine=Off` is final for the transaction

- **Status:** proposed
- **Date:** 2026-11-21 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** [#1863](https://github.com/corazawaf/coraza/pull/1863)
- **Issue(s):** No linked issue
- **Deciders:** @M4tteoP
- **Category:** Parity (SecLang parity)

## Context and Problem

`ctl:ruleEngine=Off` only sets `tx.RuleEngine`
(`internal/actions/ctl.go`). The mode is read at the start of each
`Process*` call (`IsRuleEngineOff` in `internal/corazawaf/transaction.go`),
but `RuleGroup.Eval` (`internal/corazawaf/rulegroup.go`) never reads it
between rules. The rest of the current phase therefore keeps running after
`Off`. A later rule of the same phase that sets `ctl:ruleEngine=DetectionOnly`
or `=On` overwrites `Off`, and every later phase runs again.

A common exclusion turns the engine off for a path or a client. Any later
rule of that phase that sets the mode, for example one that switches a set of
clients to `DetectionOnly`, silently undoes the exclusion, and the request
body and the response are inspected after all. With `=On`, the request can
also be blocked.

The engines differ here:

- ModSecurity v2 checks the mode before every rule
  (`apache2/re.c`, `msre_ruleset_process_phase_`). Once `Off` is set, no
  later rule runs, so `Off` holds for the rest of the transaction.
- libmodsecurity v3 behaves like Coraza: it reads the mode only when a phase
  starts (`src/transaction.cc`).

The SecLang specification has settled the question in seclang-spec
ADR-0034: after `ctl:ruleEngine=Off` the engine MUST NOT evaluate any
further rule of the transaction. It withdraws the earlier advice that a
disabling rule SHOULD be the last rule of its phase. It lists Coraza as
failing `tests/engine/processing/ctl-ruleengine-off-final.yaml` in
`compat/known-gaps.md`.

## Decision Drivers

- An exclusion that turns the engine off must hold. It must not depend on
  no later rule of the phase touching the mode.
- Parity with ModSecurity v2 and with the SecLang specification
  (seclang-spec ADR-0034).
- No cost on the hot path beyond one comparison per evaluated rule.

## Considered Options

- **Keep last write wins** (current behaviour, shared with libmodsecurity
  v3). A ruleset cannot rely on an exclusion, because any later mode change
  undoes it.
- **Stop evaluating the phase once the engine is off**: check
  `tx.IsRuleEngineOff()` in the `RuleGroup.Eval` loop, next to the existing
  interruption check. The `Process*` calls already skip the later phases.
- **Reject `ctl:ruleEngine` after `Off` inside the `ctl` action**: make the
  action a no-op once the mode is `Off`. This keeps the mode but still runs
  every later rule of the phase with the engine nominally off, so rules,
  `setvar` and logging still execute. It does not match ModSecurity v2 or
  the specification.

## Decision Outcome

Chosen: **stop evaluating the phase once the engine is off**. It matches
ModSecurity v2 and seclang-spec ADR-0034. It is one check in the rule loop,
and it applies the same way in every phase and under
`coraza.rule.multiphase_evaluation`.

`ctl:ruleEngine=On` and `=DetectionOnly` keep their current meaning. They
apply at once to the interruption decision of the current phase, and to
every later phase.

## Technical Discussion

No substantive technical discussion recorded in this repository yet. The
decision follows seclang-spec ADR-0034, which was discussed and accepted in
the SecLang specification repository.

## Participants

- @M4tteoP — author

## Consequences

- **Positive:** an engine-off exclusion can no longer be undone by a later
  rule of the same phase. Coraza passes the specification's
  `ctl-ruleengine-off-final` test.
- **Negative / follow-up:** this is a behaviour change for rule authors. A rule
  placed after a matching `ctl:ruleEngine=Off` in the same phase no longer
  runs. That includes logging, `setvar` and a later `ctl`. A rule that must
  still run has to go before the `Off`. The audit log is unaffected:
  `ProcessLogging` still writes it after skipping the phase 5 rules.

## References

- seclang-spec ADR-0034, `ctl:ruleEngine=Off` is final for the transaction:
  <https://github.com/fzipi/seclang-spec/blob/main/adr/0034-ruleengine-off-is-final.md>
- seclang-spec `spec/03-processing-model.md#ctl-timing`,
  `spec/08-actions.md#ctlruleengine`
- Regression profile: `testing/engine/ctl.go`, "ruleEngine=Off is final for the
  transaction"
