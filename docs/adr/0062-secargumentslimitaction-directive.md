# ADR-0062: `SecArgumentsLimitAction` directive

- **Status:** proposed
- **Date:** 2026-10-20 (update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** Not yet opened
- **Issue(s):** No linked issue
- **Deciders:** @jenshu
- **Category:** Feature

## Context and Problem

`SecArgumentsLimit` (default 1000, ADR-0002) applies to the query string and the
path, and since v3.8.0 to urlencoded or JSON request bodies as well. Arguments
beyond the limit are dropped and `ARGUMENTS_LIMIT_REACHED` is set to 1. The engine
does nothing else: rejecting the request is left to rules 200004 and 200005 in
`coraza.conf-recommended`.

A deployment without those rules (CRS on its own, an older vendored copy of
`coraza.conf-recommended`, a custom ruleset, a connector that ships its own config)
lets the request through with the dropped arguments uninspected. A request can put
1000 harmless arguments first and the payload after them. Before v3.8.0, every body
argument was inspected, so for these deployments the change lost coverage silently.
CRS 4.30.0 does not reference `ARGUMENTS_LIMIT_REACHED`. Its closest rule, 920380
(`&ARGS @gt tx.max_num_args`), is disabled unless `tx.max_num_args` is set.

The request body limit has no such gap: `SecRequestBodyLimitAction` defaults to
`Reject`, so with the rule engine on, Coraza returns 413 when a body is too large
without depending on loaded rules. It also provides `ProcessPartial` for operators
who want inspection of the portion that fits.

## Decision Drivers

- A WAF that drops input should not let the request through uninspected by default.
- Reuse an existing shape (`SecRequestBodyLimitAction Reject|ProcessPartial`) rather
  than designing a new one.
- Keep rules 200004/200005 observable: their rule id, message and error-log line.
- Keep `DetectionOnly` non-disruptive and rule-controlled exceptions possible.
- Let `ProcessPartial` restore today's rule-only behavior.

## Considered Options

- **Keep the rule-based approach** (rules 200004/200005). This is what ModSecurity
  does: its `modsecurity.conf-recommended` has `SecRule &ARGS "@ge 1000"` (rule
  200007) and no action directive. It leaves the gap for configs without the rules.
- **Log a warning at WAF creation** when no loaded rule references
  `ARGUMENTS_LIMIT_REACHED`, relying on operators to notice it.
- **Make `SecArgumentsLimit` itself always reject**: exceeding it returns 400 (or
  records it in `DetectionOnly`), with no new directive. This is simpler but removes
  partial processing and rule-only enforcement.
- **Add `SecArgumentsLimitAction`, defaulting to `ProcessPartial`.** Backward
  compatible, but leaves existing configurations unprotected by default.
- **Add `SecArgumentsLimitAction`, defaulting to `Reject`.**

## Decision Outcome

Chosen: **`SecArgumentsLimitAction Reject|ProcessPartial`, defaulting to `Reject`**,
because it closes the gap by default without depending on loaded rules, follows the
existing request-body-limit shape, and preserves rule-only enforcement through
`ProcessPartial`.

- **Timing and precedence.** Coraza applies `Reject` after the applicable rules:
  normally phase 1 for `ARGS_GET`/`ARGS_PATH` and phase 2 for `ARGS_POST`; query or
  path arguments added between phases 1 and 2 are checked in phase 2. The intake
  APIs cannot return an interruption, so the phase boundary is the earliest point.
  A rule interruption takes precedence. In `DetectionOnly`, the fallback records
  rather than performs the interruption; after a `ctl:ruleEngine=On` switch, an
  earlier recorded interruption no longer suppresses enforcement. `allow` does not
  bypass this engine-level limit, consistent with request-body-limit rejection.
  Rule-controlled exceptions use `ProcessPartial` and rules on
  `ARGUMENTS_LIMIT_REACHED`.
- **Source tracking and publication.** Because `ARGUMENTS_LIMIT_REACHED` is shared,
  the transaction separately tracks URI, request-body and response truncation.
  URI truncation publishes the flag immediately; POST and response arguments added
  through the API publish it from phase 2 or phase 4, or from phase 5 if their phase
  never ran. Delayed publication prevents a POST overflow from firing phase-1 rule
  200004 ("GET/PATH args"). Response truncation never triggers this fallback,
  although rules on the flag can still act.
- **Body processor reporting.** If a URI overflow has already set the shared flag,
  a request body processor receives a scoped flag so an independent body overflow
  is still detected, without changing the plugin interface.
- **Interruption.** The fallback uses `deny` with status 400, matching rules
  200004/200005 and ModSecurity rule 200007, but has no rule id.

## Technical Discussion

No substantive technical discussion recorded on an issue or pull request; this ADR
was written alongside the change, before either was opened.

## Participants

- @jenshu — author

## Consequences

- **Positive:** a request whose arguments were dropped is rejected by default,
  without depending on loaded rules. Existing recommended rules retain precedence,
  preserving their rule id and message when they interrupt.
- **Negative / follow-up:** This is a minor-release behavior change: without
  rules 200004/200005, requests exceeding `SecArgumentsLimit` for one source now
  receive a 400 without a rule id, message or error-log line (but recorded in debug
  and audit logs), instead of passing with excess arguments dropped. Operators can
  raise the limit or use `ProcessPartial`. `Reject` also makes per-route exceptions
  coarser: neither `allow` nor removing both rules bypasses it, while
  `ctl:ruleEngine=DetectionOnly` disables all blocking. For API-added POST/response
  arguments, flag visibility shifts to phase 2/4 (or 5), changing an early POST
  overflow's attribution from rule 200004 to 200005; other timing is unchanged and
  existing query double matches in `DetectionOnly` remain. Multipart fields remain
  outside the limit and require separate work.

## References

- ModSecurity v3.0.17 `modsecurity.conf-recommended`, rule 200007:
  https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.17/modsecurity.conf-recommended
- v3.8.1 release notes: https://github.com/corazawaf/coraza/releases/tag/v3.8.1
- Related ADRs: ADR-0002 (`SecArgumentsLimit`), ADR-0059 (`SecResponseBodyJsonDepthLimit`,
  a Coraza-only directive mirroring an existing one)
