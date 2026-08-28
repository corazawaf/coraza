# ADR-0004: Expose `MatchedRule.Log()` via optional interface

- **Status:** accepted
- **Date:** 2023-07-25
- **Version:** v3.0.3
- **PR:** [#848](https://github.com/corazawaf/coraza/pull/848)
- **Issue(s):** [#839](https://github.com/corazawaf/coraza/issues/839); supersedes PR [#840](https://github.com/corazawaf/coraza/pull/840)
- **Deciders:** @M4tteoP, @jcchavezs, @anuraaga, @jptosso
- **Category:** Feature

## Context and Problem

Consumers wanted to filter matched rules to only those the rule author
intended to audit-log. Users were approximating this via `Rule().Severity()`,
which is not the correct signal — audit-log eligibility depends on the rule's
`log`/`nolog` actions, not its severity. Audit logs were also coming up empty
for some rules marked `log` because the information was not reachable.

## Decision Drivers

- Fix the empty-audit-log bug for `log`-marked rules (root cause).
- Give consumers a reliable way to filter matches for logging.
- Avoid breaking the public `types.MatchedRule` interface in v3.

## Considered Options

- **A.** Add `Log() bool` to the public `types.MatchedRule` interface
  (breaking for anyone implementing the interface).
- **B.** Ship a separate `RuleLogger` interface and let callers do a type
  assertion (non-breaking).
- **C.** Do not expose the method publicly at all; let callers cast to the
  internal struct.

## Decision Outcome

Chosen: **option B** for v3 — a `RuleLogger` assertion-style interface — with
a note that a cleaner v4 will promote the method onto the main interface.

> "one easy way to avoid the breaking change is to not to add `Log` method to
> the interface and do the assertion here with a `RuleLogger` interface … with
> a comment so breaking change can be added in v4."
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/848#discussion_r1269792282))

@anuraaga initially pushed toward option C:

> "Can we just cast to the struct? We do that a few places I think"
> — @anuraaga ([review](https://github.com/corazawaf/coraza/pull/848#discussion_r1271236131))

…and later hardened the position on keeping the public surface small:

> "Let's remove the whole change in this file, it looks like the best it can
> do is provide confusion rather than clarity. If there's no public method,
> there's no public method"
> — @anuraaga ([review](https://github.com/corazawaf/coraza/pull/848#discussion_r1271236246))

The outcome followed @jcchavezs's compromise: the assertion interface shipped,
and the v4-aligned interface promotion is tracked separately.

## Technical Discussion

Discussion revolved almost entirely around API surface hygiene in v3.

@jcchavezs also flagged the risk of the workaround interface leaking into the
long-term API:

> "I'd rather not to expose this interface. Doing so we will be increasing the
> API surface and also this interface is just a workaround and very likely to
> be removed in v4. Also, go interface implementation is implicit so anyone
> can declare an interface and do the same assertion."
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/848#discussion_r1270918803))

Two supersession links are on the record: PR #840 was replaced by this one,
and issue #839 was the user-reported symptom.

## Participants

- @M4tteoP — author
- @jcchavezs — review (API surface, v4 plan)
- @anuraaga — review (structural casting alternative)
- @joshi-mohit — original reporter (quoted in PR body)

## Consequences

- **Positive:** Audit-log filtering works correctly; `log` action is respected;
  no v3 API break.
- **Negative / follow-up:** Two ways exist to inspect the logging intent (the
  optional interface, the internal struct). v4 is expected to clean this up by
  promoting the method to `types.MatchedRule`.

## References

- PR: https://github.com/corazawaf/coraza/pull/848
- Issue: https://github.com/corazawaf/coraza/issues/839
- Superseded PR: https://github.com/corazawaf/coraza/pull/840
