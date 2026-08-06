# ADR-0001: Enable RESPONSE_ARGS collection

- **Status:** accepted
- **Date:** 2023-06-12
- **Version:** v3.0.1
- **PR:** [#811](https://github.com/corazawaf/coraza/pull/811)
- **Issue(s):** No linked issue
- **Deciders:** @jptosso, @M4tteoP, @fzipi
- **Category:** Parity (ModSecurity parity)

## Context and Problem

ModSecurity exposes a `RESPONSE_ARGS` collection so rules can inspect arguments
parsed from the response body (for example JSON response fields). Coraza v3.0.0
had the scaffolding but the collection was not wired up end-to-end — there was
no way to write response-phase argument matching rules.

## Decision Drivers

- Parity with ModSecurity behaviour for rules that inspect response bodies.
- Symmetry with the existing `ARGS_GET`/`ARGS_POST` request-phase infrastructure.

## Considered Options

- Build a brand-new response-argument pipeline.
- Reuse the existing request-side body processors and simply enable the
  response-arg collection on the transaction.

## Decision Outcome

Chosen: **reuse the existing body processors** to populate a response-arg
collection. The PR is minimal, surfacing the feature rather than introducing a
new subsystem.

## Technical Discussion

The PR itself ships without a written description. Review feedback focused on
housekeeping rather than design, and follow-up work was explicitly deferred.

> "Can we move this TODO to a proper issue so someone might implement it?"
> — @fzipi ([review comment](https://github.com/corazawaf/coraza/pull/811#discussion_r1226569095))

> "There is a work in progress around it: …" — @M4tteoP, pointing at the
> in-progress response-arg discussion on OWASP Slack
> ([review comment](https://github.com/corazawaf/coraza/pull/811#discussion_r1227294607))

No substantive architectural debate took place on the PR thread itself; the
design was discussed out-of-band (OWASP Slack) and the code change was merged
with two approvals.

## Participants

- @jptosso — author
- @M4tteoP — review, Slack discussion pointer
- @fzipi — review

## Consequences

- **Positive:** Response-phase rules can now match on parsed body arguments,
  closing a compatibility gap with ModSecurity.
- **Negative / follow-up:** Response-body argument parsing uses the same
  processors as requests, so any parser limitations (JSON depth, etc.) apply
  symmetrically. Later limits such as `SecArgumentsLimit` (ADR-0002) were added
  to keep this surface bounded.

## References

- PR: https://github.com/corazawaf/coraza/pull/811
- Related ADRs: ADR-0002 (SecArgumentsLimit directive)
