# ADR-0009: Structured `debuglog` facade

- **Status:** accepted
- **Date:** 2024-02-01
- **Version:** v3.1.0
- **PR:** [#971](https://github.com/corazawaf/coraza/pull/971)
- **Issue(s):** No linked issue
- **Deciders:** @jcchavezs, @anuraaga, @fzipi
- **Category:** Refactor

## Context and Problem

Coraza's internal logging was an ad-hoc mix of formatted strings that made
transaction logs hard to reason about. The author posted [a gist of a
representative transaction log](https://gist.github.com/jcchavezs/ef0846bf457d2d6ab8b24bfce83860ce)
as evidence that the output was not actionable for operators or for future
structured-ingestion (SIEM/OTel-style).

## Decision Drivers

- Provide structured, attribute-style logging so downstream consumers can
  parse or filter reliably.
- Do not change the public logging interface consumers already wire up;
  improve the call sites and internal facade.

## Considered Options

- Adopt `slog` outright and deprecate `debuglog`.
- Keep `debuglog` as the public interface, rework call sites to emit
  structured fields through it.

## Decision Outcome

Chosen: **keep `debuglog` as the public interface, rework call sites** so
existing log-sink integrations (zerolog, zap, slog, …) continue to work
while the content of the logs becomes structured and more consistent.

## Technical Discussion

No substantive technical discussion recorded on the PR or issue thread. The
change was merged with review approval and a Codecov report; no architectural
debate was held publicly on this PR. The motivating evidence — a real-world
log sample — is captured in the PR body as a linked gist, which stands in for
the "why".

## Participants

- @jcchavezs — author
- @anuraaga — review (approval only on this PR)
- @fzipi — review (approval only on this PR)

## Consequences

- **Positive:** Logs have consistent structure; embedders can bind
  attributes to their own log backend; future work to route to `slog`
  becomes tractable.
- **Negative / follow-up:** The facade is still hand-rolled rather than
  `slog`. A future major (v4) may align with `log/slog` now that the Go
  stdlib has it.

## References

- PR: https://github.com/corazawaf/coraza/pull/971
- Linked gist (evidence): https://gist.github.com/jcchavezs/ef0846bf457d2d6ab8b24bfce83860ce
