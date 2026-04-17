# ADR-0011: Expose expected directives for e2e testing

- **Status:** accepted
- **Date:** 2024-03-08
- **Version:** v3.2.0
- **PR:** [#1012](https://github.com/corazawaf/coraza/pull/1012)
- **Issue(s):** [#1006](https://github.com/corazawaf/coraza/issues/1006)
- **Deciders:** @fionera, @M4tteoP
- **Category:** Feature

## Context and Problem

Downstream connectors (proxy-wasm, Caddy, nginx, …) need a way to run
end-to-end correctness tests against Coraza. To do that, they need to know
which directives their e2e harness is expected to load. Previously, this
value was implicit — each connector hard-coded its own copy of the expected
directive set, drifting over time.

## Decision Drivers

- Single source of truth for the e2e directive set, so connectors can import
  it instead of copying.
- Keep the API narrow: this is a testing facility, not a production API.

## Considered Options

- Document the required directives in prose and let connectors duplicate.
- Export a `Directives` constant from a dedicated `http/e2e` package for
  connectors to import.

## Decision Outcome

Chosen: **export `Directives` from `http/e2e`** and link to it from doc
comments.

## Technical Discussion

Review was limited to wording refinements — no architectural debate.

> "I would be a bit more verbose considering that loading these directives is
> a very needed step to run e2e and we need to make [sure] they actually take
> a look at the file we are pointing them"
> — @M4tteoP ([review](https://github.com/corazawaf/coraza/pull/1012#discussion_r1513149551))

The final comment points readers directly at the source of truth:
`http/e2e/e2e.go`'s `Directives` constant.

## Participants

- @fionera — author
- @M4tteoP — review (comment wording)

## Consequences

- **Positive:** Connector e2e suites import `Directives` instead of
  maintaining parallel copies; drift is removed.
- **Negative / follow-up:** Adds a small `http/e2e` surface to the public
  import path.

## References

- PR: https://github.com/corazawaf/coraza/pull/1012
- Issue: https://github.com/corazawaf/coraza/issues/1006
