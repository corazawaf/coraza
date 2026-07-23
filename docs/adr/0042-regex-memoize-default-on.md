# ADR-0042: Regex memoize enabled by default

- **Status:** accepted
- **Date:** 2026-03-18
- **Version:** v3.5.0
- **PR:** [#1540](https://github.com/corazawaf/coraza/pull/1540)
- **Issue(s):** No linked issue (follows [ADR-0006](0006-regex-ahocorasick-memoize.md), [ADR-0043](0043-waf-close-per-owner-memoize.md))
- **Deciders:** @jptosso, @jcchavezs, @fzipi, @app/copilot-swe-agent
- **Category:** Perf (default-policy shift)

## Context and Problem

The regex + Aho-Corasick memoize cache shipped in v3.0.3 behind the
`memoize_builders` build tag ([ADR-0006](0006-regex-ahocorasick-memoize.md)).
Most embedders never knew to set the tag and therefore paid the full
compile cost per WAF. Now that per-owner tracking and `WAF.Close()` landed
([ADR-0043](0043-waf-close-per-owner-memoize.md)), the cache can be safely
default-on.

## Decision Drivers

- Make the default-path fast; don't require a flag to get the obvious win.
- Refactor the memoize package to pass a `Memoizer` explicitly through
  `OperatorOptions` so it is testable and injectable.
- Offer `coraza.no_memoize` as an explicit opt-out.

## Considered Options

- Leave opt-in.
- Flip the tag to opt-out (`coraza.no_memoize`).
- Default-on, no opt-out.

## Decision Outcome

Chosen: **default-on with `coraza.no_memoize` opt-out.**

The build tag `memoize_builders` no longer exists. `OperatorOptions` grows a
`Memoizer` field (zero value = no memoization, backwards compatible).

## Technical Discussion

**Caddy validation was a merge gate.** @jcchavezs asked for end-to-end
validation with the Caddy integration:

> "We need to extensively test this with Caddy before merging."
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/1540#issuecomment-4047246804))

@fzipi confirmed the companion Caddy PR:

> "@jcchavezs Added https://github.com/corazawaf/coraza-caddy/pull/275. Can
> you take a look?"
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1540#issuecomment-4063209206))

**TinyGo CI stalled** because the scale benchmarks that now ran on default
builds are extremely slow on TinyGo's regex engine. @fzipi captured the
exact arithmetic:

> "**`TestCacheBoundedWithClose`** — 100 cycles × 300 patterns =
> **30,000 `regexp.Compile` calls** under TinyGo (each `Release` clears the
> cache, so every cycle recompiles all 300 patterns). … TinyGo's regex
> engine is dramatically slower than Go's, so these scale tests were not a
> good fit for the default CI matrix"
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1540#issuecomment-4064049379))

The tests were reshaped to fit TinyGo timing before the PR merged.

**Coverage and lint** drove two follow-up Copilot PRs (#1555, #1556).

## Participants

- @jptosso — author
- @jcchavezs — review (Caddy integration gate)
- @fzipi — review (TinyGo CI triage, coverage driver)
- @app/copilot-swe-agent — orchestrated coverage + lint follow-ups

## Consequences

- **Positive:** All embedders get the memoize speedup by default; operator
  plugins receive a `Memoizer` explicitly and are easier to test.
- **Negative / follow-up:** TinyGo scale benchmarks were reshaped because
  the slower regex engine can't run them in CI time. Backwards-compat for
  out-of-tree operator plugins is maintained via the zero-value-Memoizer
  behaviour.

## References

- PR: https://github.com/corazawaf/coraza/pull/1540
- Caddy validation: https://github.com/corazawaf/coraza-caddy/pull/275
- Related ADRs: ADR-0006 (initial memoize), ADR-0043 (`WAF.Close()` +
  per-owner tracking)
