# ADR-0050: `SecRxPreFilter` runtime directive for `@rx` pre-filtering

- **Status:** accepted
- **Date:** 2026-04-05
- **Version:** v3.7.0 (directive default `Off`)
- **PR:** [#1589](https://github.com/corazawaf/coraza/pull/1589)
- **Issue(s):** No linked issue (supersedes build-tag gating in [ADR-0049](0049-rx-literal-prefilter.md))
- **Deciders:** @M4tteoP, @jptosso, @fzipi, @Copilot, @coderabbitai
- **Category:** Feature

## Context and Problem

The `@rx` literal pre-filter ([ADR-0049](0049-rx-literal-prefilter.md))
was behind the `coraza.rule.rx_prefilter` build tag. Enabling it required
a rebuild, which made per-instance rollout and A/B testing hard in
production settings.

## Decision Drivers

- Let operators toggle the prefilter per WAF instance without a rebuild.
- Preserve the build tag for Coraza's own CI (test both codepaths).
- Keep default behaviour conservative (directive `Off`) since the
  prefilter is marked experimental.

## Considered Options

- Keep build-tag only.
- Runtime directive, `On` by default.
- Runtime directive, `Off` by default, build tag flips the default to `On`
  for CI/test purposes only.

## Decision Outcome

Chosen: **runtime directive, default `Off`, build tag remains but only
changes the default for tests.** The directive is explicitly labelled
`EXPERIMENTAL` in the recommended config + docs.

> "I added a warning Experimental line on both the recommended and docs
> comments, plus some rewording."
> — @M4tteoP ([comment](https://github.com/corazawaf/coraza/pull/1589#issuecomment-4188929785))

## Technical Discussion

**Copilot's catches shaped the doc and tests:**

Concurrency test that didn't actually exercise the prefilter:

> "`TestPrefilterConcurrentSafety` is intended to validate the prefilter
> closure/Aho-Corasick behavior under concurrency, but `newRX` is
> constructed without `RxPreFilterEnabled: true`, so the operator will not
> build/use the prefilter at all."
> — @Copilot ([review](https://github.com/corazawaf/coraza/pull/1589#discussion_r3032578657))

Default vs. tag-dependent semantics:

> "The directive doc comment says `Default: Off`, but `NewWAF()` sets
> `RxPreFilterEnabled` from `defaultRxPreFilterEnabled`, which becomes
> `true` when built with `coraza.rule.rx_prefilter`. Consider updating
> this comment to reflect that the default can be tag-dependent (or
> explicitly note that the build tag is test-only and changes the
> default)."
> — @Copilot ([review](https://github.com/corazawaf/coraza/pull/1589#discussion_r3032578690))

Runtime-vs-compile-time wording in the recommended config:

> "Line 13 currently describes `SecRxPreFilter` as compile-time behavior,
> but this directive is runtime-configurable. This can confuse operators
> reading the recommended config."
> — @coderabbitai[bot] ([review](https://github.com/corazawaf/coraza/pull/1589#discussion_r3034771145))

Both were applied.

**Should a warning fire on use?** @jptosso asked; @fzipi and @M4tteoP
opted for the `EXPERIMENTAL` comment in the recommended config instead of
a runtime warn log:

> "Should we send a warning telling the user this is an experimental
> feature?"
> — @jptosso ([comment](https://github.com/corazawaf/coraza/pull/1589#issuecomment-4185780082))

## Participants

- @M4tteoP — author
- @jptosso — review (asked about experimental-warning)
- @fzipi — review (approved wording approach)
- @Copilot — reviewer bot (drove doc + test fixes)
- @coderabbitai[bot] — reviewer (wording)

## Consequences

- **Positive:** Operators can enable / disable the prefilter without a
  rebuild; Coraza's CI still exercises both codepaths by toggling the tag.
- **Negative / follow-up:** Two sources of truth for the default
  (directive + build tag); clearly documented as test-only.

## References

- PR: https://github.com/corazawaf/coraza/pull/1589
- Related ADRs: ADR-0049 (rx literal prefilter), ADR-0052 (Aho-Corasick →
  bitmap matcher)
