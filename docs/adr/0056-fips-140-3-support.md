# ADR-0056: Runtime FIPS 140-3 support for `t:md5` / `t:sha1`

- **Status:** accepted
- **Date:** 2026-08-28
- **Version:** unreleased
- **PR:** [#1678](https://github.com/corazawaf/coraza/pull/1678)
- **Issue(s):** No linked issue (follows up on [#1629](https://github.com/corazawaf/coraza/pull/1629#issuecomment-4726930186))
- **Deciders:** @M4tteoP, @fzipi, @rikatz
- **Category:** Feature

## Context and Problem

> "Go's FIPS 140-3 mode is detected at runtime via crypto/fips140.Enabled(), no
> build tag, and default builds are unchanged. MD5 and SHA-1 aren't
> FIPS-approved, so t:md5 and t:sha1 are unavailable in this mode. They stay
> registered so rule sets still load — the CRS itself uses t:sha1 in
> REQUEST-901-INITIALIZATION.conf (901320, 901410), and rejecting at load
> would make it unloadable. Instead the transformation errors at evaluation,
> the engine logs a warning, and the operator sees the untransformed value:
> the rule stops matching rather than interrupting the transaction."
> — @M4tteoP, PR description ([#1678](https://github.com/corazawaf/coraza/pull/1678))

That last claim — "the rule stops matching" — turned out to be inaccurate; see
Technical Discussion.

## Decision Drivers

- Detect FIPS 140-3 mode at runtime (`crypto/fips140.Enabled()`) rather than a
  build tag, so default builds are unaffected and no separate binary is needed.
- Keep `t:md5`/`t:sha1` registered even though they aren't FIPS-approved,
  since CRS's `REQUEST-901-INITIALIZATION.conf` uses `t:sha1` (901320, 901410)
  and rejecting the directive at load time would make the ruleset unloadable.
- The `@validateSchema` memoizer cache key used raw MD5 hex, which panics
  under `fips140=only` even though it is used only as a cache key, not a
  security primitive.

## Considered Options

- Reject rules using `t:md5`/`t:sha1` at config-load time when FIPS-only mode
  is active.
- Gate the FIPS-aware code behind a build tag, mirroring ADR-0040's `crslang`
  pattern.
- Detect FIPS mode at runtime; keep `t:md5`/`t:sha1` registered so rule sets
  still load, and degrade at evaluation time (transformation errors, engine
  logs a warning, evaluation continues).

## Decision Outcome

Chosen: **runtime detection via `crypto/fips140.Enabled()`, no build tag.**
Under FIPS-only mode, `t:md5`/`t:sha1` return an error at evaluation instead
of being rejected at load, because rejecting at load would make CRS's own
`REQUEST-901-INITIALIZATION.conf` unloadable. The `@validateSchema` memoizer
key moved off MD5.

## Technical Discussion

**The "rule stops matching" framing in the PR description was wrong** —
@fzipi traced the actual transformation-chain behavior and reproduced it:

> "This isn't what happens — the rule doesn't stop matching, it evaluates
> against the untransformed value. […] The chain continues. So
> `t:sha1,t:hexEncode` doesn't become a no-op — it becomes `t:hexEncode`
> applied to raw input. […] The rule matches either way. What changes is that
> the per-IP persistence collection key becomes the hex of the raw,
> attacker-controlled `User-Agent`, unbounded in length — an 8KB UA yields a
> ~16KB key instead of 40 bytes, ~400x memory amplification per tracked
> collection, attacker-chosen. […] Suggestion: return a fixed sentinel value
> with `changed=true` and no error, so downstream transforms see something
> bounded and deterministic […], and emit the operator-facing warning once at
> rule-load time instead of per-evaluation."
> — @fzipi ([review](https://github.com/corazawaf/coraza/pull/1678#discussion_r3762584672))

The sentinel-value / log-once suggestion was not adopted. @M4tteoP's response
kept the per-evaluation warning:

> "Fixed comments, for the log spam this will happen only when these
> transformations are used and fips is active, which should not happen and
> rules outcome might be broken, so these warning logs should be fine in that
> case"
> — @M4tteoP ([comment](https://github.com/corazawaf/coraza/pull/1678#discussion_r3870916867))

**Schema memoizer key: FNV-1a vs. SHA-256.** @fzipi flagged that FNV-1a, while
namespaced, is a weaker choice than necessary:

> "The `\"schema:\"` namespace prefix is a genuine improvement — the old raw
> MD5 hex shared a global memoizer with regex keys. On FNV-1a though: a
> collision returns the *wrong compiled schema*, silently. Input isn't
> attacker-controlled (schemas come from config at rule-load time) and the
> odds over a handful of schemas are negligible, so this isn't a bug. But
> `sha256.Sum256` is FIPS-approved, already in the binary, the same line
> count, and removes the question entirely. Speed at rule-load time is
> irrelevant here."
> — @fzipi ([review](https://github.com/corazawaf/coraza/pull/1678#discussion_r3762584684))

This was adopted:

> "moved to sha256"
> — @M4tteoP ([comment](https://github.com/corazawaf/coraza/pull/1678#discussion_r3870935761))

@fzipi's full review, after checking out the branch and running the suite
under `fips140=off`, `on` and `only` on Go 1.26, also flagged two vacuous test
fixtures (`md5.json`/`sha1.json` matched on the wrong entry name and asserted
nothing) and a missing `persist-credentials: false` on the new CI job:

> "A bare `return` reports PASS. In the default (non-FIPS) CI run,
> `TestMD5FIPSGuard` and `TestSHA1FIPSGuard` therefore look like they ran and
> passed while asserting nothing — the same failure mode as the vacuous
> `md5.json` suite. […] Use `t.Skip(...)` so the skip is visible in test
> output."
> — @fzipi ([review](https://github.com/corazawaf/coraza/pull/1678#discussion_r3762584688))

## Participants

- @M4tteoP — author
- @fzipi — review (traced actual transformation-chain behavior, memory-
  amplification finding, schema cache-key algorithm; approved)
- @rikatz — review ("did a review, overall lgtm")
- @coderabbitai[bot] — reviewer bot

## Consequences

- **Positive:** FIPS 140-3 deployments can run Coraza (and CRS, which uses
  `t:sha1`) without a separate build; default builds are unchanged.
- **Negative / follow-up:** A rule chain that relies on `t:md5`/`t:sha1`
  transforming a value before matching now silently evaluates against the
  raw, untransformed value under FIPS-only mode instead of being short-
  circuited — including the unbounded-length collection-key amplification
  @fzipi identified in CRS 901320/901410. The per-evaluation (not per-rule-
  load) warning log was kept as-is.

## References

- PR: https://github.com/corazawaf/coraza/pull/1678
- Follow-up to: https://github.com/corazawaf/coraza/pull/1629
- Related ADRs: none
