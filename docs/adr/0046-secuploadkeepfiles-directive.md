# ADR-0046: `SecUploadKeepFiles` directive

- **Status:** accepted
- **Date:** 2026-03-19
- **Version:** v3.5.0
- **PR:** [#1557](https://github.com/corazawaf/coraza/pull/1557)
- **Issue(s):** [#1550](https://github.com/corazawaf/coraza/issues/1550)
- **Deciders:** @fzipi, @M4tteoP, @Copilot
- **Category:** Parity (ModSecurity parity)

## Context and Problem

ModSecurity exposes `SecUploadKeepFiles On|Off|RelevantOnly` to control
whether uploaded multipart files are retained or deleted after processing.
Coraza had a parser entry for the directive but the `RelevantOnly` branch
and the lifecycle plumbing were missing; deletion was unconditional.

## Decision Drivers

- ModSecurity parity.
- Respect the `RelevantOnly` semantics: keep files only when rules matched.
- TinyGo / Wasm builds have no filesystem access — gate cleanly under the
  existing `environment.HasAccessToFS` check.

## Considered Options

- Implement `On`/`Off` only.
- Implement all three states, mirroring ModSecurity semantics.

## Decision Outcome

Chosen: **implement all three states** — `On`, `Off` (default),
`RelevantOnly`. File operations are already guarded by
`environment.HasAccessToFS`, so the directive is safe on Wasm builds.

> "Also, ModSec requires `SecUploadKeepFiles` directive to work with
> `SecUploadDir`: 'This directive requires the storage directory to be
> defined (using SecUploadDir).' Should we distinguish the dir where we
> save persisted files from the tmp dir where we save the tmp ones? If so,
> we should take care of `SecUploadDir` and enforce the same requirement
> of ModSec"
> — @M4tteoP ([comment](https://github.com/corazawaf/coraza/pull/1557#issuecomment-4067770063))

> "Makes sense. Added in 25b636d0"
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1557#issuecomment-4071743033))

## Technical Discussion

**Copilot flagged a consistency gap** on directive error handling:

> "`directiveSecUploadKeepFiles` is the only nearby directive that doesn't
> check for empty `options.Opts` and return `errEmptyOptions`. With the
> current code, an empty value yields an 'invalid upload keep files status'
> error instead of the consistent 'expected options' error used by most
> directives in this file."
> — @Copilot ([review](https://github.com/corazawaf/coraza/pull/1557#discussion_r2939770730))

The author applied the guard.

**A lint break from a Copilot suggestion** caused a chained follow-up:

> "@copilot Fix the lint pipeline, as your latest suggestions broke it."
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1557#issuecomment-4076746486))

Follow-up landed as PR #1560.

## Participants

- @fzipi — author
- @M4tteoP — review (drove `SecUploadDir` alignment)
- @Copilot — reviewer bot (directive error-handling consistency)
- @app/copilot-swe-agent — follow-up lint fix (#1560)

## Consequences

- **Positive:** ModSecurity parity; operators get `RelevantOnly` to keep
  only suspicious uploads for post-hoc forensics.
- **Negative / follow-up:** Full ModSecurity spec requires pairing with
  `SecUploadDir`; check was added. Wasm builds silently ignore the
  directive (no FS access).

## References

- PR: https://github.com/corazawaf/coraza/pull/1557
- Issue: https://github.com/corazawaf/coraza/issues/1550
- Follow-up lint fix: https://github.com/corazawaf/coraza/pull/1560
