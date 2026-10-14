# ADR-0062: `ctl:forceRequestBodyVariable` falls back to the RAW processor

- **Status:** proposed
- **Date:** 2026-10-14 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** [#28](https://github.com/cloudlinux/coraza/pull/28) (cloudlinux/coraza fork)
- **Issue(s):** [#938](https://github.com/corazawaf/coraza/issues/938) (origin of the RAW processor and of the open question); fork tracking ticket DEF-55047
- **Deciders:** CloudLinux WebShield team
- **Category:** Parity (ModSecurity v2 `forceRequestBodyVariable`)

## Context and Problem

`ctl:forceRequestBodyVariable=On` exists to keep a body available as
`REQUEST_BODY` when no processor would otherwise run. ModSecurity v2 does exactly
that and parses nothing. Coraza additionally selected the URLENCODED processor
whenever no processor had been chosen, so any forced body of another type, binary
uploads included, was split on `&` and `=` into `ARGS_POST`.

On a binary body this produces garbage argument names and values, which rules
that inspect `ARGS` then match, and evaluating them costs CPU. In the DEF-55047
measurement, a whole transaction with the production ruleset (v8.58) took about
1.2 s for a 200 KiB body against about 6 ms with the body kept raw; the figure
covers rule evaluation as well as decoding. The arguments stay in memory for the
life of the transaction and can reach `SecArgumentsLimit`, which sets
`REQBODY_ERROR`.

The fallback was left open upstream. The code carried a `TODO(4.x)` asking
whether the RAW processor (ADR-0010) fits better as the forced default, quoting
the cost of parsing a body of unknown type as urlencoded.

## Decision Drivers

- Match ModSecurity v2: a forced body is exposed as `REQUEST_BODY` and not parsed.
- Stop binary bodies from filling `ARGS_POST` and triggering argument rules.
- Avoid the decoding cost and the retained arguments.
- A form Content-Type must keep its own processor.

## Considered Options

- Keep URLENCODED as the fallback.
- Fall back to RAW when no processor has been chosen.
- Leave the engine alone and set `ctl:requestBodyProcessor=RAW` in every ruleset
  that forces a body.

## Decision Outcome

Chosen: **fall back to RAW**, because it removes the false positives and the
cost at the source, for every ruleset, and matches ModSecurity v2.

A request whose Content-Type is `application/x-www-form-urlencoded` or
`multipart/form-data` already has its processor selected when the headers are
processed, so it is unaffected. A processor chosen with `ctl:requestBodyProcessor`
still wins. Only forced bodies with no processor change: those with a non-form
Content-Type or no Content-Type.

The third option fixes one ruleset and leaves the engine default for everyone
else.

## Technical Discussion

No substantive technical discussion recorded in this repository. #938, which
proposed the RAW processor, raised the cost of parsing a body of unknown type as
urlencoded only in passing, and the default was never decided there; the
`TODO(4.x)` in `internal/corazawaf/transaction.go` was the only upstream trace of
the question.

## Participants

- CloudLinux WebShield team: author

## Consequences

- **Positive:** a forced non-form body no longer populates `ARGS_POST`, so
  argument rules stop matching binary content, and the decoding cost and retained
  arguments are gone. Rules on `REQUEST_BODY` and `REQUEST_BODY_LENGTH` see the
  same values as before.
- **Negative / follow-up:** a ruleset that relied on the old fallback to read
  `ARGS_POST` from a forced body with no form Content-Type loses that variable
  and must select URLENCODED with `ctl:requestBodyProcessor=URLENCODED`. This
  deviates from upstream Coraza, so later upstream syncs touching this block need
  a manual merge.
- **Negative / follow-up:** a forced body with a non-form or absent Content-Type is
  no longer visible to `ARGS` rules. A backend that parses such a body as a form
  regardless of Content-Type sees arguments that only `REQUEST_BODY` rules can
  match. ModSecurity v2 is in the same position. Rulesets protecting such a backend
  must select URLENCODED with `ctl:requestBodyProcessor=URLENCODED` or scan
  `REQUEST_BODY`.

## References

- Code: `internal/corazawaf/transaction.go` (`ProcessRequestBody`)
- Profile: `testing/engine/ctl.go`
- Motivating discussion: https://github.com/corazawaf/coraza/issues/938
- Related ADRs: ADR-0010 (raw body processor)
