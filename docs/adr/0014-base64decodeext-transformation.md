# ADR-0014: `base64DecodeExt` transformation

- **Status:** accepted
- **Date:** 2024-04-24
- **Version:** v3.2.0
- **PR:** [#1046](https://github.com/corazawaf/coraza/pull/1046)
- **Issue(s):** No linked issue
- **Deciders:** @soujanyanmbri, @jptosso, @jcchavezs, @fzipi
- **Category:** Parity (ModSecurity parity)

## Context and Problem

PHP-hosted applications accept base64-encoded payloads containing characters
(notably `.` and space) outside the standard alphabet. Attackers exploit this
leniency to sneak past WAF decoders. ModSecurity ships a `base64DecodeExt`
transformation specifically for this case; Coraza did not.

## Decision Drivers

- ModSecurity compatibility — rulesets written for ModSecurity expect this
  transformation to exist.
- Specifically defeat base64 evasion variants targeting PHP applications.

## Considered Options

- Extend the existing `base64Decode` with a boolean flag (more booleans on
  the hot path).
- Keep `base64Decode` simple and add `base64DecodeExt` as a separate entry.
- Put one implementation behind a build tag, switch the default after
  benchmarking.

## Decision Outcome

Chosen: **separate transformation**, matching ModSecurity's surface. The
build-tag-after-benchmark suggestion was declined because this is a parity
feature, not a performance question.

> "I would propose a couple of things here: 1. Not pass more booleans but
> instead add a build tag for this and if the benchmarks are in favour of
> this new implementation use that by default. 2. Show the benchmark results
> in the description of the PR assesing why is this better than the existing
> one."
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/1046#issuecomment-2071606901))

> "We don't need another reason, it's for compatibility. We just forgot to
> implement this in the past."
> — @jptosso ([comment](https://github.com/corazawaf/coraza/pull/1046#issuecomment-2071629112))

## Technical Discussion

@soujanyanmbri summarised the motivation clearly:

> "This is to maintain consistency with modsec with base64DecodeExt operator.
> base64DecodeExt is mostly to take care of base64decode evasions while the
> payloads are used in PHP machines (Since, PHP accepts . or ' ' in
> base64encoded payloads while decoding)"
> — @soujanyanmbri ([comment](https://github.com/corazawaf/coraza/pull/1046#issuecomment-2069986120))

Test coverage reused the existing JSON-data harness
(`internal/transformations/testdata/base64DecodeExt.json`).

## Participants

- @soujanyanmbri — author
- @jptosso — review (parity argument)
- @jcchavezs — review (proposed build-tag alternative, then accepted)
- @fzipi — review

## Consequences

- **Positive:** ModSecurity rulesets that rely on `base64DecodeExt` work
  unchanged against Coraza.
- **Negative / follow-up:** Two decoders now coexist; authors must know
  which variant to pick.

## References

- PR: https://github.com/corazawaf/coraza/pull/1046
- ModSecurity reference:
  https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)#base64decodeext
