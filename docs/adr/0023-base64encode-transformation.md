# ADR-0023: `base64Encode` transformation

- **Status:** accepted
- **Date:** 2024-12-29
- **Version:** v3.3.0
- **PR:** [#1257](https://github.com/corazawaf/coraza/pull/1257)
- **Issue(s):** [#1252](https://github.com/corazawaf/coraza/issues/1252)
- **Deciders:** @tty2, @fzipi
- **Category:** Parity (ModSecurity parity)

## Context and Problem

ModSecurity's `base64Encode` transformation was missing from Coraza. Rulesets
that use it to encode payloads for logging or indirect comparison did not
work as written.

## Decision Drivers

- ModSecurity compatibility.
- Minimal new code — `encoding/base64` stdlib suffices.
- Test parity with other one-liner transformations (use existing
  `testdata/base64encode.json`).

## Considered Options

- Hand-roll the encoding loop (no reason to).
- Wrap `base64.StdEncoding.EncodeToString`.

## Decision Outcome

Chosen: **stdlib wrapper**, following the pattern used by other one-liner
transformations in `internal/transformations`.

## Technical Discussion

Review was light — a couple of misunderstandings around where the tests
lived, and a copyright-line suggestion:

> "Ah, good catch! They are already there! Don't need to add them 😄"
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1257#issuecomment-2554359814))

> "```suggestion
> // Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
> ```"
> — @fzipi ([review](https://github.com/corazawaf/coraza/pull/1257#discussion_r1892349843))

No architectural discussion — the transformation is a one-liner around
`encoding/base64`.

## Participants

- @tty2 — author
- @fzipi — review

## Consequences

- **Positive:** Rulesets that `t:base64Encode` their payloads now work.
- **Negative:** None.

## References

- PR: https://github.com/corazawaf/coraza/pull/1257
- Issue: https://github.com/corazawaf/coraza/issues/1252
- ModSecurity reference: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)#base64Encode
