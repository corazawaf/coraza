# ADR-0063: Add ARGS_RAW, ARGS_GET_RAW, ARGS_POST_RAW, and ARGS_NAMES_RAW collections

- **Status:** accepted
- **Date:** 2026-10-20
- **Version:** unreleased
- **PR:** [#1493](https://github.com/corazawaf/coraza/pull/1493)
- **Issue(s):** [#1491](https://github.com/corazawaf/coraza/issues/1491)
- **Deciders:** @fzipi, @jptosso
- **Category:** Parity (ModSecurity parity)

## Context and Problem

Coraza automatically URL-decodes argument values before storing them in `ARGS`, `ARGS_GET`, `ARGS_POST`, and `ARGS_NAMES`. These "cooked" collections make applying transformations like `t:urlDecodeUni` cause double URL decoding, introducing:

1. **False Positives:** E.g., `password=Secret%2500` decodes once to `Secret%00`, and then a rule with `t:urlDecodeUni` decodes it a second time to `Secret\x00` (null byte), erroneously triggering null-byte detection rules.
2. **Detection Gaps / Obfuscation Evasions:** Rules looking for encoded attack payloads (e.g., `%3Cscript%3E` or `%25xx`) cannot inspect the raw wire-format values before automatic percent decoding.
3. **Cross-Engine Portability Inconsistencies:** Parity with ModSecurity v2/v3 (owasp-modsecurity/ModSecurity#2118, #3501) and OWASP CRS requirements.

## Decision Drivers

- Provide wire-format argument values and names prior to any percent decoding.
- Full backward compatibility: existing `ARGS`, `ARGS_GET`, `ARGS_POST`, and `ARGS_NAMES` collection semantics and performance remain unchanged.
- Single-pass query parsing with zero redundant allocations on unencoded keys/values.
- Respect configured `ArgumentLimit` and case-sensitivity build tags (`coraza.rule.case_sensitive_args_keys`).

## Considered Options

- **Option 1: Double-pass query parsing.** Call `ParseQuery` (decoded) and `ParseQueryRaw` separately. Rejected due to redundant parsing and allocation overhead.
- **Option 2: Single-pass query parsing with pre-sized maps and fast-path unescaping.** Extend `urlutil.ParseQueryOrdered` to store both cooked and raw values in `KeyValue` (`RawKey`, `RawValue`) in parse order, and provide `ParseQueryBoth` for body processors. If input has no `%` or `+`, bypass allocation.
- **Option 3: Store only raw values and lazy-decode for standard ARGS.** While appealing, standard SecLang rules and third-party connectors expect cooked values in `ARGS` / `AddGetRequestArgument`, and non-URL-encoded formats (multipart, JSON) already have raw == cooked.

## Decision Outcome

Chosen: **Option 2**.

- Expose `ARGS_RAW`, `ARGS_GET_RAW`, `ARGS_POST_RAW`, `ARGS_NAMES_RAW`, `ARGS_GET_NAMES_RAW`, and `ARGS_POST_NAMES_RAW`.
- Capture raw query arguments during `urlutil.ParseQueryOrdered` without extra passes.
- Populate `argsPostRaw` in urlencoded, multipart, and JSON body processors.
- Support case-sensitivity in `caseSensitiveVariable` in `internal/corazawaf/rule.go`.

## Technical Discussion

Key discussion from PR #1493 on argument storage and performance:

> "Let's replace this with lazy loading, the variable is stored by default as RAW and we lazy load it in standard ARGS variables. Otherwise there is a major performance regression"
> — @jptosso ([comment](https://github.com/corazawaf/coraza/pull/1493#issuecomment-4047250570))

> "I like this. Honestly, we can even just store everything as RAW, and then if you ask for ARGS it is just applying the urlDecode transformation once."
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1493#issuecomment-4103817984))

## Participants

- @fzipi — author, decider
- @jptosso — review, performance feedback

## Consequences

- **Positive:** Rule authors can inspect raw argument values and names without double URL decoding false positives.
- **Positive:** OWASP CRS rules can inspect wire-format parameters portably across Coraza and ModSecurity.
- **Positive:** Zero regressions on existing rules or connectors.

## References

- PR: https://github.com/corazawaf/coraza/pull/1493
- Issue: https://github.com/corazawaf/coraza/issues/1491
- ModSecurity parallel issue: https://github.com/owasp-modsecurity/ModSecurity/issues/2118
- Related ADRs: ADR-0001, ADR-0002, ADR-0016
