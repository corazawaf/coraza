# ADR-0062: Inline `@pm` Snort hex content syntax

- **Status:** accepted
- **Date:** 2026-10-20
- **Version:** unreleased (post-v3.7.0)
- **PR:** [#1787](https://github.com/corazawaf/coraza/pull/1787)
- **Issue(s):** [#1600](https://github.com/corazawaf/coraza/issues/1600)
- **Deciders:** @fzipi
- **Category:** Parity

## Context and Problem

ModSecurity and Coraza's `@pm` operator documentation historically mentioned support
for Snort-style hex content syntax (`@pm A|42|C|44|F`), but Coraza's inline `@pm`
implementation merely did `strings.ToLower(data)` and split by space `" "`, leaving an
unimplemented TODO comment:
```go
// TODO this operator is supposed to support snort data syntax: "@pm A|42|C|44|F"
```
Rules attempting to use Snort syntax (such as matching binary bytes or using hex blocks
like `|41 42|` or `|00|`) treated the pipe characters and hex digits as literal ASCII text.

## Decision Drivers

- Full parity with ModSecurity v3 for Snort content syntax on inline `@pm`.
- Scope strictly bounded to inline `@pm`: do not alter `@pmFromFile` or `@pmFromDataset`
  where pipes may appear as literal delimiters in existing rule data files.
- Zero-alloc, case-insensitive hex decoding inside `|...|` blocks while preserving raw byte values.
- Retain lowercase normalization on literal segments outside hex blocks so case insensitivity
  behaves as expected.
- Fail fast on malformed syntax (unclosed pipes, odd hex digits, non-hex characters, empty blocks).
- Compatibility with `minLen` prefilter (ADR-0053) and automaton memoization.

## Considered Options

1. **Decode entire string then split:** Decode hex first, then split on space.
   - *Drawback:* A decoded space byte `|20|` would erroneously split phrases.
2. **Tokenize and decode inline `@pm` (Chosen):**
   - Characters outside `|...|` are separated by ASCII spaces (runs collapsed), and literal
     segments are lowercased.
   - Inside `|...|`, spaces are ignored, pairs of hex digits are decoded into raw bytes,
     and literal pipes are escaped as `|7C|`.

## Decision Outcome

Chosen: **Option 2**.

The inline `@pm` argument is parsed character-by-character:
- Spaces outside `|...|` delineate phrases. Runs of spaces are collapsed, dropping empty phrases.
- Literal segments outside `|...|` are converted to lowercase.
- Hex blocks `|...|` ignore interior spaces and decode case-insensitive hex pairs `[0-9a-fA-F]`
  directly to raw bytes without lowercasing.
- Malformed syntax (unclosed `|`, odd digit count, non-hex/non-space character, empty block `||`,
  empty pattern) fails rule initialization immediately with an informative error.
- Decoded phrases are passed to automaton memoization and `minPatternLen` so `minLen` reflects
  the true decoded byte length.

## Technical Discussion

No substantive technical discussion recorded on the issue thread.

## Participants

- @fzipi — issue reporter

## Consequences

- **Positive:** Rules using Snort-style hex syntax (such as binary payload signatures) work
  consistently in Coraza inline `@pm`.
- **Positive:** Malformed patterns are detected at parse time instead of silently compiling
  with unexpected matching behavior.
- **Negative:** Inline `@pm` arguments containing unescaped `|` characters will now return
  a syntax error unless escaped as `|7C|`.

## References

- Issue: https://github.com/corazawaf/coraza/issues/1600
- Related ADRs: ADR-0053 (`@pm` operator `minLen` prefilter)
