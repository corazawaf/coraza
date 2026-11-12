# ADR-0065: Inline `@pm` Snort hex content syntax

- **Status:** proposed
- **Date:** 2026-10-20
- **Version:** unreleased (post-v3.8.1)
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

- Parity with ModSecurity for Snort content syntax on inline `@pm`.
- Scope strictly bounded to inline `@pm`: do not alter `@pmFromFile` or `@pmFromDataset`
  where pipes may appear as literal delimiters in existing rule data files.
- Zero-alloc, case-insensitive hex decoding inside `|...|` blocks while preserving raw byte values.
- Retain lowercase normalization on literal segments outside hex blocks so case insensitivity
  behaves as expected, while matching remains case-insensitive across all decoded phrases.
- Fail closed at compile time on malformed syntax (unclosed pipes, odd hex digits, non-hex characters, empty blocks).
- Compatibility with `minLen` prefilter (ADR-0053) and automaton memoization.

## Considered Options

1. **Decode entire string then split (ModSecurity v2/v3):** Decode hex across the whole string first, then split on space.
   - *Drawback:* A decoded space byte `|20|` erroneously splits phrases, altering intended pattern boundaries.
2. **Fall back to literal string on malformed pattern (ModSecurity v3):** If a hex block contains invalid characters or is unclosed, treat the entire string literally.
   - *Drawback:* Silent fallback hides syntax mistakes (such as unclosed pipes or typos in hex strings) and leads to unexpected rule execution where the pattern matches literal pipe characters instead of the intended byte sequence.
3. **Tokenize and decode inline `@pm` with fail-closed validation (Chosen):**
   - Characters outside `|...|` are separated by ASCII spaces (runs collapsed), and literal segments are lowercased.
   - Inside `|...|`, spaces are ignored, pairs of hex digits are decoded into raw bytes without lowercasing, and literal pipes are escaped as `|7C|`.
   - Matching remains case-insensitive across both literal segments and decoded hex bytes (e.g. `|41|` matches `a`).
   - Fast-fails at rule initialization time on syntax errors.

## Decision Outcome

Chosen: **Option 3**.

The inline `@pm` argument is parsed character-by-character:
- Spaces outside `|...|` delineate phrases. Runs of spaces are collapsed, dropping empty phrases.
- Literal segments outside `|...|` are converted to lowercase.
- Hex blocks `|...|` ignore interior spaces and decode case-insensitive hex pairs `[0-9a-fA-F]`
  directly to raw bytes without lowercasing.
- Matching remains case-insensitive across all phrases, including hex bytes (for example, `|41|` matches `a`).
- Malformed syntax (unclosed `|`, odd digit count, non-hex/non-space character, empty block `||`,
  empty pattern) fails rule initialization immediately with an informative error.
- Decoded phrases are passed to automaton memoization and `minPatternLen` so `minLen` reflects
  the true decoded byte length.

## Intentional Deviations from ModSecurity

1. **Compile-time fail closed vs. literal fallback:** ModSecurity v3 never returns an error during hex parsing and instead silently falls back to treating the input as a literal string on any malformed hex block (including unclosed blocks, odd digit counts, or unexpected characters). Coraza fails closed at compile time, rejecting malformed rules immediately to prevent security misconfigurations.
2. **Phrase splitting and decoded spaces:** ModSecurity v2 and v3 decode hex across the full argument first and then split into phrases by whitespace. Consequently, a hex-encoded space (`|20|`) is split into separate phrases in ModSecurity. Coraza tokenizes phrases first while parsing hex blocks, so `a|20|b` remains a single phrase containing an embedded space byte.
3. **SecLang escape sequences:** SecLang string escape sequences (`\:`, `\;`, `\\`, `\"`) are supported outside hex blocks by the SecLang directive parser.
4. **Scope bounded to inline `@pm`:** In ModSecurity v2, Snort hex syntax is also processed in `@pmFromFile` and `@strmatch`. In Coraza, the scope is strictly bounded to inline `@pm` to avoid breaking file-based pattern dictionaries where `|` may be used as literal data or delimiters.
5. **Case-insensitive matching with preserved byte values:** Decoded hex bytes are stored without lowercasing so raw non-ASCII bytes (e.g. `|ff fe|` or `|00|`) remain intact, while `@pm` matching itself remains case-insensitive across the input (e.g., `|41|` matching `0x41` or `0x61` / `'a'`).

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
