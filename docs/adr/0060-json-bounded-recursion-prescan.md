# ADR-0060: Iterative depth pre-scan before `gjson.Valid` in the JSON body processor

- **Status:** proposed
- **Date:** 2026-09-30 (expected; update before merge)
- **Version:** unreleased (post-v3.8.0)
- **PR:** [#1](https://github.com/corazawaf/coraza-ghsa-6gcq-wc29-5xf2/pull/1) (private advisory fork; update to the public PR once GHSA-6gcq-wc29-5xf2 is published)
- **Issue(s):** No linked issue (security advisory [GHSA-6gcq-wc29-5xf2](https://github.com/corazawaf/coraza/security/advisories/GHSA-6gcq-wc29-5xf2))
- **Deciders:** @fzipi
- **Category:** Parity (security fix)

## Context and Problem

`readJSON` (`internal/bodyprocessors/json.go`) runs a depth- and
argument-count-bounded flattening walk (`readItems`), then calls
`gjson.Valid(s)` on the raw body if that walk returned no error:

```go
truncated, err = readItems(json, key, maxRecursion, argumentLimit, byteBudget, &usedBytes, &argCount, res)
if err != nil {
    return res, truncated, err
}
if !gjson.Valid(s) {
    return res, truncated, errors.New("invalid JSON")
}
```

`readItems`'s own recursion guard (`maxRecursion`) only fires when `readItems`
actually recurses into a nested value. The byte-budget and argument-limit
guards added by GHSA-3ww9-vw83-9w5x and GHSA-6r3q-mjv7-xr8m run *before* that
recursion check and short-circuit the walk with `truncated=true, err=nil`
instead of recursing further. If `SecArgumentsLimit` is reached by earlier,
shallow values in the document, the walk stops before it ever reaches a
deeply nested tail later in the same document -- so `maxRecursion` is never
evaluated against that tail, `err` comes back `nil`, and `readJSON` falls
through to `gjson.Valid(s)` on the complete raw body, including the part the
walk never visited. `gjson.Valid` (gjson v1.18.0, `validany` ->
`validarray`/`validobject`) recurses once per nesting level with no depth
bound of its own. A body of roughly 13 MB -- comfortably under the
recommended `SecRequestBodyLimit` -- crafted with 1000 shallow scalars (to
exhaust the default `SecArgumentsLimit`) followed by millions of nested `[`
characters crashes the process with `fatal error: stack overflow`, which is
not a `panic` and cannot be caught by any `recover()`.

This is the same underlying hazard the recursion limit was already meant to
close (a plain, sufficiently deep body without an argument-limit trigger
already crashed the process before this bound existed), reopened by a
guard-ordering interaction between two later, independently-correct fixes.

## Decision Drivers

- The fix must not weaken the byte-budget/argument-limit guards or the
  best-effort walk they protect (`readItems` still runs unconditionally
  first; see `corazawaf/coraza#1615`).
- `gjson.Valid` must never run on input whose nesting could exceed
  `maxRecursion`, regardless of what triggered the walk to stop early.
- The check must stay fast on the common case (ordinary, shallow JSON) and
  must not itself introduce a second unbounded-recursion path.

## Considered Options

- Reorder `readItems`'s existing guards so the `maxRecursion` check runs
  before the byte-budget/argument-limit checks. Rejected: it does not close
  the gap. The `ForEach` callback still returns early, before ever calling
  `readItems` again on the nested value, so the nested value's depth is
  never checked by any ordering of guards inside the function that is never
  re-entered for it.
- Give `gjson.Valid` a bounded-depth variant, or replace it with a hand-rolled
  validator. Rejected as unnecessarily large: the only property needed here
  is "does this input nest deeper than `maxRecursion`", not full syntax
  validation, and `gjson.Valid` already does the latter correctly once depth
  is known to be safe.
- Run an iterative (non-recursive), depth-bounded pre-scan over the raw body
  before calling `gjson.Valid`, and skip `Valid` (returning the same
  recursion-limit error `readItems` would have produced) whenever the scan
  finds nesting past `maxRecursion`.

## Decision Outcome

Chosen: **the iterative pre-scan.** `jsonNestingExceedsLimit(s, limit)` is a
single pass over the bytes of `s` with a depth counter, tracking string
literals (with backslash-escape handling) so brackets inside string values
are not counted. It has no recursion, so it cannot itself stack-overflow
regardless of how deep or how long the input is, and it exits as soon as
depth exceeds `limit` rather than scanning to the end. `readJSON` calls it
right after `readItems` returns with `err == nil`, and before `gjson.Valid`:
if nesting exceeds `maxRecursion`, `readJSON` returns
`"max recursion reached while reading json object"` -- the same error
`readItems` would have returned had it reached that depth -- without ever
calling `gjson.Valid`. `ProcessRequest` and `ProcessResponse` both call
`readJSON`, so both paths get the fix from one change.

The pre-scan does not replace `gjson.Valid`: it only bounds recursion depth.
A body that passes the depth check but is otherwise malformed still goes on
to fail `gjson.Valid` exactly as before.

## Technical Discussion

No substantive technical discussion recorded; drafted and fixed in the same
session that produced the advisory, verified empirically (see Consequences)
before submission.

## Participants

- @fzipi -- author

## Consequences

- **Positive:** The crash is closed on both the request and response body
  paths. Verified with the original repro (a 13,002,001-byte body: 1000
  shallow scalars followed by 13,000,000 nested `[` characters, under the
  recommended `SecRequestBodyLimit` and default `SecArgumentsLimit`) --
  before the fix this crashes the process with `fatal error: stack
  overflow`; after the fix `readJSON` returns
  `truncated=true, err="max recursion reached while reading json object"` in
  under 50ms. A smaller, safe-to-run-in-CI regression case
  (`TestReadJSONArgumentLimitTruncationEnforcesRecursionLimit`) exercises the
  same guard-ordering mechanism at a depth (120) far below where gjson's
  recursion would actually crash a test process, together with a direct
  table test of `jsonNestingExceedsLimit` covering string-literal and
  escape-handling edge cases.
- **Negative / follow-up:** A body that is deeply nested only in a part the
  argument-limit walk never reached now fails with a recursion-limit error
  instead of the more specific (and, before this fix, entirely absent)
  signal. This matches the error a straightforwardly-too-deep body already
  produced, so it is a consistency fix, not a new failure mode for
  legitimate traffic within `SecRequestBodyJsonDepthLimit`/
  `SecResponseBodyJsonDepthLimit` (default 1024).

## References

- Advisory: https://github.com/corazawaf/coraza/security/advisories/GHSA-6gcq-wc29-5xf2
- Advisory PR (private fork): https://github.com/corazawaf/coraza-ghsa-6gcq-wc29-5xf2/pull/1
- Related ADRs: ADR-0058 (JSON flattened-key collision, same file), ADR-0059
  (`SecResponseBodyJsonDepthLimit`, the recursion-limit directive this fix
  bounds `gjson.Valid` against)
