# ADR-0058: Preserve both values on a JSON-flattened key collision

- **Status:** proposed
- **Date:** 2026-09-29 (expected; update before merge)
- **Version:** unreleased (targeted for v3.8.0)
- **PR:** [#1](https://github.com/corazawaf/coraza-ghsa-5gj4-9gm7-2fx2/pull/1) (private advisory fork; update to the public PR once GHSA-5gj4-9gm7-2fx2 is published)
- **Issue(s):** No linked issue (security advisory [GHSA-5gj4-9gm7-2fx2](https://github.com/corazawaf/coraza/security/advisories/GHSA-5gj4-9gm7-2fx2))
- **Deciders:** @fzipi
- **Category:** Parity (security fix)

## Context and Problem

> "Coraza's JSON body processor converts nested JSON properties into
> dot-separated `ARGS_POST` names without escaping dots contained in literal
> property names. Two distinct JSON properties can therefore collapse into
> the same Coraza variable [...] Coraza stores both properties as
> `ARGS_POST:json.account.role`; the later value `safe` replaces the
> SQL-injection value. Standard backend JSON parsers preserve the two
> distinct properties and expose the malicious nested value as
> `account.role`."
> — [GHSA-5gj4-9gm7-2fx2](https://github.com/corazawaf/coraza/security/advisories/GHSA-5gj4-9gm7-2fx2)

`readItems` (`internal/bodyprocessors/json.go`) flattens nested JSON into a
`map[string]string` keyed by a dot-joined path (`json.account.role`). A
literal property name containing a dot (`{"account.role": "x"}`) produces the
identical flattened key as the equivalent nested path
(`{"account": {"role": "x"}}`). Because the intermediate structure was a plain
Go map, whichever property gjson visited second silently overwrote the
other's value before `ProcessRequest` ever copied the result into
`ARGS_POST`.

## Decision Drivers

- Close the bypass: a value that reaches `ARGS_POST` under a colliding key
  must not silently vanish. The nested value in the advisory's PoC has to
  stay visible to CRS rule `949110` regardless of what other property shares
  its flattened key.
- `internal/bodyprocessors/json.go`'s flattened keys are matched by existing
  OWASP CRS rules as literal substrings — rule `944130` (suspicious Java
  class names in `ARGS_NAMES`, a Struts2/OGNL-injection detection) matches
  patterns like `com.opensymphony.xwork2` against the generated key text
  directly. Any fix that changes what a non-colliding, single-level dotted
  property name looks like once flattened breaks that detection.
- Do not require a second directive or a schema of "safe" property names;
  every JSON payload must be handled the same way regardless of shape.

## Considered Options

- Escape the `.` path separator and the escape character in literal property
  names before appending them to the flattened key (the advisory's primary
  suggested remediation: "Literal property-name separators must be escaped
  or encoded so that a nested path and a property containing dots cannot
  produce the same collection key"). Tried first; reverted (see Technical
  Discussion).
- Preserve multiple source values under a colliding key instead of
  overwriting (the advisory's secondary suggested remediation: "Coraza
  should also preserve multiple source values rather than silently
  overwriting a prior value when a generated-key collision occurs").
- Reject the request outright when a collision is detected (fail closed).
  Rejected: a false positive here would be indistinguishable from a
  legitimate payload that merely reuses a common nested field name alongside
  an unrelated dotted top-level property, and CRS has no existing precedent
  of rejecting JSON on this basis.

## Decision Outcome

Chosen: **preserve multiple values under a colliding key rather than
escaping the separator.** `readItems`'s intermediate map changed from
`map[string]string` to `map[string][]string`; a write to an existing key now
appends instead of overwriting. `ProcessRequest`/`ProcessResponse` copy every
value into `ARGS_POST`/`RESPONSE_ARGS` via `SetIndex(key, i, value)` for each
index, so a colliding key becomes a multi-valued collection entry -- exactly
how `MULTIPART_FILENAME` already handles two distinct filename readings for
the same part (see ADR-0057, GHSA-3wr7-993q-jrff). A rule matching that
variable, with or without a specific key filter, is evaluated against every
value, so the previously-hidden nested value is inspected again.

The flattened key text itself is unchanged for both colliding and
non-colliding payloads: escaping was tried first and reverted once it broke
an existing, unrelated CRS detection (see Technical Discussion), and this
option does not have that failure mode because it never changes what a
non-colliding key looks like.

## Technical Discussion

No substantive technical discussion recorded on the PR thread; the escaping
approach's incompatibility with CRS rule `944130` was found in-session by
running the existing `testing/coreruleset` regression suite against the
first implementation attempt, before any review took place.

**2026-09-29 rebase note:** rebasing onto `main` after GHSA-6r3q-mjv7-xr8m's
`SecArgumentsLimit`/`ArgumentLimit` fix landed surfaced a real interaction
between the two: that fix's guard compared `len(res)` (distinct flattened
keys) against `argumentLimit`, which this ADR's `map[string][]string` change
makes an undercount whenever keys collide -- a literal duplicate key (e.g.
`{"a":1,"a":1,...}`, which `gjson.ForEach` does surface for every occurrence
in the raw JSON text) can accumulate an unbounded number of values under one
map key while `len(res)` stays at 1, defeating `SecArgumentsLimit` entirely
for that shape. Fixed during the rebase by tracking total appended values in
a separate counter (`argCount`) instead of `len(res)`, checked at every guard
site `len(res)` was previously checked. Confirmed the gap was real (reverting
to `len(res)` made a new regression test, `TestReadJSONArgumentLimitCountsCollidedValues`,
fail with 10,000 values under one key against a limit of 1,000) before
confirming the fix closes it.

**2026-09-30 follow-up: case-folding collision.** This ADR's Decision Outcome
says `ProcessRequest`/`ProcessResponse` copy every value into
`ARGS_POST`/`RESPONSE_ARGS` "via `SetIndex(key, i, value)` for each index".
That closes the collision this ADR set out to fix (two flattened keys with
byte-identical text), but a second, distinct collision shares the same
failure mode: `ARGS_POST` and `RESPONSE_ARGS` are case-insensitive
(`RESPONSE_ARGS` always is, `ARGS_POST` unless built with
`coraza.rule.case_sensitive_args_keys`), so two flattened keys that differ
only by case -- `json.account.role` vs `json.account.Role` -- are distinct
entries in `readJSON`'s own case-sensitive intermediate map but fold to the
*same* collection bucket. Each `SetIndex(key, i, value)` call thinks it owns
index `i` of that bucket without knowing the other key also writes there, so
whichever key Go's randomized map iteration visits second overwrites index 0
of whichever visited first -- deterministically leaving exactly one
survivor every request, just an unpredictable one (confirmed empirically:
over 200 trials of `{"account":{"role":"1' OR '1'='1","Role":"safe"}}`, the
attack value survived only 22 times).

Fix: use `col.Add(key, value)` instead of `SetIndex(key, i, value)`. `Add`
always appends regardless of any index, so both a same-case collision (this
ADR's original case, one `data` key with an ordered slice of values) and a
case-folding collision (two different `data` keys landing in the same
bucket) end up with every value preserved, in whichever order the writes
happen to occur. Both cases are rows of
`TestJSONProcessRequestKeyCollisionDoesNotHideNestedValue`. The same-case row
(order-sensitive) still passes unchanged, since a single `data` key's own
value order is unaffected by switching from indexed writes to appends. The
case-folding row (order-independent) fails deterministically against the
pre-fix code and passes after it. It unions the values of both key spellings,
so it also holds under `coraza.rule.case_sensitive_args_keys`, where the keys
never collide.

## Participants

- @fzipi — author

## Consequences

- **Positive:** The advisory's reported bypass is closed: a value that
  reaches a colliding flattened key stays visible to rule inspection instead
  of being silently dropped. Existing CRS detections that match literal
  dotted property names as a substring of `ARGS_NAMES` (rule `944130`) are
  unaffected, since flattened key text never changes.
- **Negative / follow-up:** A rule that assumes exactly one value per
  `ARGS_POST` key (uncommon; CRS has no such rule today) could behave
  differently against a colliding payload than it did before this fix,
  since a key that previously held one value may now hold two. This is the
  same trade-off already accepted for `MULTIPART_FILENAME` in ADR-0057.
  Coraza does not currently expose a signal saying "this key collided";
  should that become useful, it is a small, separable addition, not a
  reason to revisit this decision.

## References

- Advisory: https://github.com/corazawaf/coraza/security/advisories/GHSA-5gj4-9gm7-2fx2
- Advisory PR (private fork): https://github.com/corazawaf/coraza-ghsa-5gj4-9gm7-2fx2/pull/1
- Case-folding collision follow-up PR (private fork): https://github.com/corazawaf/coraza-ghsa-5gj4-9gm7-2fx2/pull/2
- Related ADRs: ADR-0057 (`filename*`/`filename` dual-value precedent for the same "preserve both readings" pattern)
