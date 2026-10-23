# ADR-0063: Release the transformation cache after each phase and drop large body buffers on Close

- **Status:** proposed
- **Date:** 2026-10-23 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1-cl7)
- **PR:** not opened yet (update before merge)
- **Issue(s):** No linked issue (CloudLinux DEF-55803 follow-up, Cloudways memory spikes on large request bodies)
- **Deciders:** Ruslan Shmelev (CloudLinux)
- **Category:** Perf

## Context and Problem

wafd, the Imunify360 connector, runs phases 1 and 2 when the web server asks for a
verdict. It then keeps the transaction open until the web server sends the log phase,
up to 20 s later, which is as long as the backend takes to answer. Two kinds of
per-request memory stay reachable over that window, or longer.

**Transformation cache.** `RuleGroup.Eval` memoizes transformed argument values in
`tx.transformationCache` and clears the cache at the start of each phase, so a
cached value is never used outside the phase that made it. The cache was otherwise
only cleared in `Close()`. After phase 2 it held every transformed value of the
request until the log phase. A heap profile of one 3.8 MiB urlencoded body under the
Imunify360 full ruleset showed 105 MB held in `transformArg` while waiting for the
log phase (lowercase 36, urlDecode 30, urlDecodeUni 15, normalisePath 11, cmdLine 7,
base64 3.6 MB). An allowed 0.5 MiB body held 9–16 MiB, and 8 concurrent ones held
72–115 MiB.

With the same ruleset, phase 2 creates about 100 cache entries per argument: 198 for
a GET of `/`, 314 for a GET with 3 query arguments, 537 for a wp-login POST, 3002 for
a 30-field form and 24,861 for a 200-field form. A Go map does not shrink when it is
cleared, so `clear()` in `Close()` left a pooled transaction holding the buckets of
the largest request it had served.

**Request body buffer.** `BodyBuffer.Reset()` called `bytes.Buffer.Reset()`, which
keeps the buffer's capacity. `Close()` puts the transaction back in `WAF.txPool`, so
a transaction that had buffered a large body in memory kept that allocation. Under
steady traffic the same transaction comes back from the pool after every GC (the
pool's victim cache), so the buffer was never freed. wafd calls
`TruncateRequestBody` for allowed requests, but a request it blocks or abandons
never reaches that call. A wafd regression test held 16.0 MiB after one blocked or
abandoned 16 MiB body followed by 100 small requests and 5 GCs.

## Decision Drivers

- No change to what any rule sees or matches, in any phase.
- Bounded memory per pooled transaction, independent of the largest request it served.
- Keep reusing the map and the buffer for typical small requests, so their allocation
  rate does not go up.
- No change to the public API, so connectors need no change.

## Considered Options

- **Keep both as they were.** The memory above stays held.
- **A hook the connector calls after phase 2** to drop the cache. Every connector would
  have to call it, and it would only cover connectors that know about it. Releasing the
  cache is invisible to rules, so there is nothing for the connector to decide.
- **Release the cache at the end of every phase**, and replace the map when it grew
  past a threshold. Releasing the buffer in `Close()` the same way.
- **Never keep the map or the buffer** (allocate them for every transaction). Simplest,
  but it adds allocations to every request, small ones included.
- **Clear transformed ARGS values as well.** ARGS are variables that phase 3–5 rules
  match, so dropping them would change detection. Not done.

## Decision Outcome

Chosen: **release at the end of every phase, with a size threshold.**

- `RuleGroup.Eval` calls `tx.releaseTransformationCache()` after the phase's last rule.
  The delete loop at the start of `Eval` stays: it is the guard against a cache key
  that holds an argument pointer from an earlier phase, and it costs nothing on an
  empty map. `Eval` has no early return, so the release also runs when a rule
  interrupts, when `skipAfter` ends the phase, and when the phase is cut short by a
  done context (`ErrPhaseCanceled`, DEF-57619).
- `releaseTransformationCache` clears a map with at most
  `transformationCacheKeepLen` (1024) entries and replaces a larger one with a new
  map. 1024 is above every GET and small POST measured above (at most 537 entries), so
  those keep reusing the map, and below any form of about 10 fields or more, whose
  buckets are not kept. `Close()` calls the same helper.
- `BodyBuffer.Reset` keeps a buffer up to `bodyBufferKeepCap` (64 KiB) and replaces a
  larger one with a new `bytes.Buffer`. The temporary file path is unchanged.

This is semantically transparent. The cache is only read within the phase that filled
it, and the next phase cleared it before its first rule anyway. The body buffer is
empty after `Reset` either way, and only its capacity differs.

## Technical Discussion

No substantive technical discussion recorded; the change was drafted from the
Cloudways memory-spike analysis in the Imunify360 WebShield repository and has not
been reviewed yet.

## Participants

- Ruslan Shmelev (CloudLinux): author

## Consequences

- **Positive:** The transformed values of a request are released when its phase ends
  instead of when the log phase arrives. Large maps and large in-memory body buffers no
  longer outlive their request in `WAF.txPool`. Tests:
  - `TestTransformationCacheReleasedAfterPhase`: the cache is empty after each phase,
    including an interrupted phase and a phase cut short by a done context. The map is
    kept at 1024 entries and replaced at 1025.
  - `TestCloseReleasesLargeRequestBody`, `TestBodyBufferResetReleasesLargeBuffer`.
  - The `transformations_cache_release.yaml` engine profile checks detection. A
    transforming rule matches in every phase, an identical second rule in the same
    phase matches (a cache hit), and raw `t:none` rules in later phases do not see the
    transformed values of earlier ones. It runs for a GET, and for a POST with 1500
    arguments, so phase 2 crosses the threshold.
- **Negative / follow-up:** A request that crosses a threshold allocates a new map or
  buffer on the next transaction that reuses it. The parsed argument collections (ARGS
  and its derivatives) keep their map capacity in a pooled transaction, as before. Both
  thresholds are constants, not directives.

## References

- Related ADRs: ADR-0061 (`@pm` zero-copy haystack, same DEF-57621 profile)
- `internal/corazawaf/rulegroup.go` (`Eval`), `internal/corazawaf/transaction.go`
  (`releaseTransformationCache`, `Close`), `internal/corazawaf/body_buffer.go` (`Reset`)
