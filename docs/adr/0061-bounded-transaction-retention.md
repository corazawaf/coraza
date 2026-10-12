# ADR-0061: Bound what a pooled transaction retains and stream body reads

- **Status:** proposed
- **Date:** 2026-10-19 (expected merge date)
- **Version:** unreleased (post-v3.8.1)
- **PR:** [#NNNN](https://github.com/corazawaf/coraza/pull/NNNN)
- **Issue(s):** [#1749](https://github.com/corazawaf/coraza/issues/1749)
- **Deciders:** @fzipi
- **Category:** Perf

## Context and Problem

`Transaction` objects are pooled (`sync.Pool`) and reset in `Close()`. Three of
the structures they own keep their high-water mark across that reset:

- `BodyBuffer` resets its `bytes.Buffer`, which keeps its capacity. With
  `coraza.conf-recommended` (128 KiB request body in memory, 512 KiB response
  body) one large exchange leaves up to 640 KiB pinned in that pooled
  transaction.
- `collections.Map.Reset` deletes every key; Go maps never shrink, so a request
  that hit `ArgumentLimit` (1000) leaves bucket arrays for 1000 entries in
  `ARGS_POST`, `ARGS_POST_NAMES`, … of that transaction.
- The per-transaction `transformationCache` is cleared the same way at the start
  of every phase. CRS phase 2 fills ~600 entries for a request with a handful of
  arguments; the cache scales with the argument count.

`sync.Pool` is drained over two GC cycles, so none of this is unbounded, but
under steady load every pooled transaction sits at its peak.

Separately, the body is read back through `bodyBufferReader`, which only
implements `Read`. `io.Copy(strings.Builder, reader)` in the urlencoded, JSON
and raw body processors (and in the HTTP interceptor's response passthrough)
therefore fell back to `copyBuffer`, which allocates a 32 KiB scratch buffer per
call: 12.6 MB of the CRS benchmark profile, to copy 28-byte bodies.

Tracking issue #1749, items 5–7.

## Decision Drivers

- Memory held by idle pooled transactions should not depend on the largest
  request they ever saw.
- The hot path must not pay for the fix: normal traffic (tens of headers, a
  handful of arguments, bodies well under 64 KiB) must keep reusing the same
  allocations.
- No new configuration: one defensible constant per structure, documented next
  to it.
- TinyGo: `clear` and `io.SectionReader` are available; no new primitives.

## Considered Options

- **A. Drop and rebuild above a threshold on reset** (`maxRetainedBufferCap` =
  64 KiB, `maxRetainedKeys` = 256, `maxRetainedTransformationCache` = 4096):
  below the threshold behaviour is unchanged (`clear` / `Buffer.Reset`), above it
  the structure is replaced by an empty one.
- **B. Always reallocate on reset**: simplest, but every request would pay the
  initial growth of every collection and buffer again.
- **C. Size the retained structures from configuration** (e.g. keep up to
  `SecRequestBodyInMemoryLimit`): that is the current behaviour and the problem.
- **D. Make `BodyBuffer`/`Map` not pooled at all**: moves the allocation to every
  transaction, same cost as B with more churn.

For the read path there was only ever one option: implement `io.WriterTo` on
`bodyBufferReader` so `io.Copy` writes the in-memory remainder in a single
`Write` (file-backed buffers go through an `io.SectionReader`). The unused and
file-incorrect `BodyBuffer.WriteTo` (it read from the file's current offset,
which sits at the end after writing) is removed.

## Decision Outcome

Chosen: **A**. The thresholds are chosen so that normal traffic never crosses
them: 64 KiB is well above typical form or JSON bodies and the body processors
already allocate a body-sized string per request, so re-growing a dropped buffer
costs at most that much again; 256 keys is several times a typical header or
argument count; 4096 cache entries is ~7× what CRS phase 2 needs for a request
with four arguments.

The audit-log request body is read with `io.Copy` into a `strings.Builder`
instead of `io.ReadAll` + `string(...)`, removing one body-sized copy.

## Technical Discussion

No substantive technical discussion recorded on the PR thread at the time of
writing; the thresholds come from the measurements in #1749.

## Participants

- @fzipi — author

## Consequences

- **Positive:** idle pooled transactions no longer pin the memory of their
  largest request; body processors stop allocating 32 KiB per body; one fewer
  body copy in audit logging.
- **Negative / follow-up:** a workload whose *every* request exceeds a threshold
  (bodies > 64 KiB, > 256 argument keys) reallocates that structure per request.
  The constants are internal; if such a workload appears they can be revisited or
  made configurable in a follow-up ADR.

## References

- PR: https://github.com/corazawaf/coraza/pull/NNNN
- Issue: https://github.com/corazawaf/coraza/issues/1749
- Related ADRs: ADR-0019 (zero-copy helpers), ADR-0042 / ADR-0043 (memoize ownership)
