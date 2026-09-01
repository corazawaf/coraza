# ADR-0048: NDJSON (JSON Stream) body processor

- **Status:** accepted
- **Date:** 2026-03-21
- **Version:** v3.5.0
- **PR:** [#1563](https://github.com/corazawaf/coraza/pull/1563)
- **Issue(s):** No linked issue
- **Deciders:** @app/copilot-swe-agent (author), @fzipi
- **Category:** Feature

## Context and Problem

NDJSON / JSON Lines / RFC 7464 (JSON Sequence) streams carry one JSON
record per line. Applied to WAF processing, each record should be
evaluated independently — otherwise a malicious record hiding mid-stream
requires buffering the whole body just to catch it.

## Decision Drivers

- Stream-native inspection: evaluate rules per record, don't buffer.
- Preserve cross-record state (TX variables, anomaly scores) across
  evaluations.
- Autodetect RFC 7464 by peeking for RS (`0x1E`) byte.
- Enforce the same JSON depth limit as the regular JSON processor
  ([ADR-0030](0030-secrequestbodyjsondepthlimit.md)).

## Considered Options

- Buffer the whole stream, then run rules once.
- Line-by-line processing, evaluate per record, clear and repopulate
  `ARGS_POST` between records.

## Decision Outcome

Chosen: **line-by-line processing with per-record rule evaluation.**

- `bufio.Scanner` with configurable max token size.
- `json.<N>.<field>` indexing pattern (same conventions as the JSON body
  processor).
- Registered under aliases `JSONSTREAM`, `NDJSON`, `JSONLINES`.
- `processRequestBodyStreaming` / `processResponseBodyStreaming` on
  `Transaction` make `Eval(Phase2)` safe to call multiple times:
  `AllowTypePhase`, `Skip`, and transformation cache all reset between
  calls.
- `experimental.StreamingTransaction` exposes
  `ProcessRequestBodyFromStream(input, output)` /
  `ProcessResponseBodyFromStream(input, output)` for integrators building
  streaming middleware.

## Technical Discussion

No substantive technical discussion recorded on the PR thread. The Copilot
SWE agent delivered the change end-to-end; the design and e2e tests are
captured in the PR body. Reviewers approved on the strength of the
streaming-relay API design and per-record test coverage:

- clean stream → 200
- stream with malicious record → 403
- `application/jsonlines` content type
- SQLi inside a record field → 403
- blank lines ignored
- non-NDJSON content type unaffected

## Participants

- @app/copilot-swe-agent — author
- @fzipi — review

## Consequences

- **Positive:** Streaming APIs emitting NDJSON can be protected without
  per-connection buffering; cross-record anomaly-score accumulation works.
- **Negative / follow-up:** `processRequestBodyStreaming` mutates
  `ARGS_POST` between records — embedders relying on post-phase argument
  state will see only the last record's values.

## References

- PR: https://github.com/corazawaf/coraza/pull/1563
- Related ADRs: ADR-0010 (raw body processor), ADR-0030
  (`SecRequestBodyJsonDepthLimit`)
