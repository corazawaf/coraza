# ADR-0066: Bound non-file request-body processing before materialization

- **Status:** proposed
- **Date:** 2026-10-15
- **Version:** unreleased
- **PR:** TBD
- **Issue(s):** [#896](https://github.com/corazawaf/coraza/issues/896), [#1628](https://github.com/corazawaf/coraza/issues/1628)
- **Deciders:** Coraza maintainers
- **Category:** Parity

## Context and Problem

`SecRequestBodyNoFilesLimit` was parsed but not enforced. A forced URLENCODED
processor could copy a large binary body into `REQUEST_BODY` and `ARGS_POST`,
where rules and transformations could copy it again. A simple body-length check
would reject legitimate multipart uploads because file content is exempt from
this limit.

## Decision Drivers

- Stop non-multipart bodies before a processor copies the complete body.
- Count multipart part headers and ordinary fields while excluding boundary
  framing and file payload bytes, matching ModSecurity's counter.
- Preserve connector replay after a reader probes one byte beyond the limit.
- Leave the public body-processor plugin interface unchanged.

## Considered Options

- Check `BodyBuffer.Size()` before every processor. This cannot distinguish
  multipart file payload from ordinary bytes.
- Parse the whole multipart body and subtract file sizes afterward. This lets
  an oversized field pass through unbounded `io.ReadAll` first.
- Force unknown bodies to RAW or cap rule transformations. Neither implements
  the configured no-files accounting contract.
- Use an internal multipart accounting reader and bounded field reader,
  alongside transaction-level early enforcement for non-multipart bodies.

## Decision Outcome

Chosen: **incremental transaction and multipart accounting.** The transaction
enforces the non-multipart budget during writes and reader copies.
`ReadRequestBodyFrom` retains a one-byte probe in its buffer so the connector can
replay it; `ProcessPartial` supplies only the inspected prefix to the processor.
The built-in multipart processor counts raw part-header bytes and raw ordinary
field payload incrementally. A wire-state reader records header sizes before
the MIME parser normalizes whitespace or unfolds continuation lines. Boundary
framing, epilogue bytes and completed file payload are excluded. A file part
truncated by malformed input does not receive the exemption. Field reads stop
at the budget, and collection changes for the current part are published only
after that part passes accounting.

Earlier completed parts remain visible to `ProcessPartial` and to rules handling
a later parser error. Temporary file names are recorded immediately for cleanup.
The budget reader permits a fixed 8 KiB standard-library read-ahead margin while
the parser classifies a part. A replacement multipart plugin is treated as a
non-file-aware processor.

An unset directive retains Coraza's existing zero-value behavior, rather than
enabling ModSecurity's implicit default limit. The no-files threshold uses `>`;
Coraza's existing `SecRequestBodyLimit` threshold remains unchanged.

ModSecurity v3 increments its multipart no-files counter for raw part headers
and ordinary form-data payload, but not for boundary lines. Coraza follows that
classification. Malformed input remains bounded by the parser read-ahead guard
and the overall request-body limit.

ModSecurity also sets `REQBODY_ERROR` and `INBOUND_DATA_ERROR` when the
no-files limit is exceeded, independently of `SecRequestBodyLimitAction`.
Coraza follows that behavior. Consequently, `ProcessPartial` does not create
an interruption by itself, but a configured phase-two rule that blocks on
`REQBODY_ERROR` can still deny the transaction. This differs from Coraza's
existing overall `SecRequestBodyLimit` partial-path state and is intentional.

## Technical Discussion

No substantive technical discussion recorded.

## Participants

- Coraza maintainers

## Consequences

- **Positive:** Large non-file bodies do not enter full-body processors or
  phase-two transformations; multipart file payload remains exempt.
- **Negative / follow-up:** The existing body buffer still holds multipart input
  until processing. A configured `SecRequestBodyInMemoryLimit` remains important
  for large uploads. The built-in parser can read up to 8 KiB past the no-files
  budget while classifying a part, but it does not publish the over-limit field
  into `ARGS_POST`.

## References

- Issues: https://github.com/corazawaf/coraza/issues/896 and https://github.com/corazawaf/coraza/issues/1628
