# ADR-0054: Ignore `SyntaxError` unexpected EOF in XML body processor

- **Status:** accepted
- **Date:** 2025-12-18
- **Version:** v3.4.0
- **PR:** [#1452](https://github.com/corazawaf/coraza/pull/1452)
- **Issue(s):** No linked issue
- **Deciders:** @hnakamur
- **Category:** Parity (ProcessPartial semantics)

## Context and Problem

`SecRequestBodyLimitAction ProcessPartial` can truncate an XML document
mid-parse. The XML body processor treated the resulting
`xml.SyntaxError: unexpected EOF` as fatal, discarding whatever had been
parsed. This is the XML twin of the multipart fix in
[ADR-0031](0031-multipart-unexpected-eof.md).

## Decision Drivers

- Honour `ProcessPartial`'s contract for XML bodies.
- Stay consistent with the multipart processor's handling.

## Considered Options

- Propagate the error (status quo).
- Treat unexpected-EOF as clean termination for ProcessPartial.

## Decision Outcome

Chosen: **treat `SyntaxError` unexpected-EOF as clean termination** so
whatever parsed before the cut is retained.

## Technical Discussion

No substantive technical discussion recorded on the PR or issue thread.
The rationale is stated in the PR body:

> "We need this behavior since we need to process an incomplete XML
> document when `SecRequestBodyLimitAction` is set to `ProcessPartial`."
> — @hnakamur, [PR body](https://github.com/corazawaf/coraza/pull/1452)

The PR merged with approvals and a clean codecov report; no reviewer
counter-proposals on the thread.

## Participants

- @hnakamur — author

## Consequences

- **Positive:** Parity with [ADR-0031](0031-multipart-unexpected-eof.md)
  for XML; `ProcessPartial` consistently yields partial data across body
  processors.
- **Negative:** Genuine XML corruption becomes indistinguishable from a
  legitimate truncation on the parser side.

## References

- PR: https://github.com/corazawaf/coraza/pull/1452
- Related ADRs: ADR-0031 (multipart unexpected EOF)
