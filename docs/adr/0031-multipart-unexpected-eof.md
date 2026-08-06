# ADR-0031: Ignore unexpected EOF in MIME multipart body processor

- **Status:** accepted
- **Date:** 2026-03-06
- **Version:** v3.4.0
- **PR:** [#1453](https://github.com/corazawaf/coraza/pull/1453)
- **Issue(s):** No linked issue
- **Deciders:** @hnakamur, @fzipi, @jcchavezs, @Copilot (PR reviewer bot)
- **Category:** Parity (ProcessPartial semantics)

## Context and Problem

When `SecRequestBodyLimitAction` is `ProcessPartial`, Coraza stops reading
the body at the limit, which yields an `io.ErrUnexpectedEOF` to the
multipart parser. The parser treated that as fatal, losing the parts it had
already decoded and leaving the transaction with empty `ARGS_POST` /
`FILES` collections.

## Decision Drivers

- Honour `ProcessPartial`'s contract: keep what was parsed before the cut.
- Keep the collections populated with whatever made it in (files, form
  fields) so rules can fire on partial data.
- No behaviour change when the body is complete.

## Considered Options

- Propagate the EOF and drop partial data (status quo).
- Treat `io.ErrUnexpectedEOF` as a clean termination and preserve partials.

## Decision Outcome

Chosen: **treat unexpected EOF as clean termination** in the multipart
processor, preserving both files and form-field parts collected so far.
`filesCombinedSizeCol` is updated before the early return so size-based
rules see truthful values.

## Technical Discussion

Most substantive review came from the Copilot PR reviewer. Three issues
were flagged and fixed:

**1. Form-field data needs to be asserted in tests.**
> "The test cases don't verify that form field data … is correctly processed
> before the incomplete file part. Consider adding assertions to check that
> v.ArgsPost() contains the expected 'text' field value to ensure that
> partial processing works correctly for both files and form fields."
> — @Copilot ([review](https://github.com/corazawaf/coraza/pull/1453#discussion_r2651017385))

**2. `filesCombinedSizeCol` was being skipped on the break path.**
> "After encountering an unexpected EOF and breaking out of the loop, the
> function should still update `filesCombinedSizeCol` before returning.
> Currently, the break at line 96 skips the `filesCombinedSizeCol` update at
> line 108, which could result in an incorrect combined file size when
> partial processing occurs."
> — @Copilot ([review](https://github.com/corazawaf/coraza/pull/1453#discussion_r2651845715))

> "Fixed."
> — @fzipi ([review](https://github.com/corazawaf/coraza/pull/1453#discussion_r2895132899))

**3. Need a form-field-truncation case.**
> "All test cases focus on incomplete file parts, but there's no test case
> for an incomplete regular form field."
> — @Copilot ([review](https://github.com/corazawaf/coraza/pull/1453#discussion_r2651017397))

> "Added."
> — @fzipi ([review](https://github.com/corazawaf/coraza/pull/1453#discussion_r2895122169))

@jcchavezs wired up a Copilot-driven follow-up PR for the changes:

> "@copilot open a new pull request to apply changes based on the comments
> in …"
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/1453#issuecomment-4008409641))

## Participants

- @hnakamur — author
- @fzipi — review (applied fixes)
- @jcchavezs — review (Copilot orchestration)
- @Copilot (PR reviewer bot) — review

## Consequences

- **Positive:** `ProcessPartial` actually yields partial data for multipart
  requests; truncation does not wipe the transaction.
- **Negative / follow-up:** The `io.ErrUnexpectedEOF` case is now silently
  benign in the multipart path; genuine parse corruption may be harder to
  distinguish from legitimate truncation. The existing
  `MULTIPART_STRICT_ERROR` (see [ADR-0017](0017-multipart-strict-error.md))
  still triggers on actual parse faults.

## References

- PR: https://github.com/corazawaf/coraza/pull/1453
- Related ADRs: ADR-0017 (`MULTIPART_STRICT_ERROR`)
