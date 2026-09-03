# ADR-0051: Audit log Part J (uploaded files metadata)

- **Status:** accepted
- **Date:** 2026-04-03
- **Version:** v3.7.0
- **PR:** [#1591](https://github.com/corazawaf/coraza/pull/1591)
- **Issue(s):** No linked issue
- **Deciders:** @fzipi, @M4tteoP, @coderabbitai
- **Category:** Parity (ModSecurity v2 Part J parity)

## Context and Problem

ModSecurity v2's docs describe `Part J` of `SecAuditLogParts` as a list of
uploaded-file metadata, but ModSecurity v2 itself never implemented it —
`msc_logging.c` has no Part J output or escaping logic to match. The
format below is Coraza's own, built from the documented field list, not a
byte-for-byte match to a real ModSecurity output:

```text
1,12345,"image.png","image/png"
2,67890,"doc.pdf","application/pdf"
Total,80235
```

Coraza documented Part J but emitted nothing; uploaded-file metadata was
being folded into Part C in a way that wasn't spec-compliant.

## Decision Drivers

- ModSecurity v2 format parity for audit-log consumers that already know
  Part J.
- Safe escaping of filenames / MIME types (`strconv.Quote`).
- Fallback MIME string when Content-Type missing:
  `<Unknown Content-Type>`.

## Considered Options

- Leave file metadata in Part C.
- Move metadata to Part J per spec, keep native/JSON/OCSF formats in sync.

## Decision Outcome

Chosen: **move to Part J, emit Coraza's own CSV-like format based on
ModSecurity v2's documented field list** (index, size, filename,
content-type), using `strconv.Quote` for escaping — there's no shipped
ModSecurity v2 output to be byte-compatible with. JSON format inherits
the data via struct marshalling; OCSF already read from
`Request().Files()` so it gains the data automatically.

## Technical Discussion

**Implementation notes from the PR body:**

> "**Native format** matches ModSecurity v2's Part J output from
> `msc_logging.c` … **JSON format** gets file data automatically via struct
> marshaling — no extra code needed. **OCSF format** already had file
> observable logic in `formats_ocsf.go:110` that reads from
> `Request().Files()`, so it works once the data is populated."
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1591#issuecomment-4183561086))

`msc_logging.c` doesn't actually contain a Part J implementation to match —
ModSecurity v2 documented the part but never shipped it. "Matches" here
means the field list (index, size, filename, content-type), not verified
wire-compatible output.

**TODO cleanup** @M4tteoP asked:

> "Is this still a todo? Should it be revisited and just become code
> documentation?"
> — @M4tteoP ([review](https://github.com/corazawaf/coraza/pull/1591#discussion_r3033682654))

> "Converted to a concise documentation note — no longer a TODO, just
> describes what Part I would do (still not implemented)."
> — @fzipi ([review](https://github.com/corazawaf/coraza/pull/1591#discussion_r3034070981))

**Version tag on docs:**

> "Also internal/seclang/directives.go directiveSecAuditLogParts
> documentation should be updated:
>
> ```
> // - J: This part contains information about the files uploaded using `multipart/form-data` encoding; not implemented yet.
> ```
>
> might make sense to specify the Coraza version from when this is
> avaiable. `not implemented yet.` -> `Available from Coraza v3.7.0` or
> similar"
> — @M4tteoP ([review](https://github.com/corazawaf/coraza/pull/1591#discussion_r3033700886))

Applied.

**Error-handling discipline on size parsing:**

> "`strconv.ParseInt` for file sizes now checks the error and logs a debug
> message with the file name, raw value, and parse error via
> `tx.DebugLogger()`. Size defaults to 0 on failure."
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1591#issuecomment-4183650976))

## Participants

- @fzipi — author
- @M4tteoP — review (TODO cleanup, version-tag in docs)
- @coderabbitai[bot] — reviewer (MIME assertion in tests)

## Consequences

- **Positive:** the native audit log emits a Part J block of uploaded-file
  metadata (the part ModSecurity v2 reserved for this purpose); the JSON and
  OCSF outputs expose the equivalent metadata through their own field
  structures. SIEM pipelines that consume it work out of the box.
- **Negative / follow-up:** Part I (fake urlencoded body for multipart
  requests) is still unimplemented and documented as such.

## References

- PR: https://github.com/corazawaf/coraza/pull/1591
- ModSecurity reference: Part J documented (but unimplemented) in
  `msc_logging.c`
- Related ADRs: ADR-0005 (formatter interface), ADR-0018 (OCSF)
