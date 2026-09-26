# ADR-0057: REQUEST_BODY opt-in, REQUEST_BODY_LENGTH always, when a processor ran

- **Status:** proposed
- **Date:** 2026-09-06 (expected; update before merge)
- **Version:** unreleased (post-v3.7.0)
- **PR:** Not yet opened — tracked in [#1685](https://github.com/corazawaf/coraza/issues/1685)
- **Issue(s):** [#1685](https://github.com/corazawaf/coraza/issues/1685)
- **Deciders:** @fzipi, @jcchavezs
- **Category:** Parity (ModSecurity v3 parity)

## Context and Problem

`ProcessRequestBody` never sets `REQUEST_BODY` itself; it delegates entirely to the
body processor, and the processors disagree: `raw` and `urlencoded` set
`REQUEST_BODY`/`REQUEST_BODY_LENGTH`, `xml` sets neither (only `XML://@*` and
`XML:/*`), and `json` stashes the raw body in `TX:json_request_body` instead. That
means a rule inspecting raw body bytes — for example, an XXE rule matching a
`<!DOCTYPE`/`<!ENTITY` declaration, which the parsed XML collections never expose —
works on libmodsecurity v3 and silently no-ops on Coraza
([coreruleset/coreruleset#4767](https://github.com/coreruleset/coreruleset/issues/4767)).
xml.go also returns its parse error before setting anything, and Go's
`encoding/xml` rejects a custom entity reference, so on the classic XXE payload
nothing is populated at all today, not even the XML collections.

Coraza currently matches v2 here, which was a deliberate alignment made in 2022. v3
is the intentional, maintained reference
([owasp-modsecurity/ModSecurity#2146](https://github.com/owasp-modsecurity/ModSecurity/issues/2146)),
so this ADR aligns Coraza's default-request-body-population *mechanism* toward v3,
without changing the default *behaviour* seen by existing rules.

## Decision Drivers

- v3 is the reference implementation upstream defends as intentional; v2 is the
  outlier, tied to its Apache integration.
- [#1628](https://github.com/corazawaf/coraza/issues/1628) reports the opposite
  complaint — bodies force-parsed into `REQUEST_BODY`/`ARGS_POST` blow up memory —
  and shares the same root cause (materializing a disk-backed body brought back
  into RAM). The two changes must not fight each other.
- `SecForceRequestBodyVariable`/`ctl:forceRequestBodyVariable` already mean "I want
  `REQUEST_BODY`"; reusing them needs no new directive, no new documentation
  surface, and no reconciliation with libmodsecurity, which has no equivalent knob.
- Two existing `testing/engine/json.go` profiles assert v2 semantics for
  `REQUEST_BODY` by default; those must keep passing unless the default is
  deliberately changed.
- `REQUEST_BODY_LENGTH` is tracked on the body buffer regardless of the processor,
  so it can be populated at zero allocation independent of whatever is decided for
  the body content itself.

## Considered Options

- **A — populate unconditionally.** Set `REQUEST_BODY`/`REQUEST_BODY_LENGTH`
  centrally in `ProcessRequestBody`, before dispatching to any processor, so every
  processor behaves like v3 by default.
- **B — extend the existing opt-in.** In `ProcessRequestBody`, capture the raw
  body from `requestBodyBuffer.Reader()` into `REQUEST_BODY` *before* dispatching
  to the body processor, gated on `SecForceRequestBodyVariable`/
  `ctl:forceRequestBodyVariable` being set (today the flag only takes effect when
  the processor is empty). Because the capture happens before parsing, a parse
  failure — xml.go's early return on the classic XXE payload, or `json`'s
  "invalid JSON" error — does not prevent `REQUEST_BODY` from being set; only the
  *parsed* collections (`XML:/*`, `ARGS_POST`) stay empty on a parse error, as they
  do today. Always populate `REQUEST_BODY_LENGTH` unconditionally, since it costs
  nothing regardless of this flag.
- **C — a new directive, default-on**, deferred until the `#1628` body-size guard
  lands, so a v3-by-default `REQUEST_BODY` cannot reintroduce the memory blow-up
  `#1628` is asking to fix.

## Decision Outcome

Leaning towards **B**, because it gets v3-equivalent visibility for rules that ask
for it — CRS can flip `ctl:forceRequestBodyVariable=On` in phase 1 scoped to the
XML content types `coraza.conf-recommended` already maps to the XML processor
(`text/xml`, `application/xml`, `application/soap+xml`), paying the copy exactly
where the XXE rule needs it — while keeping the
default behaviour, and the two `testing/engine/json.go` profiles, unchanged. `A`
gives v3 semantics uniformly but changes default behaviour for everyone and
reopens the `#1628` memory concern without its guard in place; `C` is safer but
adds a directive and depends on sequencing with `#1628` before it can default on.

This record is **proposed**, not accepted: the issue thread ends with this
proposal and has not yet been confirmed by a second maintainer, and the open
questions below are unresolved.

## Technical Discussion

> "Is my assumption correct to say we would just allocate double max body limit by
> setting the variable if it isn't valid JSON/XML? Any chance we can do opt out? I
> would say we should provide a way to the user to decide whether invalid Jason
> should be populated or not (length can be populated tho). Either opt in or opt
> out should be possible."
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/issues/1685#issuecomment-5392976005))

<!-- separate comment -->

> "One case is worse than "double": once the body exceeds
> `SecRequestBodyInMemoryLimit` the buffer has spilled to a temp file
> (`internal/corazawaf/body_buffer.go:78`), so materializing the variable pulls a
> disk-backed body back into RAM and defeats the in-memory limit. That is the part
> I would want a guard on, and it is the same guard #1628 is asking for."
> — @fzipi ([comment](https://github.com/corazawaf/coraza/issues/1685#issuecomment-5411063069))

<!-- separate comment -->

> "I think we can get opt-in without adding any config surface, by reusing what is
> already there. `SecForceRequestBodyVariable` and `ctl:forceRequestBodyVariable`
> already mean "I want `REQUEST_BODY`". Today the flag only takes effect when the
> body processor is empty (`transaction.go:1104`); when a processor ran it does
> nothing."
> — @fzipi ([comment](https://github.com/corazawaf/coraza/issues/1685#issuecomment-5411063069))

## Participants

- @fzipi — issue author, proposed both the original (option A) and revised
  (option B) designs
- @jcchavezs — raised the memory cost and opt-in/opt-out requirement that shaped
  option B

## Consequences

- **Positive:** closes the XXE detection gap for rules that explicitly ask for it
  via `ctl:forceRequestBodyVariable`/`SecForceRequestBodyVariable`;
  `REQUEST_BODY_LENGTH` becomes available for every processor at zero allocation
  cost; no new directive to document or maintain; default behaviour and existing
  engine profiles are unaffected.
- **Negative / follow-up:** rule authors (CRS included) must explicitly enable the
  flag — typically scoped to the XML content types (`text/xml`, `application/xml`,
  `application/soap+xml`) in phase 1 — to get the coverage; this does
  not fix xml.go's early-return-on-parse-error path, which still means the XML
  collections stay empty on a parse failure even though `REQUEST_BODY` would now be
  populated; the `json` processor's `TX:json_request_body` workaround is not
  removed by this ADR alone; enabling the flag on a disk-backed (spilled) body still
  pulls the full body back into memory, so rolling this out ahead of the `#1628`
  guard needs care; whether a truncated body should populate `REQUEST_BODY` at all,
  and whether `REQUEST_BODY_LENGTH` is then the received or declared length, remains
  an open question for the implementing PR.

## References

- Issue: https://github.com/corazawaf/coraza/issues/1685
- coreruleset/coreruleset#4767 — the XXE coverage gap that surfaced this
- coreruleset/coreruleset#2502 — CRS-side XXE discussion
- owasp-modsecurity/ModSecurity#2146 — upstream v2/v3 divergence, maintainer position
- #1628 — memory blow-up from eager body population, same v3 reference, opposite direction
- #737 — earlier `ForceRequestBodyVariable` behaviour change
