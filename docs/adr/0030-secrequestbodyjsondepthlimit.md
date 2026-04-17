# ADR-0030: `SecRequestBodyJsonDepthLimit` directive

- **Status:** accepted
- **Date:** 2026-03-06
- **Version:** v3.4.0
- **PR:** [#1110](https://github.com/corazawaf/coraza/pull/1110)
- **Issue(s):** No linked issue
- **Deciders:** @fzipi, @jcchavezs
- **Category:** Feature

## Context and Problem

Deeply nested JSON request bodies can exhaust the parser or the WAF host's
stack — a known DoS class that has burned ModSecurity in the past. Coraza
had no configurable ceiling, and the JSON body processor also entered
parsing without validating the input first.

## Decision Drivers

- Bound JSON recursion to prevent DoS via deeply nested objects.
- Validate JSON before handing it to the arg-extraction step so invalid
  bodies do not partially populate collections.
- Pick a conservative default (1024) that accommodates real schemas.

## Considered Options

- Validate + depth-limit unconditionally (extra CPU per request).
- Parse-and-bail (best effort, cheaper), risk of mid-parse collection
  pollution.
- Pre-validate with `gjson.Valid` then parse with the lazy `gjson.Parse`.

## Decision Outcome

Chosen: **pre-validate with `gjson.Valid`, then parse**, and introduce
`SecRequestBodyJsonDepthLimit` (default 1024). The author benchmarked the
overhead explicitly and found it acceptable (~33% of the full JSON pipeline
in the worst case), citing the upstream library's own recommendation:

> "It is not very expensive. Of course, it is _more_ expensive than not
> doing vlaidation (adds roughly 33% more time in my benchmarks). The
> upstream library says that '_If you are consuming JSON from an
> unpredictable source then you may want to validate prior to using
> GJSON._' I agree, for the case of a WAF. Or we can forget about
> validation, and see if someone can bypass us. 🤷 If we do, we should
> document clearly this decision."
> — @fzipi ([review](https://github.com/corazawaf/coraza/pull/1110#discussion_r1685809270))

@jcchavezs challenged the expense and the unbounded config:

> "do we really need to do this? the first impression is this is very
> expensive, the second one is when we use a low body limit this will
> always be invalid isn't/"
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1110#discussion_r1685791244))

> "I think it should never be -1 and always force a limit."
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1110#discussion_r1685791885))

The final shape: bounded by default, operator can raise the limit but not
disable it, and the author ran full benchmarks to back the cost claim:

> "## Benchmark: `gjson.Valid` pre-validation overhead … Measured the cost
> of `gjson.Valid()` in the full `readJSON` pipeline …"
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1110#issuecomment-3904707166))

## Technical Discussion

The "should there be a hard ceiling on the directive" question was also
captured:

> "should there be any hard limit?"
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1110#discussion_r2809954992))

> "Do you mean theoretically? Or practically?"
> — @fzipi ([review](https://github.com/corazawaf/coraza/pull/1110#discussion_r2809956756))

The final implementation ships a default (1024) and leaves the ceiling
operator-tunable, on the reasoning that 1024 already dwarfs any realistic
schema.

## Participants

- @fzipi — author (benchmarks + defense of pre-validation)
- @jcchavezs — review (cost, default, hard-ceiling pushback)

## Consequences

- **Positive:** DoS-class attack via deeply nested JSON is neutralised by
  default; invalid JSON is rejected before collection pollution.
- **Negative / follow-up:** Extra ~33% cost on the JSON body path —
  accepted for a WAF under untrusted input.

## References

- PR: https://github.com/corazawaf/coraza/pull/1110
- gjson upstream: https://github.com/tidwall/gjson#validate-json
