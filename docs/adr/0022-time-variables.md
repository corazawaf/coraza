# ADR-0022: `TIME_*` variables support

- **Status:** accepted
- **Date:** 2024-12-09
- **Version:** v3.3.0
- **PR:** [#1223](https://github.com/corazawaf/coraza/pull/1223)
- **Issue(s):** [#1220](https://github.com/corazawaf/coraza/issues/1220)
- **Deciders:** @geoolekom, @jcchavezs, @M4tteoP, @fzipi, @jptosso
- **Category:** Parity (ModSecurity parity)

## Context and Problem

ModSecurity exposes `TIME`, `TIME_DAY`, `TIME_EPOCH`, `TIME_HOUR`,
`TIME_MIN`, `TIME_MON`, `TIME_SEC`, `TIME_WDAY`, `TIME_YEAR`. Popular
rulesets (Imunify360 was cited) use them heavily for time-window rules and
for enriching `msg` / `logdata`. Coraza had none.

## Decision Drivers

- ModSecurity compatibility.
- Support real-world ruleset patterns like "measure duration between two
  phases" (Imunify360's filescan rules).
- Pick a single, sensible TIME_MON range (ModSecurity itself is
  inconsistent: v2 uses 1-12, v3 uses 0-11).

## Considered Options

- Do not implement — push time handling into the embedder's logger.
- Implement eagerly at transaction-creation time.
- Implement lazily (fill on first access).
- Implement eagerly with a precomputed `int → string` lookup table.

## Decision Outcome

Chosen: **eager population at transaction creation, with small perf
optimisations** (follow-up #1242). Lazy collections were prototyped but did
not pay off enough to justify the new concept.

> "We merged this PR as it was and with a couple of performance improvements
> in #1242 because lazy collections wasn't bringing enough improvements for
> this particular use case that it did not feel right to land such a concept
> for low benefit."
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/1223#issuecomment-2568873506))

For `TIME_MON` the PR standardised on **1–12** to align with the
ModSecurity v2→v3 reconciliation in owasp-modsecurity/ModSecurity#3306.

> "There is already an open PR … that aligns v3 to use `1-12` range. So I
> believe that we have pretty much agreed that `1-12` range is the one we
> should stick with. Let's go with it"
> — @M4tteoP ([review](https://github.com/corazawaf/coraza/pull/1223#discussion_r1853923001))

## Technical Discussion

**Initial resistance from @jcchavezs:**

> "I am not fully convinced on the need of this. I believe the case you
> point out is more like a logger concern as we are only interpolating the
> variable to display the timestamp. **Interpolating a variable isn't cheap**,
> nor it is allocating all the variables we allocated and converted by
> default from int to string."
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/1223#issuecomment-2483103482))

…countered with real-world rule examples (Imunify360 filescan duration
rules), which moved the decision:

> "Thanks @geoolekom! I think most of the points raised here make sense.
> Let me do a couple of experiments as what I have in mind is that this a
> good opportunity for trying lazy collections."
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/1223#issuecomment-2488002382))

**TinyGo / Wasm consideration.** @jcchavezs noted Wasm environments can't
cheaply call `time.Now()`, so lazy filling was attractive. The PoC lived at
https://github.com/geoolekom/coraza/pull/1 ; it did not outperform the simple
eager path enough to ship.

**Perf optimisation.** @jcchavezs suggested a lookup table over `strconv.Itoa`:

> "I was advocating for having a map in memory e.g. `var hourConversion
> map[int]string = map[int]string{1: \"1\", 2: \"2\", ...}` instead of doing
> the `strconv.Itoa`."
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1223#discussion_r1846662447))

Landed in follow-up #1242.

**Alternative shape considered.** @fzipi asked whether lazy/per-access
population would be simpler end-to-end:

> "Isn't better to just remove this call and generate the value for each
> variable at access time instead? Kind of being more an *init* than *set*."
> — @fzipi ([review](https://github.com/corazawaf/coraza/pull/1223#discussion_r1868568426))

## Participants

- @geoolekom — author (provided the real-world rule examples that carried
  the decision)
- @jcchavezs — review (lazy-collection PoC, perf guidance)
- @M4tteoP — review (drove the `TIME_MON` 1-12 decision)
- @fzipi — review (shape alternatives)
- @jptosso — review

## Consequences

- **Positive:** Time-aware rules (scan-duration logic, rate/hour correlation,
  `msg`/`logdata` enrichment) work in Coraza; CRS and Imunify360 rules that
  rely on `TIME_*` become usable.
- **Negative / follow-up:** `time.Now()` is called for every transaction;
  Wasm-scale deployments pay a cost. Lazy collections explored and declined.
  Further perf tuning shipped in #1242.

## References

- PR: https://github.com/corazawaf/coraza/pull/1223
- Issue: https://github.com/corazawaf/coraza/issues/1220
- Follow-up perf PR: https://github.com/corazawaf/coraza/pull/1242
- Lazy-collection PoC: https://github.com/geoolekom/coraza/pull/1
- ModSecurity TIME_MON alignment: https://github.com/owasp-modsecurity/ModSecurity/issues/3305,
  https://github.com/owasp-modsecurity/ModSecurity/pull/3306
