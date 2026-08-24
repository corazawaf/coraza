# ADR-0006: Memoize cache for regexes and Aho-Corasick tables

- **Status:** accepted
- **Date:** 2023-08-06
- **Version:** v3.0.3 (opt-in, behind `coraza.memoize_builders` build tag)
- **PR:** [#836](https://github.com/corazawaf/coraza/pull/836)
- **Issue(s):** [coraza-caddy#76](https://github.com/corazawaf/coraza-caddy/issues/76)
- **Deciders:** @jcchavezs, @anuraaga, @jptosso, @M4tteoP
- **Category:** Perf

## Context and Problem

Every WAF instance compiled every regex and Aho-Corasick table afresh. When
the same ruleset is mounted into many WAFs (the Caddy connector pattern
reported in coraza-caddy#76), the same regular expressions get compiled
hundreds of times, wasting CPU at boot and RSS forever after.

## Decision Drivers

- Dramatically reduce memory / compile-time in multi-WAF deployments.
- Stay opt-in so embedders that instantiate one WAF per process see no
  behaviour change.
- Avoid adding a `Close()` method to the `WAF` interface in v3 — adding one
  would be a break.

## Considered Options

- Per-WAF cache.
- Process-global cache, opt-in via build tag, exposed via `experimental`.
- Add `WAF.Close()` now and bind the cache to the WAF lifetime.

## Decision Outcome

Chosen: **process-global cache, opt-in via build tag, exposed via
`experimental`**, because the cache is inherently global (many WAFs share one
process) and adding `WAF.Close()` was considered too large an API move for v3.
The global `Close()` helper lives in `experimental` so anyone worried about
leaks can clear on reload.

> "We should include a flush or reset function so we can delete everything
> after a web server reload. That function must be exported. I would include
> it in `experimental/coraza`"
> — @jptosso ([comment](https://github.com/corazawaf/coraza/pull/836#issuecomment-1622448598))

> "Waf close is not coming in v3 as we cannot break the api, we should just
> export all helpers in experimental until we can merge them. But closing
> cache is different, as this is global and no per-WAF"
> — @jptosso ([comment](https://github.com/corazawaf/coraza/pull/836#issuecomment-1622462418))

@anuraaga agreed per-WAF close would not help here:

> "For this PR though, I don't see how a WAF close method would help though
> since IIUC the cache is global, not per waf. Having a global method in
> experimental for now seems ok."
> — @anuraaga ([comment](https://github.com/corazawaf/coraza/pull/836#issuecomment-1622687655))

## Technical Discussion

@anuraaga pushed on the concurrency primitive:

> "This is ok but this file looks like an obvious mutex guarded map, not sure
> it's worth referencing anything. Anyways it looks like a `sync.Map` should
> be much faster for this, it's docs specifically mention the write once read
> many case of a cache"
> — @anuraaga ([review](https://github.com/corazawaf/coraza/pull/836#discussion_r1253758317))

Error-handling philosophy briefly debated — @jptosso objected to panics,
@jcchavezs chose to match `MustCompile`:

> "Agree, however this should be fixed in `main`, I am just reproducing the
> `MustCompile` behaviour."
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/836#discussion_r1269182547))

The cache was shipped as opt-in (build tag) in v3.0.3, later became the default
in v3.5.0 once per-WAF tracking was available
([ADR-0042](0042-regex-memoize-default-on.md),
[ADR-0043](0043-waf-close-per-owner-memoize.md)).

## Participants

- @jcchavezs — author
- @anuraaga — review (sync.Map suggestion, lifecycle sanity check)
- @jptosso — review (drove the "global + experimental reset" design)
- @M4tteoP — review (docs/readme nit)

## Consequences

- **Positive:** Large multi-WAF deployments (Caddy, proxy-wasm ambient
  authorities) drop boot-time compile cost dramatically.
- **Negative / follow-up:** The global cache is process-lifetime — embedders
  reloading rulesets in-place must call the experimental reset. A cleaner
  per-WAF lifecycle awaits `WAF.Close()` (ADR-0043) and the default-on
  decision (ADR-0042).

## References

- PR: https://github.com/corazawaf/coraza/pull/836
- Related ADRs: ADR-0042 (memoize default on), ADR-0043 (`WAF.Close()`)
- Upstream motivating issue: https://github.com/corazawaf/coraza-caddy/issues/76
