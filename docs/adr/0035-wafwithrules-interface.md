# ADR-0035: `WAFWithRules` experimental interface — `RulesCount()` / `MergeRules()`

- **Status:** accepted
- **Date:** 2026-02-27
- **Version:** v3.4.0
- **PR:** [#1492](https://github.com/corazawaf/coraza/pull/1492)
- **Issue(s):** Dependency of [libcoraza#50](https://github.com/corazawaf/libcoraza/pull/50)
- **Deciders:** @ppomes, @fzipi, @M4tteoP, @Copilot (reviewer)
- **Category:** Feature (API)

## Context and Problem

Connectors (nginx, Apache) needed a way to:

1. Report how many rules a WAF instance has loaded — for caching, logging,
   and load-verification checks.
2. Inherit/merge rules across config scopes (http → server → location in
   nginx terms).

Neither capability was exposed before this PR.

## Decision Drivers

- Provide an experimental interface (`WAFWithRules`) that connectors can
  type-assert to, keeping the main `WAF` interface small.
- Define merge semantics: duplicate IDs skipped, ID=0 rules (`SecMarker`,
  un-ID'd `SecAction`) always merged because they legitimately repeat.
- Allow concurrent-safety guarantees to remain with the initialization
  phase only.

## Considered Options

- Promote `RulesCount()` / `MergeRules()` onto `WAF` (breaks semver).
- Ship as a separate `WAFWithRules` experimental interface.

## Decision Outcome

Chosen: **separate `experimental.WAFWithRules` interface**. ID=0 merge
semantics explicitly documented.

## Technical Discussion

The Copilot reviewer drove five substantive structural changes:

**1. O(n·m) merge complexity.**
> "`RuleGroup.Merge` performs `FindByID` for each rule being merged, making
> merges O(n*m). In nginx config inheritance, this could be invoked per
> location and become noticeably expensive with large rulesets (e.g., CRS).
> Consider building a set/map of existing IDs once … and doing O(1)
> lookups while iterating the source rules."
> — @Copilot ([review](https://github.com/corazawaf/coraza/pull/1492#discussion_r2835610053))

**2. Nil-safety on `Merge`.**
> "`RuleGroup.Merge` will panic if called with `other == nil`. Since the
> method returns an `error`, it would be safer to treat a nil source as a
> no-op"
> — @Copilot ([review](https://github.com/corazawaf/coraza/pull/1492#discussion_r2835610061))

**3. Thread-safety documentation.**
> "`MergeRules` mutates the WAF's rule set, but both the public `WAF` type
> and internal WAF docs state instances are 'concurrent safe' … Please
> document the required usage constraints (e.g., must be called during
> initialization before any transactions are created / not safe
> concurrently with transaction processing)"
> — @Copilot ([review](https://github.com/corazawaf/coraza/pull/1492#discussion_r2835610080))

**4. Brittle concrete-type switch.**
> "`MergeRules` only accepts `other` when it is exactly the unexported
> concrete type `wafWrapper` (value). This makes the
> `experimental.WAFWithRules` interface hard to use with
> decorators/wrappers and is also brittle … Consider using a type switch
> that supports both `wafWrapper` and `*wafWrapper`"
> — @Copilot ([review](https://github.com/corazawaf/coraza/pull/1492#discussion_r2835610087))

**5. ID=0 semantics.**
> "`WAFWithRules` docs say 'Rules already present (by ID) are skipped', but
> the underlying implementation (via `RuleGroup.Merge`) always merges rules
> with ID 0 (e.g., `SecMarker`) even if the destination already has ID 0
> rules. Please either document this ID=0 exception here, or change the
> merge logic"
> — @Copilot ([review](https://github.com/corazawaf/coraza/pull/1492#discussion_r2835610077))

@ppomes extended tests to cover `SecAction` without explicit `id:`:

> "Added tests at both levels: `TestRuleGroupMergeSecAction` … and
> `TestMergeRulesSecAction` … verifies both SecAction rules are merged and
> never deduplicated"
> — @ppomes ([review](https://github.com/corazawaf/coraza/pull/1492#discussion_r2835771992))

@fzipi flagged the ID=0 semantic during review ("wait, my bad: `SecMarker`
has ID=0, not `SecAction`"), showing the nuance the Copilot reviewer's
concern was pointing at.

## Participants

- @ppomes — author (downstream libcoraza driving the need)
- @fzipi — review (SecAction / SecMarker ID-0 semantics)
- @M4tteoP — review
- @Copilot — reviewer bot (drove 5 structural improvements)

## Consequences

- **Positive:** Connectors can query rule counts and merge rulesets across
  configuration scopes without maintaining their own bookkeeping.
- **Negative / follow-up:** Merge is not safe concurrent with transaction
  processing — documented. The brittle type-switch / lack of decorator
  support were improved during review but remain an area to watch.

## References

- PR: https://github.com/corazawaf/coraza/pull/1492
- libcoraza dependency: https://github.com/corazawaf/libcoraza/pull/50
- Related ADRs: ADR-0034 (rule observer callback)
