# ADR-0035: `WAFWithRules` experimental interface — `RulesCount()`

- **Status:** accepted
- **Date:** 2026-02-27
- **Version:** v3.4.0
- **PR:** [#1492](https://github.com/corazawaf/coraza/pull/1492)
- **Issue(s):** Dependency of [libcoraza#50](https://github.com/corazawaf/libcoraza/pull/50)
- **Deciders:** @ppomes, @fzipi, @M4tteoP, @Copilot (reviewer)
- **Category:** Feature (API)

## Context and Problem

Connectors (nginx, Apache) needed a way to report how many rules a WAF
instance has loaded — for caching, logging, and load-verification checks.
No such capability was exposed before this PR.

The PR originally also proposed a `MergeRules()` method to inherit/merge
rules across config scopes (http → server → location in nginx terms). That
part was dropped before merge — see Decision Outcome.

## Decision Drivers

- Provide an experimental interface (`WAFWithRules`) that connectors can
  type-assert to, keeping the main `WAF` interface small.
- Ship what's actually needed now (`RulesCount()`) rather than a larger,
  unused surface — see Decision Outcome.

## Considered Options

- Promote `RulesCount()` onto `WAF` (breaks semver).
- Ship `RulesCount()` as a separate `WAFWithRules` experimental interface.
- Also ship `MergeRules()` in the same interface/PR (attempted, then
  descoped — see Technical Discussion).

## Decision Outcome

Chosen: **separate `experimental.WAFWithRules` interface exposing only
`RulesCount()`**. `MergeRules()` was implemented and went through review
(the ID=0 semantics and structural concerns below), but was pulled from
the PR before merge once it turned out the downstream consumer didn't
need it yet:

> "In fact, `MergeRules` is not used at all by the nginx module. Only
> `RulesCount` is. I initially wanted to remove the stub from libcoraza,
> but since it is not (yet) needed, we can re-introduce it later — as you
> wish. I can simplify this PR to remove `MergeRules` and keep only
> `RulesCount` if you prefer."
> — @ppomes ([comment](https://github.com/corazawaf/coraza/pull/1492#issuecomment-3939553512))

> "The simpler the better, and if it is not used, then we can always add
> it later."
> — @fzipi ([comment](https://github.com/corazawaf/coraza/pull/1492#issuecomment-3969120877))

The merged diff touches only `experimental/waf.go`, `waf.go`, and
`waf_test.go`, and adds `RulesCount()` alone — no `MergeRules`,
`RuleGroup.Merge`, or ID=0 handling shipped in this PR.

## Technical Discussion

This discussion concerns the `MergeRules()` design that was in the PR at
review time and was later dropped (see Decision Outcome); it is kept here
because it's the reason `MergeRules()` didn't ship. The Copilot reviewer
raised five structural concerns against that now-removed code:

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

> "Done — added tests at both levels:
> - `TestRuleGroupMergeSecAction` in rulegroup_test.go: uses ID=0 directly,
>   verifies both are kept after merge
> - `TestMergeRulesSecAction` in waf_test.go: uses `SecAction` without `id:`
>   (which gets ID=0 internally), verifies both SecAction rules are merged
>   and never deduplicated"
> — @ppomes ([review](https://github.com/corazawaf/coraza/pull/1492#discussion_r2835771992))

@fzipi initially second-guessed the semantics during review ("wait, my
bad: `SecMarker` has ID=0, not `SecAction`"), but @ppomes confirmed both
get ID=0 in the default build:

> "You're right that `SecMarker` always has ID=0. Note that `SecAction`
> without explicit `id:` also gets ID=0 (default build without
> `mandatory_rule_id_check` tag), so the test is still valid."
> — @ppomes ([comment](https://github.com/corazawaf/coraza/pull/1492#issuecomment-3939553512))

None of this shipped — it documents why `MergeRules()` was dropped, not
behavior present in the merged code.

## Participants

- @ppomes — author (downstream libcoraza driving the need)
- @fzipi — review (SecAction / SecMarker ID-0 semantics)
- @M4tteoP — review
- @Copilot — reviewer bot (raised 5 structural concerns on the dropped
  `MergeRules` design)

## Consequences

- **Positive:** Connectors can query rule counts without maintaining their
  own bookkeeping, via a small experimental interface.
- **Negative / follow-up:** No rule-merging capability shipped.
  `MergeRules()`'s O(n·m) cost, nil-safety, concurrency-safety
  documentation, and brittle type-switch (Technical Discussion) remain
  open questions for whoever picks it up if/when a consumer needs it.

## References

- PR: https://github.com/corazawaf/coraza/pull/1492
- libcoraza dependency: https://github.com/corazawaf/libcoraza/pull/50
- Related ADRs: ADR-0034 (rule observer callback)
