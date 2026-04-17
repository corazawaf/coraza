# ADR-0016: Case-sensitive args support

- **Status:** accepted
- **Date:** 2024-05-28
- **Version:** v3.2.0 (behind `coraza.rule.case_sensitive_args_keys` build tag)
- **PR:** [#1059](https://github.com/corazawaf/coraza/pull/1059)
- **Issue(s):** No linked issue
- **Deciders:** @fzipi, @M4tteoP, @jcchavezs, @jptosso, @anuraaga
- **Category:** Parity (RFC / ModSecurity parity)

## Context and Problem

HTTP argument names are case-sensitive per RFC. Coraza's default
case-insensitive args behaviour silently merged `foo=1` with `Foo=2` in the
same collection, which is semantically wrong and, for some protections, can
mask attacks.

## Decision Drivers

- RFC compliance for argument matching.
- Avoid breaking rules that relied on the prior case-insensitive behaviour.
- Interop with the CRS test suite.

## Considered Options

- Flip behaviour in v3.x (breaking).
- Expose an engine flag (build tag) that opts into case-sensitive args.
- Let each collection declare its own case-sensitivity via an interface
  (design preferred by the author, but blocked on existing collection
  surface).

## Decision Outcome

Chosen: **opt-in via a build tag (`coraza.rule.case_sensitive_args_keys`).**
The "collection declares its own case-sensitivity" design is captured as a
known limitation in the PR body:

> "I don't like too much that it is the rule that tells if the collection is
> case sensitive. Ideally, we should be able to ask the collection (by
> calling `collection.IsCaseSensitive()` or similar) so that responsibility
> is delegated properly. But didn't knew how to do it first hand."
> — @fzipi (PR body)

## Technical Discussion

Long, substantive back-and-forth on whether this is a breaking change.

**M4tteoP flagged the compatibility risk:**

> "Isn't this a breaking change in the behavior of the engine? Up to now
> users might have written rules in lowercase that would not work anymore
> once this PR gets merged. Are we okay with this change in a minor release?"
> — @M4tteoP ([review](https://github.com/corazawaf/coraza/pull/1059#discussion_r1591311146))

**fzipi argued the fix is RFC-correct:**

> "IMHO yes, because this is the common behavior in other engines."
> — @fzipi ([review](https://github.com/corazawaf/coraza/pull/1059#discussion_r1592452961))

**jcchavezs pushed for build-tag gating to avoid silent breakage:**

> "Maybe we could leverage a build tag for this and introduce the BC in 4.0?"
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1059#discussion_r1592519944))

…and characterised the semantics precisely:

> "rules that use to work won't work anymore and with no notice. That is the
> definition of breaking change (yes, we are breaking something that was
> broken)."
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1059#discussion_r1595884046))

**anuraaga echoed Go's compatibility posture:**

> "With go's promise of compatibility, it's common to auto-update on minors
> and expect no change. Just for reference, the recent blog about … For this
> PR it's still better to add a config option to opt-in to the correct
> behavior and change that in a major version release to prevent rule
> breakage."
> — @anuraaga ([review](https://github.com/corazawaf/coraza/pull/1059#discussion_r1594816563))

**M4tteoP demonstrated a concrete breakage:**

> "With ARGS not case-sensitive, we might have in place a rule like:
> `SecRule ARGS_GET:var3 \"@rx …\"` … Enabling case sensitivity, it would
> suddenly just check `ARGS_GET:var3`."
> — @M4tteoP ([review](https://github.com/corazawaf/coraza/pull/1059#discussion_r1602256989))

The build-tag path won. @fzipi asked for help wiring it:

> "Can someone then, with more knownledge than me, add that magnificent
> build tag and we can get over this?"
> — @fzipi ([review](https://github.com/corazawaf/coraza/pull/1059#discussion_r1596029956))

@jcchavezs pointed at the wiring PR (#1065).

## Participants

- @fzipi — author
- @M4tteoP — review (breakage examples, README update)
- @jcchavezs — review (drove build-tag gating, BC semantics)
- @anuraaga — review (Go compat posture, CRS-test suggestion)
- @jptosso — review

## Consequences

- **Positive:** RFC-correct case-sensitive args is available for embedders
  that want it today; a clean v4 migration path exists.
- **Negative / follow-up:** Two behaviours coexist; CRS-test coverage for
  case sensitivity remained a known gap at merge.

## References

- PR: https://github.com/corazawaf/coraza/pull/1059
- Follow-up wiring: https://github.com/corazawaf/coraza/pull/1065
- Related ADRs: ADR-0015 (case-sensitive maps)
