# ADR-0013: Register audit-log formatters for TinyGo builds

- **Status:** accepted
- **Date:** 2024-04-02
- **Version:** v3.2.0
- **PR:** [#1027](https://github.com/corazawaf/coraza/pull/1027)
- **Issue(s):** Follows [coraza-proxy-wasm#263](https://github.com/corazawaf/coraza-proxy-wasm/pull/263)
- **Deciders:** @M4tteoP, @jcchavezs
- **Category:** Parity (TinyGo / WebAssembly build target)

## Context and Problem

The `init_tinygo.go` file had an explicit `TODO` at
[L22](https://github.com/corazawaf/coraza/blob/0af085cac97602ac22cb58d3a1c7308f241affb6/internal/auditlog/init_tinygo.go#L22)
saying formatters weren't registered for TinyGo. The proxy-wasm connector
needed JSON audit logging under TinyGo, so the skipped registration was
blocking downstream work.

## Decision Drivers

- Support proxy-wasm's need for JSON audit logs without forking the build.
- Keep build-tag gating so TinyGo-unfriendly dependencies don't leak into the
  WASM build.

## Considered Options

- Register all formatters unconditionally (breaks TinyGo compile).
- Add TinyGo-specific copies named `jsonFormatterTinyGo` etc.
- Use build tags to select which formatter file compiles into which target,
  keeping the type names consistent.

## Decision Outcome

Chosen: **build-tag selection without renaming types**. The `Tiny` suffix was
explicitly dropped in review.

> "nit: do we need the Tiny suffix given that we have the build tags. Same
> for the wasm formatter."
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1027#discussion_r1540206047))

> "Yep, not really needed, removed, thanks"
> — @M4tteoP ([review](https://github.com/corazawaf/coraza/pull/1027#discussion_r1540212934))

## Technical Discussion

One follow-on style call for `serial` naming consistency, deferred to the
downstream PR:

> "I would not call it wasmSerial but redeclare serial here for tinygo only"
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/1027#discussion_r1542832255))

## Participants

- @M4tteoP — author
- @jcchavezs — review (naming, merge sign-off)

## Consequences

- **Positive:** proxy-wasm (and any other TinyGo-targeting connector) can use
  JSON audit logging without carrying a patched fork.
- **Negative / follow-up:** Build-tag matrix grows; TinyGo-specific failures
  must be covered by the `tinygo.yml` CI workflow going forward.

## References

- PR: https://github.com/corazawaf/coraza/pull/1027
- Downstream PR: https://github.com/corazawaf/coraza-proxy-wasm/pull/263
