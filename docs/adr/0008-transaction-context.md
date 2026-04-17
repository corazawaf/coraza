# ADR-0008: Attach `context.Context` to transactions

- **Status:** accepted
- **Date:** 2024-01-31
- **Version:** v3.1.0
- **PR:** [#963](https://github.com/corazawaf/coraza/pull/963)
- **Issue(s):** [#919](https://github.com/corazawaf/coraza/issues/919)
- **Deciders:** @jcchavezs, @anuraaga, @MrWako
- **Category:** Feature

## Context and Problem

Embedders wanted to correlate Coraza log output with the upstream request
context — for distributed tracing, log-injection, etc. Without access to
`context.Context` from inside rule matches, there was no clean way to pass a
trace ID through to the audit-log consumer.

## Decision Drivers

- Let consumers access a `context.Context` from a `MatchedRule` to correlate
  WAF logs with surrounding request traces.
- Avoid breaking the v3 `types.RuleMatch` interface in a minor release.
- Stay consistent with the existing `WAF` config style.

## Considered Options

- Add `Context() context.Context` directly to the public `types.RuleMatch`
  interface.
- Expose a new `experimental.WAF` / `Contexter` optional interface and let
  callers assert to it.
- Introduce a new functional option vs a config-object method for transaction
  construction.

## Decision Outcome

Chosen: **optional `Contexter` assertion + a new `NewTransactionWithContext`
entrypoint** with a config-object style consistent with the rest of the WAF
API.

> "Not sure about it. I'd rather to expose experimental features over exposing
> a new experimental API (composed of many features). Unfortunately the way
> to expose experimental features is to create a new interface but that is
> much simpler than saying 'the experimental WAF'"
> — @jcchavezs ([review](https://github.com/corazawaf/coraza/pull/963#discussion_r1467953170))

@anuraaga asked to follow the config-object style already used by the WAF
constructor — the final shape complies:

> "We use a config object instead of functional options for waf maybe good to
> be consistent with it."
> — @anuraaga ([review](https://github.com/corazawaf/coraza/pull/963#discussion_r1467685179))

> "I personally find two methods to be ok, lean towards consistency with the
> waf config. If you're interested in changing that to options pattern as
> well for a potential major then that'd be ok too"
> — @anuraaga ([review](https://github.com/corazawaf/coraza/pull/963#discussion_r1470407485))

## Technical Discussion

User @MrWako validated the pattern end-to-end:

> "I've just tested by pulling in master and adding the snippet above. Works
> perfectly! Really good to be able to easily correlate the WAF logs with the
> request traffic through the system"
> — @MrWako ([comment](https://github.com/corazawaf/coraza/pull/963#issuecomment-1920910404))

@jcchavezs documented the escape hatch for embedders:

> "```go
> type Contexter interface { Context() context.Context }
> …
> if ctxer, ok := mr.(Contexter); ok { ctx = ctxer.Context() }
> ```"
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/963#issuecomment-1920789693))

…and telegraphed the v4 plan:

> "for this we will introduce a new method in the `types.RuleMatch` interface
> which is a breaking change but I can guarantee *nobody* has an own
> implementation of that so user facing it isn't a breaking change. So for v4
> expect to remove the type casting as it will just work."
> — @jcchavezs ([comment](https://github.com/corazawaf/coraza/pull/963#issuecomment-1920919931))

## Participants

- @jcchavezs — author, drove the experimental-interface plan
- @anuraaga — review (config-object consistency, seal-internal suggestion)
- @MrWako — issue reporter + downstream validator

## Consequences

- **Positive:** Matched rules can expose the request `context.Context` for
  log/trace correlation without any v3 interface break.
- **Negative / follow-up:** Two construction entrypoints
  (`NewTransaction`, `NewTransactionWithContext`) coexist; v4 is expected to
  fold the context into the canonical interface and drop the assertion.

## References

- PR: https://github.com/corazawaf/coraza/pull/963
- Issue: https://github.com/corazawaf/coraza/issues/919
