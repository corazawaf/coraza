# Threat model

This file is read by Anthropic's OSS Scanner before it analyses Coraza. It complements
[`SECURITY.md`](../SECURITY.md) (reporting policy, how we score), [`AGENTS.md`](../AGENTS.md)
(architecture, testing rules, secure-coding rules) and [`RATIONALE.md`](../RATIONALE.md)
(why the body-buffering limits are what they are). Read those three first.

## What this project does and where untrusted input enters

Coraza is a Web Application Firewall engine, a Go library. An integrator (a reverse proxy,
an HTTP middleware, a sidecar) feeds it one HTTP transaction at a time through the
`types.Transaction` API (`ProcessConnection`, `ProcessURI`, `AddRequestHeader`,
`ProcessRequestHeaders`, `WriteRequestBody`/`ReadRequestBodyFrom`, `ProcessRequestBody`,
`AddResponseHeader`, `ProcessResponseHeaders`, `WriteResponseBody`, `ProcessResponseBody`,
`ProcessLogging`). Coraza evaluates SecLang rules (ModSecurity v2/v3 compatible, normally
the OWASP CRS) against the transaction and returns an interruption when a rule
blocks.

**Every byte of the request and of the response is attacker-controlled**: the method, URI,
query string, headers, cookies, the request body in every format we parse (urlencoded,
JSON, XML, multipart/form-data, raw), and the response headers and body. The attacker also
controls how that input is split, encoded, repeated and ordered.

**Rules and configuration are trusted.** SecLang files, `SecRule` arguments, operator
arguments, file paths for `@pmFromFile`/`@ipMatchFromFile`/`@inspectFile`, audit-log
destinations and `ctl:` actions placed in a rule are the operator's choice. A finding that
requires the attacker to write or alter rules is not a vulnerability. A finding where a
*valid* rule or directive silently does less than ModSecurity would do with it (a parse
divergence, a key that never matches, a limit that is accepted but not enforced) is in
scope: operators rely on that parity.

The integrator is semi-trusted: `http/` (our own middleware and interceptor) is in scope;
third-party connectors (coraza-proxy-wasm, coraza-caddy, coraza-spoa) live in other
repositories and are out of scope here, but an API contract that makes a reasonable
integrator unsafe is in scope.

## Components that matter most / least

Most, in this order:

1. `internal/corazawaf/` — `Transaction`, `Rule.Evaluate`/`doEvaluate`, `RuleGroup.Eval`,
   variable extraction, the transformation cache, interruption handling, the body
   buffers and their limits. One `WAF` is shared by many concurrent transactions; anything
   written into shared rule or WAF state from a transaction is a bug.
2. `internal/bodyprocessors/` — urlencoded, JSON, XML, multipart, raw. Parser disagreements
   with real backends (PHP, Go `net/http`, Python, Java servlet containers) are the classic
   WAF bypass. Every processor must honour `SecArgumentsLimit`, `SecRequestBodyLimit`,
   `SecRequestBodyJsonDepthLimit` and the in-memory/temp-file limits.
3. `internal/transformations/` and `internal/operators/` — each transformation must be a
   total function of its input; each operator must be bounded in time and memory for any
   input (watch regexes we compile from rule arguments: `@rx` uses Go's RE2 so ReDoS from
   the pattern itself is not a concern, but custom scanning loops are).
4. `internal/collections/` and `internal/variables/` — key lookup semantics (case folding,
   regex keys, exceptions `!ARGS:foo`), counts, concat views over several maps.
5. `internal/seclang/` — the parser. Config is trusted, but silent misparses are in scope.
6. `internal/auditlog/` — attacker bytes reach log files and remote sinks; CR/LF and
   format injection are in scope (we have fixed several).
7. `internal/url/`, `internal/cookies/`, `internal/strings/`, `internal/io/`,
   `internal/memoize/` — small, hot, and full of edge cases.
8. `http/` — middleware, interceptor, body streaming, websocket handling.

Less: `debuglog/`, `experimental/` (plugin registries; the plugin *interfaces* matter, the
registration code does not), `internal/sync/` (TinyGo shims), `examples/`, `testing/` (the
harness itself), `magefile.go`, `docs/`.

Out of scope: the OWASP CRS's own detection logic (report to
github.com/coreruleset/coreruleset), libinjection's own false negatives in
`@detectSQLi`/`@detectXSS` (we vendor `libinjection-go`), `testing/modsecurity/` (a
comparison suite against the C library, not built in this image), TinyGo-only code paths
(TinyGo is not installed in this image).

## How to exercise it

- `go test ./...` runs the engine's own tests and `examples/http-server`; in this image it
  does not cover `testing/modsecurity` (needs the libmodsecurity C library, not built) or
  the TinyGo build (`internal/sync/pool_tinygo.go` and friends; TinyGo is not installed).
  `go run mage.go test` runs CI's build-tag matrix (`coraza.no_memoize`,
  `coraza.rule.multiphase_evaluation`, `coraza.rule.no_regex_multiline`,
  `coraza.rule.case_sensitive_args_keys`, ...). Test binaries for every tag are already
  compiled into the build cache, so the matrix runs offline.
- The clearest way to state "these rules + this request should/should not match" is a
  declarative profile: see `testing/engine/*.go` and the `Testing` section of `AGENTS.md`.
  A reproducer in that form, or a small `_test.go` using `coraza.NewWAF(...)` and
  `tx.Process*`, is what we need in a report; `SECURITY.md` says reports without a
  reproducer are closed.
- `testing/coreruleset/` runs the full OWASP CRS v4 regression corpus through Coraza with
  go-ftw (`cd testing/coreruleset && go test ./...`, ~15 s). It is the ground truth for
  "does this change break detection": a proposed patch that touches body processors,
  transformations, collections or rule evaluation must pass it, under the default tags and
  under `-tags=coraza.rule.multiphase_evaluation`.
- Running as root, two tests fail by construction: `TestConcurrentWriterFailsOnInit` and
  `TestSerialWriterFailsOnInitForUnexistingFile` expect opening `/unexisting.log` to be
  denied. That is the container, not a bug; everything else passes.
- `build/http-server` is `examples/http-server` built against the engine; it loads
  `coraza.conf-recommended` and serves a WAF-protected endpoint for end-to-end probing.
- `coraza.conf-recommended` is the configuration we expect in production, including the
  limits and the backstop rules (`200002`-`200005`). Score against it, not against a bare
  `SecRuleEngine On`.

## How you rate severity

We score with CVSS 3.1 and re-score every report during triage; the rules below are what
we apply (see `SECURITY.md`, "CVSS scores are triaged, not accepted as submitted").

- **WAF bypass** (a payload that a rule should inspect never reaches it, or reaches it
  altered so the rule misses, while the backend receives it intact): Scope Changed,
  Confidentiality None, Integrity Low — the impact lands on the protected application,
  which still has to be vulnerable to the payload. Attack Complexity Low when the bypass
  fires from attacker-supplied input alone on any deployment; High only when it depends on
  something outside the attacker's control (a specific backend behaviour, winning a race).
  That gives Medium (5.8 / 4.0) for most bypasses. A required *configuration* (a
  non-default directive, a custom rule) is scored as if present and does not raise Attack
  Complexity, unless that configuration deliberately weakens security or conflicts with
  our guidance (`coraza.conf-recommended`, `RATIONALE.md`), in which case it is the
  operator's choice and not a finding; either way, say what the precondition is. Rate
  High only when a default
  `coraza.conf-recommended` + CRS deployment at paranoia level 1 misses an entire
  attack class.
- **Denial of service**: memory or CPU that grows beyond what the configured limits bound
  (`SecRequestBodyLimit`, `SecRequestBodyInMemoryLimit`, `SecArgumentsLimit`,
  `SecRequestBodyJsonDepthLimit`, `SecResponseBodyLimit`) from a single request is High
  (7.5, `A:H`). Amplification that stays bounded by the body limit but defeats the
  argument/recursion limits, or inert backstop rules, is Medium (`A:L`). Measure it: a
  report should say how many bytes in produce how much memory or time. We care about
  microseconds-to-seconds per request, not nanoseconds.
- **A panic reachable from request input** in library code is High: the integrator's
  process dies. `net/http` recovers per connection; most other integrators do not.
- **Shared-state races** (a transaction writing into the `WAF`, a `Rule`, a pooled
  object that another transaction reads) are at least Medium; score the consequence
  (bypass, false positive, panic) as above, with Attack Complexity High for the race itself.
- **Log injection / forgery** into the audit log or error log is Low.
- **Parity with ModSecurity**: a directive, operator, transformation or variable that
  silently behaves differently from ModSecurity v2/v3 in a way that weakens detection is a
  bypass; one that is stricter is not a vulnerability. Cite the ModSecurity source
  (`apache2/` for v2, `src/` for v3) when claiming parity either way.

Not vulnerabilities, do not report:

- Anything requiring control of rules, configuration, the filesystem the WAF reads, or the
  integrator's code.
- False positives (a benign request blocked) unless they are attacker-triggerable against a
  third party's traffic.
- `@inspectFile` passing the variable value as the program's argument: that is its
  documented contract and ModSecurity's.
- `SecRequestBodyNoFilesLimit` not being enforced: documented as unsupported.
- The comment transformations (`removeComments`, `replaceComments`) being unaware of SQL
  string literals: a documented limitation shared with ModSecurity since 2016
  (ModSecurity#1207); the mitigation is at the rule level.
- The `unsafe` uses in `internal/strings` and `internal/corazawaf/rule.go` (ADR-0019) and
  the process-wide memoization of compiled patterns (ADR-0042/0043): by design.
- Lack of authentication, TLS, rate limiting: Coraza is a library inside the integrator.

## What a good report and patch look like

- A reproducer we can run: a `_test.go` or a profile in `testing/engine/`, with the rules,
  the request, what happened and what should have happened. Include the output of the
  unpatched code.
- The CVSS vector with the preconditions spelled out, scored with the rules above.
- A patch that follows `AGENTS.md`: the fix in the shared function all callers route
  through, one regression case in the test home that owns the behaviour (a profile for
  rule semantics, a table row for a pure function), no new test files, no new `unsafe`, no
  CGO, TinyGo-compatible, passing `go run mage.go check` and the CRS suite. Check the
  ModSecurity source for how it behaves before choosing a semantic.
- We fix on private advisory forks and publish through GitHub Security Advisories; reports
  that are confirmed get an advisory with the reporter credited and the AI involvement
  disclosed per `SECURITY.md`.
