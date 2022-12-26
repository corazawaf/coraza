# Changelog

## Coraza v3  (unreleased)

* Decided for Golang semantic versioning [#208](https://github.com/corazawaf/coraza/issues/208)

* BREAKING: Required Go version gets bumped to 1.18 [#343](https://github.com/corazawaf/coraza/pull/343)

* **CRS v4 Support** - [#218](https://github.com/corazawaf/coraza/issues/218) -
Coraza v3 is fully compatible with the OWASP Core Rule Set v4. Support for Core Rule Set 3.x is dropped as rules are still based on PCRE. CRS v4 is solely based on RE2 and will soon see a public & official release.  

  CRS further moved away from its dependency on old Regexp::Assemble to the new crs-toolchain helper to prevent rules incompatible with Coraza.

* **FEATURE: TinyGo & WASM support & Proxy-WASM Connector** - [#254](https://github.com/corazawaf/coraza/pull/254) -
Coraza adds initial support for TinyGo to allow compiling to Web Assembly (WASM). Compatible directives are marked with *Tinygo Compatibility* in the documentation.

  Based on contributions sponsored by the Tetrate.io team, a new [coraza-proxy-wasm connector](https://github.com/corazawaf/coraza-proxy-wasm) is developed which can be loaded in [Envoy Proxy](https://www.envoyproxy.io) or as Istio plugin.

  Special thanks to the Tetrate team, Anuraag Agrawal, Matteo Pace and José Carlos Chávez. This greatly enhances our coverage, as now we support Envoy proxy and any WASM-proxy compatible system.

* **FEATURE: SecDatasets & operators** - [#361](https://github.com/corazawaf/coraza/pull/361) -
SecDatasets are added as replacement for .data files. WASM support is an essential feature of Coraza v3, but users cannot fully enjoy its potential because of file reading limitations. For this reason, SecDataset is a decent replacement for .data files.

  Two new SecLang operators are added which can be used to query datasets. `pmFromDataset`  [#361](https://github.com/corazawaf/coraza/pull/361) and `ipMatchFromDataset` [#75e8217](https://github.com/corazawaf/coraza/commit/75e821700de9fbfafde6c763f474c7add8dab319) which can be used instead of their file based equivalents for those environments which can't access the filesystem.


```apache
SecDataset restricted-files-1 `
.my.cnf
.mysql_history
`
SecRule REQUEST_FILENAME "@pmFromDataset restricted-files-1" \
    "...msg:'Match sample_dataset'"
```

* **FEATURE: Restpath Operator** - [#282](https://github.com/corazawaf/coraza/pull/282) - `@restpath` takes a path pattern as a parameter eg. `/path/to/{id}/{name}` and aids evaluation of application urls. The path will be transformed to a regex and assigned to variables in `ARGS_PATH`, `ARGS_NAMES`, and `ARGS`. 

```apache
SecRule REQUEST_URI "@restpath /some/random/url/{id}/{name}" "…..chain"
SecRule ARGS_PATH:id "!@eq %{user:session_id}" "deny"
```

* **FEATURE: Redirect Operator** - [#290](https://github.com/corazawaf/coraza/pull/290) -
Redirect takes a status code and url as parameter and based on this information returns an http redirect to the client. 

```apache
SecRule REQUEST_URI "/redirect"  "phase:1,id:1,status:302,redirect:http://www.example.com
```

* **Enhanced Multipart Support** - [#452](https://github.com/corazawaf/coraza/pull/452) -
Pick up the MULTIPART_PART_HEADERS support found in ModSecurity [reference](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)-Variables#MULTIPART_PART_HEADERS).

> This variable is a collection of all part headers found within the request body with Content-Type multipart/form-data. The key of each item in the collection is the name of the part in which it was found, while the value is the entire part-header line -- including both the part-header name and the part-header value.

```apache
SecRule ARGS:_msg_body "@rx Hi Martin," "id:200, phase:2,log"
SecRule MULTIPART_PART_HEADERS:_msg_body "Content-Disposition" "id:250, phase:2, log"
SecRule MULTIPART_PART_HEADERS "Content-Disposition" "id:300, phase:2, log"
```

### Performance Optimizations

Similar performance to modsecurity is archived, we are faster or slower, depending on the payload. Usually, big payloads work better in Coraza. Coraza v3 is ~50% faster than Coraza v2.0.1, more than 200% faster than Coraza v2.0.0.

- Replace the Aho Corasick string matching implementation used internally with Petar Dambovaliev’s implementation (60% less memory consumption and 233% faster execution time) [#302](https://github.com/corazawaf/coraza/pull/302)
- Optimize validateNID operator [#30e5b56](https://github.com/corazawaf/coraza/commit/30e5b564d4d7c6688fb819c97b0891e097570a2e) [#348](https://github.com/corazawaf/coraza/pull/348)
- Use io.Discard instead of /dev/null to save a syscall when debug log output should be discarded [#354](https://github.com/corazawaf/coraza/pull/354)
- Optimize Body Buffering [#505](https://github.com/corazawaf/coraza/pull/505)
- Remove unused mutex in RuleGroup [#381](https://github.com/corazawaf/coraza/pull/381)
- Speed up random string generation by switching to a pseudorandom generator [#403](https://github.com/corazawaf/coraza/pull/403)
- Improve SecLang parser performance [#412](https://github.com/corazawaf/coraza/pull/412) 
- Use strings.Builder to avoid copy string input to bytes in `urlencode` [#320]((https://github.com/corazawaf/coraza/pull/320) and `base64decode` [#319](https://github.com/corazawaf/coraza/pull/319) 
- Use lookup table for byte range validation in `validateByteRange` [#490](https://github.com/corazawaf/coraza/pull/490)

### API Changes

A lot of effort was added to optimize and clean up the Coraza API which resulted in a couple of breaking API changes.

- **New Variables Engine** - [#277](https://github.com/corazawaf/coraza/pull/277) - Implements a new Variables Engine similar to modsecurity. Variables have two pointers `tx.Collections[]` and `tx.variables.*` which either allow programmatic access using the proper collection mechanism or using dynamic variable names.

  There are multiple variable types (Simple, Map, Proxy, Translation) with different helpers and generic helpers. Each type has its own variable (string, map, proxy, etc.)  https://github.com/corazawaf/coraza/tree/v3/dev/collection 

  **BREAKING**: Raw data can only be accessed through a RequestBodyProcessor

- **BREAKING**: Library entry points are converted to immutable interfaces [#397](https://github.com/corazawaf/coraza/pull/397)

  This simplifies the interface and provides a safe mechanism to invoke Coraza and handle transactions. It further allows for major changes without updating the public API and maintains compatibility. Any calls to seclang.NewParser can be removed.

  The approach for doing this is to first move existing interfaces into internal/corazawaf, internal/seclang and start creating public API from scratch delegating to these. After completing migration, there is probably cleanup that could be done which may result in the removal of delegation, but that could happen after locking in a public API.



- **BREAKING**: Rename Waf to WAF to follow Go type naming conventions of acronyms. `coraza.NewWaf` must be accessed as `coraza.NewWAF` and `tx.Waf` as `tx.WAF`. [#373](https://github.com/corazawaf/coraza/pull/373)

- **BREAKING**: Rename methods of *Transaction* [#518](https://github.com/corazawaf/coraza/pull/518)
  - Interrupted &rarr; IsInterrupted
  - ResponseBodyAccessible &rarr; IsResponseBodyAccessible
  - IsProcessableResponseBody &rarr; IsResponseBodyProcessable
  - RequestBodyAccessible &rarr; IsRequestBodyAccessible

- **BREAKING: Remove ZAP** - [#682b59](https://github.com/corazawaf/coraza/commit/6828b59811f5a1b0b86213533a71ec9aaea229c8) [#b64ede7](https://github.com/corazawaf/coraza/commit/b64ede757c7409d7ab9e441bbdfcf6157a3aa6b0) - Debug logging is now an interface and Zap is removed . Support to allow `SecDebugLog` to log to `/dev/stderr` or `/dev/stdout` is added in [#449](https://github.com/corazawaf/coraza/pull/#449)

- **BREAKING: WAFConfig Type**: A new immutable WAFConfig type is added to initialize Coraza, which replaces seclang.NewParser.
Each WithXXX function (WithRules, WithDirectives, WithDirectivesFromFile, WithAuditLog, WithContentInjection, WithRequestBodyAccess, WithResponseBodyAccess, WithDebugLogger, WithErrorLogger, WithRootFS) of this type returns a new instance including the corresponding change. [#bffb435/config.go#L1

- **Rules, Action & Transaction Interfaces** - New immutable interfaces are added

- **BREAKING**: Convert rulematch types to interfaces [#478](https://github.com/corazawaf/coraza/pull/478)

- **BREAKING**: https://github.com/corazawaf/coraza/pull/503

- **BREAKING**: Add RequestBodyAccessible() and ResponseBodyAccessible() to types.transaction.

- **BREAKING**: Export Request/Response BodyAccess values [#499](https://github.com/corazawaf/coraza/pull/)


### Testing

- Introduce new CRS testing suite for Coraza v3 based on Go HTTPServer and go-ftw. Remove Caddy to avoid circular project dependency [#457](https://github.com/corazawaf/coraza/pull/457)
- Automatically perform Benchmarks to detect performance regressions [#301](https://github.com/corazawaf/coraza/pull/301)
- Enhance the test engine to perform tests of returned interruptions (output.interruption).
- Add testing for disruptive actions.
- Switch to mage instead of pre-commit [#315](https://github.com/corazawaf/coraza/pull/315) [#355](https://github.com/corazawaf/coraza/pull/355) [#356](https://github.com/corazawaf/coraza/pull/356)



--------------------------------------------------------------

## Coraza v2  (March 22, 2022)

BUG FIXES:

* Fix incorrect macro expansions for log and msg of chained rule [#193](https://github.com/corazawaf/coraza/issues/193)

IMPROVEMENTS:

* Fully compliant with SecLang from modsecurity v2 [PR #123](https://github.com/corazawaf/coraza/pull/123)
* Better performance [PR #123](https://github.com/corazawaf/coraza/pull/123), [PR #136](https://github.com/corazawaf/coraza/pull/136)
* New enhanced plugins interface for transformations, actions, body processors, and operators [PR #120](https://github.com/corazawaf/coraza/pull/120)
* Many features removed and transformed into plugins: XML (Mostly), GeoIP [PR #170](https://github.com/corazawaf/coraza/pull/170) and PCRE regex
* Full internal API refactor, public API has not changed
* Refactor Audit logging with support for log output plugins [PR #20](https://github.com/corazawaf/coraza/pull/20), [PR #133](https://github.com/corazawaf/coraza/pull/133)
* Update libinjection-go [PR #157](https://github.com/corazawaf/coraza/pull/157)
* Better debug logging
* New error logging (like modsecurity)

NOTES:

**Migrate from Corza v1**

* Rollback `SecAuditLog` to the legacy syntax (serial/concurrent)
* Attach an error log handler using `waf.SetErrorLogCb(cb)` (optional)
* The function `Transaction.Clean()` must be used to clear transaction data, files and take them back to the sync pool.
* If you are using low level APIs check the complete changelog as most of them were removed.
* OWASP CRS does not require external dependencies anymore
