## Coraza v3  (unreleased)

* Decided for Golang semantic versioning [#208](https://github.com/corazawaf/coraza/issues/208)

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
  * Rollback SecAuditLog to the legacy syntax (serial/concurrent)
  * Attach an error log handler using ```waf.SetErrorLogCb(cb)``` (optional)
  * the function Transaction.Clean() must be used to clear transaction data, files and take them back to the sync pool.
  * If you are using low level APIs check the complete changelog as most of them were removed.
  * OWASP CRS does not require any external dependency anymore
