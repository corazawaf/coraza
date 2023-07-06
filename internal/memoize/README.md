# Memoize

Memoize allows to cache certain expensive function calls and
cache the result. The main advantage in Coraza is to memoize
the regexes when the connects spins up more than one WAF in
the same process and hence same regexes are being compiled
over and over.

Currently it is opt-in under the `memoize_regex` build tag
as under a misuse it could lead to a memory leak as currently
the cache is global.
