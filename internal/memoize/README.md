# Memoize

Memoize allows to cache certain expensive function calls and
cache the result. The main advantage in Coraza is to memoize
the regexes and aho-corasick dictionaries when the connects
spins up more than one WAF in the same process and hence same
regexes are being compiled over and over.

Currently it is opt-in under the `memoize_builders` build tag
as under a misuse (e.g. using after build time) it could lead
to a memory leak as currently the cache is global.

**Important:** Connectors with *live reload* functionality (e.g. Caddy)
could lead to memory leaks which might or might not be negligible in
most of the cases as usually config changes in a WAF are about a few
rules, this is old objects will be still alive in memory until the program
stops.
