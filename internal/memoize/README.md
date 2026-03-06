# Memoize

Memoize caches certain expensive function calls (regex and aho-corasick
compilation) so the same patterns are not recompiled when multiple WAF
instances in the same process share rules.

Memoization is **enabled by default**. To opt out, use the
`coraza.no_memoize` build tag.

## Build variants

| Build tag             | Behavior                                         |
|-----------------------|--------------------------------------------------|
| *(none)*              | Full memoization with `singleflight` (default)   |
| `tinygo`              | Memoization without `singleflight` (TinyGo)      |
| `coraza.no_memoize`   | No-op — every call compiles fresh                 |
