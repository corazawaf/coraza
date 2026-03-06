# Memoize

Memoize caches certain expensive function calls (regex and aho-corasick
compilation) so the same patterns are not recompiled when multiple WAF
instances in the same process share rules.

Memoization is **enabled by default**. To opt out, use the
`coraza.no_memoize` build tag.

## Per-WAF ownership tracking

Each cached entry tracks which WAF instances ("owners") use it. When a
WAF is closed via `WAF.Close()`, its owner ID is removed from all cache
entries. Entries with no remaining owners are deleted, allowing the GC to
collect the compiled objects once no in-flight transactions reference them.

This solves the memory leak previously seen in live-reload scenarios
(e.g. Caddy) where the old global cache grew without bound.

## Build variants

| Build tag             | Behavior                                         |
|-----------------------|--------------------------------------------------|
| *(none)*              | Full memoization with `singleflight` (default)   |
| `tinygo`              | Memoization without `singleflight` (TinyGo)      |
| `coraza.no_memoize`   | No-op — every call compiles fresh                 |
