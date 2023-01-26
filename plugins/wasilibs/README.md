## wasilibs plugins

This package provides operator plugins using implementations that are compiled from other
languages like C, C++, Rust to WebAssembly. The pure Go WebAssembly runtime wazero is used
so there is no limitation on the Go application that can use the plugins - notably, cgo is
not required.

Performance improves significantly, at the expense of slightly higher memory usage. You should
always benchmark to confirm improvements in your use cases but it should generally be helpful
to enable this plugin.

Note, it is possible to use cgo for some more performance improvement at the cost of requiring
build tooling. See the READMEs of the implementation libraries for details on how to enable it.
In general, pure Go should run fine.

### Usage

Install the package as normal:

```bash
go get github.com/corazawaf/coraza/v3/plugins/wasilibs
```

and before initializing `WAF`, for example in an `init()` function, call `Register`.

```go
package main

import (
    "github.com/corazawaf/coraza/v3/plugins/wasilibs"
)

func init() {
	wasilibs.Register()
}
```

Alternatively, you can use the `RegisterX` functions to register the plugins individually.


```go
package main

import (
    "github.com/corazawaf/coraza/v3/plugins/wasilibs"
)

func init() {
	wasilibs.RegisterPM()
	wasilibs.RegisterRX()
	wasilibs.RegisterSQLi()
	wasilibs.RegisterXSS()
}
```

### Operators

The overridden operators are

- `rx`: Uses [re2](https://github.com/wasilibs/go-re2)
- `pm`: Uses [BurntMill/aho-corasick](https://github.com/wasilibs/go-aho-corasick)
- `detect_sqli`, `detect_xss`: Uses [libinjection](https://github.com/wasilibs/go-libinjection)

Note that `wasilibs.Register()` does not enable the `detect_sqli` plugin as it does not
outperform the default implementation.
