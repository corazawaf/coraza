module github.com/corazawaf/coraza/v3/examples/http-server

go 1.17

replace github.com/corazawaf/coraza/v3 => ../..

require github.com/corazawaf/coraza/v3 v3.0.0-00010101000000-000000000000

require (
	github.com/cloudflare/ahocorasick v0.0.0-20210425175752-730270c3e184 // indirect
	github.com/corazawaf/coraza/v2 v2.0.1 // indirect
	github.com/corazawaf/libinjection-go v0.0.0-20220207031228-44e9c4250eb5 // indirect
	golang.org/x/net v0.0.0-20220520000938-2e3eb7b945c2 // indirect
)
