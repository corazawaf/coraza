module github.com/jcchavezs/coraza-wasm-example

go 1.17

require github.com/corazawaf/coraza/v2 v2.0.0-rc.3

require (
	github.com/alphahorizonio/tinynet v0.0.0-20210118222949-51439cf30be8 // indirect
	github.com/alphahorizonio/unisockets v0.1.1 // indirect
	github.com/cloudflare/ahocorasick v0.0.0-20210425175752-730270c3e184 // indirect
	github.com/corazawaf/libinjection-go v0.0.0-20220207031228-44e9c4250eb5 // indirect
	github.com/tidwall/gjson v1.14.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	go.uber.org/zap v1.21.0 // indirect
	golang.org/x/net v0.0.0-20220325170049-de3da57026de // indirect
)

replace github.com/corazawaf/coraza/v2 => ../..
