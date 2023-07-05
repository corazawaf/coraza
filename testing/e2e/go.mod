module github.com/corazawaf/coraza/v3/testing/e2e

go 1.18

require (
	github.com/corazawaf/coraza/v3 v3.0.1-0.20230620093802-ce5e52dd2b74
	github.com/corazawaf/coraza/v3/http/e2e v0.0.0-00010101000000-000000000000
	github.com/mccutchen/go-httpbin/v2 v2.9.0
)

require (
	github.com/corazawaf/libinjection-go v0.1.2 // indirect
	github.com/magefile/mage v1.15.0 // indirect
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20211021192214-5ab2d9280aa9 // indirect
	github.com/tidwall/gjson v1.14.4 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	golang.org/x/net v0.11.0 // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
)

replace github.com/corazawaf/coraza/v3/http/e2e => ../../http/e2e/
