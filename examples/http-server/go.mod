module github.com/corazawaf/coraza/v3/examples/http-server

go 1.17

require github.com/corazawaf/coraza/v3 v3.0.0-00010101000000-000000000000

require (
	github.com/corazawaf/libinjection-go v0.0.0-20220909190158-227e7e772cef // indirect
	github.com/magefile/mage v1.13.0 // indirect
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20211021192214-5ab2d9280aa9 // indirect
	github.com/tidwall/gjson v1.14.3 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	golang.org/x/net v0.0.0-20220809184613-07c6da5e1ced // indirect
)

replace github.com/corazawaf/coraza/v3 => ../..
