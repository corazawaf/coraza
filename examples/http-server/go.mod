module github.com/corazawaf/coraza/v3/examples/http-server

go 1.21

require github.com/corazawaf/coraza/v3 v3.0.0-00010101000000-000000000000

require (
	github.com/corazawaf/libinjection-go v0.2.1 // indirect
	github.com/magefile/mage v1.15.0 // indirect
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20240411101913-e07a1f0e8eb4 // indirect
	github.com/tidwall/gjson v1.17.1 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	golang.org/x/net v0.27.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
)

replace github.com/corazawaf/coraza/v3 => ../../
