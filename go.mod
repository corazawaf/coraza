module github.com/corazawaf/coraza/v3

go 1.22.3

// Testing dependencies:
// - go-mockdns
// - go-modsecurity (optional)

// Development dependencies:
// - mage

// Build dependencies:
// - libinjection-go
// - aho-corasick
// - gjson
// - binaryregexp
// - ocsf-schema-golang

require (
	github.com/anuraaga/go-modsecurity v0.0.0-20220824035035-b9a4099778df
	github.com/corazawaf/libinjection-go v0.2.2
	github.com/foxcpp/go-mockdns v1.1.0
	github.com/magefile/mage v1.15.1-0.20231118170541-2385abb49a1f
	github.com/mccutchen/go-httpbin/v2 v2.15.0
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20240411101913-e07a1f0e8eb4
	github.com/tidwall/gjson v1.18.0
	github.com/valllabh/ocsf-schema-golang v1.0.3
	golang.org/x/net v0.30.0
	golang.org/x/sync v0.8.0
	rsc.io/binaryregexp v0.2.0
)

require (
	github.com/miekg/dns v1.1.57 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)
