module github.com/corazawaf/coraza/v3

go 1.26.5

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
	github.com/corazawaf/coraza-coreruleset v0.0.0-20240226094324-415b1017abdc
	github.com/corazawaf/libinjection-go v0.3.2
	github.com/foxcpp/go-mockdns v1.2.0
	github.com/jcchavezs/mergefs v0.1.1
	github.com/kaptinlin/jsonschema v0.9.8
	github.com/magefile/mage v1.17.0
	github.com/mccutchen/go-httpbin/v2 v2.25.0
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20250424160509-463d218d4745
	github.com/tidwall/gjson v1.18.0
	github.com/valllabh/ocsf-schema-golang v1.0.3
	golang.org/x/net v0.58.0
	golang.org/x/sync v0.22.0
	rsc.io/binaryregexp v0.2.0
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-json-experiment/json v0.0.0-20260623181947-01eb4420fa68 // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/kaptinlin/jsonpointer v0.4.28 // indirect
	github.com/miekg/dns v1.1.57 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	golang.org/x/mod v0.40.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

retract v3.2.2
