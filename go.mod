module github.com/corazawaf/coraza/v3

go 1.18

// Testing dependencies:
// - go-mockdns
// - go-modsecurity (optional)

// Development dependencies:
// - mage

// Build dependencies:
// - libinjection-go
// - aho-corasick
// - gjson
// - xmlquery

require (
	github.com/antchfx/xmlquery v1.3.15
	github.com/anuraaga/go-modsecurity v0.0.0-20220824035035-b9a4099778df
	github.com/corazawaf/libinjection-go v0.1.2
	github.com/foxcpp/go-mockdns v1.0.0
	github.com/magefile/mage v1.14.0
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20211021192214-5ab2d9280aa9
	github.com/tidwall/gjson v1.14.4
	golang.org/x/net v0.8.0
)

require (
	github.com/antchfx/xpath v1.2.3 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/miekg/dns v1.1.50 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	golang.org/x/tools v0.6.0 // indirect
)
