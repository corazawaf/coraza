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
// - jsonparser

require (
	github.com/anuraaga/go-modsecurity v0.0.0-20220824035035-b9a4099778df
	github.com/buger/jsonparser v1.1.1
	github.com/corazawaf/libinjection-go v0.1.1
	github.com/foxcpp/go-mockdns v1.0.0
	github.com/magefile/mage v1.14.0
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20211021192214-5ab2d9280aa9
	golang.org/x/net v0.0.0-20221002022538-bcab6841153b
)

require (
	github.com/miekg/dns v1.1.50 // indirect
	golang.org/x/mod v0.6.0-dev.0.20220419223038-86c51ed26bb4 // indirect
	golang.org/x/sys v0.0.0-20220913175220-63ea55921009 // indirect
	golang.org/x/tools v0.1.12 // indirect
)
