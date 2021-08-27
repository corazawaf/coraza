package geoip

type GeoData struct {
	IsoCode     string  // Country ISO-3166 code
	CountryName string  // The full country name.
	Continent   string  // The two character continent that the country is located. EX: EU
	Region      string  // The two character region. For US, this is state. For Canada, providence, for Chile this is a region, etc.
	City        string  // The city name if supported by the database.
	PostalCode  string  // The postal code if supported by the database.
	Latitude    float64 // The latitude if supported by the database.
	Longitude   float64 // The longitude if supported by the database.
}

type GeoDb interface {
	Init(parameters map[string]string) error
	Get(address string) (GeoData, error)
	Close() error
}
