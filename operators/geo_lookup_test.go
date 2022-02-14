package operators

import (
	engine "github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/coraza/v2/types/variables"
	"github.com/oschwald/geoip2-golang"
	"testing"
)

func Test_geoLookup_Evaluate(t *testing.T) {
	geoLookupTest := geoLookup{}
	if err := geoLookupTest.Init(""); err != nil {
		t.Errorf("Error init geolookup")
	}

	var err error
	waf := engine.NewWaf()
	waf.GeoIPDB, err = geoip2.Open("../testdata/mmdb/GeoLite2-City.mmdb")
	if err != nil {
		t.Errorf("geoip db init error: %s", err)
	}

	tx := waf.NewTransaction()
	if !geoLookupTest.Evaluate(tx, "81.2.69.142") {
		t.Errorf("Invalid result for @geoLookup operator")
	}

	if tx.GetCollection(variables.Geo).GetFirstString(variables.CountryCode) != "GB" {
		t.Errorf("Invalid `COUNTRY_CODE` result for @geoLookup operator")
	}

	if tx.GetCollection(variables.Geo).GetFirstString(variables.CountryName) != "United Kingdom" {
		t.Errorf("Invalid `COUNTRY_NAME` result for @geoLookup operator")
	}

	if tx.GetCollection(variables.Geo).GetFirstString(variables.CountryContinent) != "Europe" {
		t.Errorf("Invalid `COUNTRY_CONTINENT` result for @geoLookup operator")
	}

	if tx.GetCollection(variables.Geo).GetFirstString(variables.City) != "Hayling Island" {
		t.Errorf("Invalid `CITY` result for @geoLookup operator")
	}

	if tx.GetCollection(variables.Geo).GetFirstString(variables.PostalCode) != "PO11" {
		t.Errorf("Invalid `POSTAL_CODE` result for @geoLookup operator")
	}

	if tx.GetCollection(variables.Geo).GetFirstFloat64(variables.Latitude) != 50.7799 {
		t.Errorf("Invalid `LATITUDE` result for @geoLookup operator")
	}

	if tx.GetCollection(variables.Geo).GetFirstFloat64(variables.Longitude) != -0.9707 {
		t.Errorf("Invalid `LONGITUDE` result for @geoLookup operator")
	}
}
