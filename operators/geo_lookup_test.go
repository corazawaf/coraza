package operators

import (
	engine "github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/coraza/v2/types/variables"
	"github.com/oschwald/geoip2-golang"
	"strconv"
	"testing"
)

func Test_geoLookup(t *testing.T) {
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

	if tx.GetCollection(variables.Geo).GetFirstString(countryCode) != "GB" {
		t.Errorf("Invalid `COUNTRY_CODE` key for @geoLookup operator")
	}

	if tx.GetCollection(variables.Geo).GetFirstString(countryName) != "United Kingdom" {
		t.Errorf("Invalid `COUNTRY_NAME` key for @geoLookup operator")
	}

	if tx.GetCollection(variables.Geo).GetFirstString(countryContinent) != "Europe" {
		t.Errorf("Invalid `COUNTRY_CONTINENT` key for @geoLookup operator")
	}

	if tx.GetCollection(variables.Geo).GetFirstString(city) != "Hayling Island" {
		t.Errorf("Invalid `CITY` key for @geoLookup operator")
	}

	if tx.GetCollection(variables.Geo).GetFirstString(postalCode) != "PO11" {
		t.Errorf("Invalid `POSTAL_CODE` key for @geoLookup operator")
	}

	latitude, err := strconv.ParseFloat(tx.GetCollection(variables.Geo).GetFirstString(latitude), 64)
	if err != nil {
		t.Errorf("latitude data parse error: %s", err.Error())
	}
	if latitude != 50.7799 {
		t.Errorf("Invalid `LATITUDE` key for @geoLookup operator")
	}

	longitude, err := strconv.ParseFloat(tx.GetCollection(variables.Geo).GetFirstString(longitude), 64)
	if err != nil {
		t.Errorf("longitude data parse error: %s", err.Error())
	}
	if longitude != -0.9707 {
		t.Errorf("Invalid `LONGITUDE` key for @geoLookup operator")
	}
}
