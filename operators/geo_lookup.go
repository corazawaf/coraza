// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package operators

import (
	"github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/coraza/v2/types/variables"
	"net"
	"strconv"
)

const (
	countryCode      = "country_code"
	countryName      = "country_name"
	countryContinent = "country_continent"
	city             = "city"
	postalCode       = "postal_code"
	latitude         = "latitude"
	longitude        = "longitude"

	// Deprecated
	// dmaCode      = "dma_code"
	// areaCode     = "area_code"
	// region       = "region"
	// countryCode3 = "country_code3"
)

type geoLookup struct{}

func (o *geoLookup) Init(data string) error {
	return nil
}

func (o *geoLookup) Evaluate(tx *coraza.Transaction, value string) bool {
	c, err := tx.Waf.GeoIPDB.City(net.ParseIP(value))
	if err != nil {
		return false
	}

	tx.GetCollection(variables.Geo).Set(countryCode, []string{c.Country.IsoCode})
	tx.GetCollection(variables.Geo).Set(countryName, []string{c.Country.Names["en"]})
	tx.GetCollection(variables.Geo).Set(countryContinent, []string{c.Continent.Names["en"]})
	tx.GetCollection(variables.Geo).Set(city, []string{c.City.Names["en"]})
	tx.GetCollection(variables.Geo).Set(postalCode, []string{c.Postal.Code})
	tx.GetCollection(variables.Geo).Set(latitude, []string{strconv.FormatFloat(c.Location.Latitude, 'f', 10, 64)})
	tx.GetCollection(variables.Geo).Set(longitude, []string{strconv.FormatFloat(c.Location.Longitude, 'f', 10, 64)})

	// deprecated variables
	// tx.GetCollection(variables.Geo).Set(region, []string{})
	// tx.GetCollection(variables.Geo).Set(countryCode3, []string{})
	// tx.GetCollection(variables.Geo).Set(dmaCode, []string{})
	// tx.GetCollection(variables.Geo).Set(areaCode, []string{})
	return true
}

var _ coraza.RuleOperator = &geoLookup{}
