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

type geoLookup struct{}

func (o *geoLookup) Init(data string) error {
	return nil
}

func (o *geoLookup) Evaluate(tx *coraza.Transaction, value string) bool {
	// kept for compatibility, it requires a plugin.
	city, err := tx.Waf.GeoIPDB.City(net.ParseIP(value))
	if err != nil {
		return false
	}

	tx.GetCollection(variables.Geo).Set(variables.CountryCode, []string{city.Country.IsoCode})
	tx.GetCollection(variables.Geo).Set(variables.CountryName, []string{city.Country.Names["en"]})
	tx.GetCollection(variables.Geo).Set(variables.CountryContinent, []string{city.Continent.Names["en"]})
	tx.GetCollection(variables.Geo).Set(variables.City, []string{city.City.Names["en"]})
	tx.GetCollection(variables.Geo).Set(variables.PostalCode, []string{city.Postal.Code})
	tx.GetCollection(variables.Geo).Set(variables.Latitude, []string{strconv.FormatFloat(city.Location.Latitude, 'f', 10, 64)})
	tx.GetCollection(variables.Geo).Set(variables.Longitude, []string{strconv.FormatFloat(city.Location.Longitude, 'f', 10, 64)})

	// deprecated variables
	// tx.GetCollection(variables.Geo).Set(variables.Region, []string{})
	// tx.GetCollection(variables.Geo).Set(variables.CountryCode3, []string{})
	// tx.GetCollection(variables.Geo).Set(variables.DmaCode, []string{})
	// tx.GetCollection(variables.Geo).Set(variables.AreaCode, []string{})

	return true
}

var _ coraza.RuleOperator = &geoLookup{}
