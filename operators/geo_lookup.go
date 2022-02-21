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
	"strconv"
)

const (
	countryCode      = "country_code"
	countryName      = "country_name"
	countryContinent = "country_continent"
	region           = "region"
	city             = "city"
	postalCode       = "postal_code"
	latitude         = "latitude"
	longitude        = "longitude"
)

type geoLookup struct{}

func (o *geoLookup) Init(data string) error {
	return nil
}

func (o *geoLookup) Evaluate(tx *coraza.Transaction, value string) bool {
	r, err := tx.Waf.GeoDB.Get(value)
	if err != nil {
		return false
	}

	tx.GetCollection(variables.Geo).Set(countryCode, []string{r.CountryCode})
	tx.GetCollection(variables.Geo).Set(countryName, []string{r.CountryName})
	tx.GetCollection(variables.Geo).Set(countryContinent, []string{r.CountryContinent})
	tx.GetCollection(variables.Geo).Set(region, []string{r.Region})
	tx.GetCollection(variables.Geo).Set(city, []string{r.City})
	tx.GetCollection(variables.Geo).Set(postalCode, []string{r.PostalCode})
	tx.GetCollection(variables.Geo).Set(latitude, []string{strconv.FormatFloat(r.Latitude, 'f', 10, 64)})
	tx.GetCollection(variables.Geo).Set(longitude, []string{strconv.FormatFloat(r.Longitude, 'f', 10, 64)})
	return true
}

var _ coraza.RuleOperator = &geoLookup{}
