// Copyright 2021 Juan Pablo Tosso
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
	"net"

	engine "github.com/jptosso/coraza-waf/v1"
)

type GeoLookup struct {
	data string
}

func (o *GeoLookup) Init(data string) error {
	return nil
}

func (o *GeoLookup) Evaluate(tx *engine.Transaction, value string) bool {
	if tx.Waf.GeoDb == nil {
		return false
	}
	ip := net.ParseIP(value)
	record, err := tx.Waf.GeoDb.Country(ip)
	if err != nil {
		return false
	}
	tx.GetCollection(engine.VARIABLE_GEO).Add("COUNTRY_CODE", record.Country.IsoCode)
	//TODO:
	// NOTE: US ONLY VARIABLES WON'T BE ADDED, also NA and SA will be replaced with AM because of reasons
	// COUNTRY_CODE3: Up to three character country code.
	// COUNTRY_NAME: The full country name.
	// COUNTRY_CONTINENT: The two character continent that the country is located. EX: EU
	// REGION: The two character region. For US, this is state. For Canada, providence, etc.
	// CITY: The city name if supported by the database.
	// POSTAL_CODE: The postal code if supported by the database.
	// LATITUDE: The latitude if supported by the database.
	// LONGITUDE: The longitude if supported by the database.
	return true
}
