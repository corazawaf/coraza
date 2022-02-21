// Copyright 2022 Xinyu Wu
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

package geoip

import (
	"fmt"
	"github.com/ip2location/ip2location-go/v9"
)

// IP2Location engine for geoip
type IP2Location struct {
	db *ip2location.DB
}

// Init db for engine
func (i2l *IP2Location) Init(file string) error {
	if file == "" {
		return fmt.Errorf("[file=path] required for maxminddb geoip database")
	}

	var err error
	i2l.db, err = ip2location.OpenDB(file)
	return err
}

// Get address related information
func (i2l *IP2Location) Get(address string) (GeoData, error) {
	r, err := i2l.db.Get_all(address)
	if err != nil {
		return GeoData{}, err
	}

	return GeoData{
		CountryCode:      r.Country_short,
		CountryName:      r.Country_long,
		CountryContinent: "",
		Region:           r.Region,
		City:             r.City,
		PostalCode:       "",
		Latitude:         float64(r.Latitude),
		Longitude:        float64(r.Longitude),
	}, nil
}

// Close engine
func (i2l *IP2Location) Close() error {
	i2l.db.Close()
	return nil
}
