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
	"github.com/oschwald/geoip2-golang"
	"net"
)

// MaxMinddb engine for geoip
type MaxMinddb struct {
	db *geoip2.Reader
}

// Init db for engine
func (m *MaxMinddb) Init(file string) error {
	if file == "" {
		return fmt.Errorf("[file=path] required for maxminddb geoip database")
	}

	var err error
	m.db, err = geoip2.Open(file)
	return err
}

// Get address related information
func (m *MaxMinddb) Get(address string) (GeoData, error) {
	ip := net.ParseIP(address)
	r, err := m.db.City(ip)
	if err != nil {
		return GeoData{}, err
	}

	return GeoData{
		CountryCode:      r.Country.IsoCode,
		CountryName:      r.Country.Names["en"],
		CountryContinent: r.Continent.Names["en"],
		Region:           "",
		City:             r.City.Names["en"],
		PostalCode:       r.Postal.Code,
		Latitude:         r.Location.Latitude,
		Longitude:        r.Location.Longitude,
	}, nil
}

// Close engine
func (m *MaxMinddb) Close() error {
	return m.db.Close()
}
