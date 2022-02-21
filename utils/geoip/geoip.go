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

// GeoData is used to store the information by the geoip engine
type GeoData struct {
	CountryCode      string
	CountryName      string
	CountryContinent string
	Region           string
	City             string
	PostalCode       string
	Latitude         float64
	Longitude        float64
}

// GeoDb defines the geoip engine interface
type GeoDb interface {
	Init(file string) error
	Get(address string) (GeoData, error)
	Close() error
}
