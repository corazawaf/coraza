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

package geo

import "fmt"

// readers stores an unexported map of registered GeoReaders
// They must only be added by directives as it is not concurrent-safe for writing
var readers = map[string]GeoReader{}

// GeoReader is the interface that wraps a GeoIP database
// It is used by the @geoLookup operator to create the GEO variables
type GeoReader interface {
	// Init a geo reader for the given file, for example .mmdb, data, etc
	// It fails in case the file is invalid, cannot be read or is not supported
	// Init is called by the directive SecGeoLookupDb
	Init(path string) error
	// Get the country code for a given IP address
	// returns every documented variable for GEO as map[string][]string
	// GEO:COUNTRY_CODE, GEO:COUNTRY_NAME, GEO:COUNTRY_CONTINENT, GEO:REGION, GEO:CITY, GEO:POSTAL_CODE, GEO:LATITUDE, GEO:LONGITUDE
	// Important: Get must be concurrent safe
	Get(ip string) (map[string][]string, error)
	// Close the georeader and release resources
	// It fails if the reader was already closed
	Close() error
}

// RegisterGeoReader registers a new GeoReader plugin
// There are no defaults GeoReaders
func RegisterGeoReader(name string, reader GeoReader) {
	readers[name] = reader
}

// GetGeoReader returns a GeoReader by name
// It fails if the georeader does not exist
func GetGeoReader(name string) (GeoReader, error) {
	if reader, ok := readers[name]; ok {
		return reader, nil
	}
	return nil, fmt.Errorf("geo reader not found: %s", name)
}
