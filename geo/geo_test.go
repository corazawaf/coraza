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

import "testing"

var data = []struct {
	address string
	country string
	city    string
}{
	{"190.90.123.123", "cl", "santiago"},
	{"222.41.24.55", "ar", "buenos aires"},
}

type sampleGeo struct {
}

func (sg *sampleGeo) Init(_ string) error {
	return nil
}

func (sg *sampleGeo) Close() error {
	return nil
}

func (sg *sampleGeo) Get(address string) (map[string][]string, error) {
	for _, d := range data {
		if d.address == address {
			return map[string][]string{
				"country": {d.country},
				"city":    {d.city},
			}, nil
		}
	}
	return nil, nil
}

var _ Reader = &sampleGeo{}

func TestGeoPlugin(t *testing.T) {
	RegisterPlugin("sample", func() Reader {
		return &sampleGeo{}
	})
	g, err := GetReader("sample")
	if err != nil {
		t.Error(err)
	}
	for _, d := range data {
		m, err := g.Get(d.address)
		if err != nil {
			t.Error(err)
		}
		if m["country"][0] != d.country {
			t.Errorf("Expected %s, got %s", d.country, m["country"][0])
		}
		if m["city"][0] != d.city {
			t.Errorf("Expected %s, got %s", d.city, m["city"][0])
		}
	}
}
