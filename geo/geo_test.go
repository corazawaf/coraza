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
