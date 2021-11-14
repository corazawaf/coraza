package geo

import "fmt"

var readers = map[string]GeoReader{}

type GeoReader interface {
	Init(path string) error
	Get(ip string) (map[string][]string, error)
	Close() error
}

func RegisterGeoReader(name string, reader GeoReader) {
	readers[name] = reader
}

func GetGeoReader(name string) (GeoReader, error) {
	if reader, ok := readers[name]; ok {
		return reader, nil
	}
	return nil, fmt.Errorf("geo reader not found: %s", name)
}
