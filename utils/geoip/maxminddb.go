package geoip

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
)

type Maxminddb struct {
	db *geoip2.Reader
}

func (mx *Maxminddb) Init(args map[string]string) error {
	var err error
	file := args["file"]
	if file == "" {
		return fmt.Errorf("[file=path] is required for maxminddb geoip database")
	}
	mx.db, err = geoip2.Open(file)
	return err
}

func (mx *Maxminddb) Get(address string) (GeoData, error) {
	ip := net.ParseIP(address)
	record, err := mx.db.City(ip)
	if err != nil {
		return GeoData{}, nil
	}
	return GeoData{
		IsoCode:     record.Country.IsoCode,
		CountryName: record.Country.Names["en"],
		Continent:   record.Continent.Names["en"],
		Region:      "",
		City:        record.City.Names["en"],
		PostalCode:  record.Postal.Code,
		Latitude:    record.Location.Latitude,
		Longitude:   record.Location.Longitude,
	}, nil
}

func (mx *Maxminddb) Close() error {
	return mx.db.Close()
}
