package geoip

import (
	"fmt"

	"github.com/ip2location/ip2location-go/v9"
)

type Ip2Location struct {
	db *ip2location.DB
}

func (i2l *Ip2Location) Init(args map[string]string) error {
	var err error
	file := args["file"]
	if file == "" {
		return fmt.Errorf("[file=path] is required for ip2location geoip database")
	}
	i2l.db, err = ip2location.OpenDB(file)
	if err != nil {
		return err
	}
	return nil
}

func (i2l *Ip2Location) Get(address string) (GeoData, error) {
	results, err := i2l.db.Get_all(address)
	if err != nil {
		return GeoData{}, err
	}

	return GeoData{
		IsoCode:     results.Country_short,
		CountryName: results.Country_short,
		Continent:   "",
		Region:      results.Areacode,
		City:        results.City,
		PostalCode:  "",
		Latitude:    float64(results.Latitude),
		Longitude:   float64(results.Longitude),
	}, nil
}

func (i2l *Ip2Location) Close() error {
	i2l.db.Close()
	return nil
}
