package operators

import(
	"github.com/jptosso/coraza-waf/pkg/utils"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"net"
)

type GeoLookup struct{
	data string
}

func (o *GeoLookup) Init(data string){
	
}

func (o *GeoLookup) Evaluate(tx *engine.Transaction, value string) bool{
	if tx.WafInstance.GeoDb == nil{
		return false
	}
	ip := net.ParseIP(value)
	record, err := tx.WafInstance.GeoDb.Country(ip)
	if err != nil{
		return false
	}
	tx.Collections["country_code"] = &utils.LocalCollection{}
	tx.Collections["country_code"].Init()
	tx.Collections["country_code"].Add("", []string{record.Country.IsoCode})
	return true
}