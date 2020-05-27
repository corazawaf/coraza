package operators
import(
	"github.com/jptosso/coraza-waf/pkg/models"
)
func OperatorsMap() map[string]models.Operator {
	return map[string]models.Operator{
		"beginsWith": &BeginsWith{},
		"rx": &Rx{},
		"eq": &Eq{},
		"detectSQLi": &DetectSQLi{},
		"detectXSS": &DetectXSS{},
		"contains": &Contains{},
		"endsWith": &EndsWith{},
		"ge": &Ge{},
		"gt": &Gt{},
		"le": &Le{},
		"lt": &Lt{},
		"unconditionalMatch": &UnconditionalMatch{},
		"within": &Within{},
		"pmFromFile": &PmFromFile{},
		"pm": &Pm{},
		"validateByteRange": &ValidateByteRange{},
		"validateUrlEncoding": &ValidateUrlEncoding{},
		"streq": &Streq{},	
		"ipMatch": &IpMatch{},
		"geoLookup": &GeoLookup{},
		"rbl": &Rbl{},
		"validateUtf8Encoding": &ValidateUtf8Encoding{},
	}
}