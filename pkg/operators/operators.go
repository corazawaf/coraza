package operators
import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)
func OperatorsMap() map[string]engine.Operator {
	return map[string]engine.Operator{
		"beginsWith": &BeginsWith{},
		"rx": &Rx{},
		"eq": &Eq{},
		"detectSQLi": &DetectSQLi{},
		"detectXSS": &DetectXSS{},
		"contains": &Contains{},
		"endsWith": &EndsWith{},
		"inspectFile": &InspectFile{},
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
		"ipMatchFromFile": &IpMatchFromFile{},
		"geoLookup": &GeoLookup{},
		"rbl": &Rbl{},
		"validateUtf8Encoding": &ValidateUtf8Encoding{},
	}
}