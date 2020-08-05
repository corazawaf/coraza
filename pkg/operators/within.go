package operators

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
	"strings"
	"regexp"
)

type Within struct{
	data []string
}

func (o *Within) Init(data string){
	//split by space( ), comma(,) or pipe(|)
	re := regexp.MustCompile(` |,|\|`)
	spl := re.Split(data, -1)
    o.data = []string{}

    for i := range spl {
        o.data = append(o.data, spl[i])
    }
}

func (o *Within) Evaluate(tx *engine.Transaction, value string) bool{
	data := o.data
	if len(o.data) == 1{
		tdata := o.data[0]
		tdata = tx.MacroExpansion(tdata)
		data = strings.Split(tdata, " ")
	}
	for _, s:= range data {
		if s == value{
			return true
		}
	}
	return false
}