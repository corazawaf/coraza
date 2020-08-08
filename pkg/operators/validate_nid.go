package operators

import(
	"strings"
	"regexp"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/operators/nids"
)

type ValidateNid struct{
	fn nids.Nid
	rgx string
}

func (o *ValidateNid) Init(data string){
	spl := strings.SplitN(data, " ", 2)
	o.fn = nids.NidMap()[spl[0]]
	o.rgx = spl[1]
}

func (o *ValidateNid) Evaluate(tx *engine.Transaction, value string) bool{
	re, _ := regexp.Compile(o.rgx)
	matches := re.FindAllStringSubmatch(value, -1)
	if tx.Capture{
		tx.ResetCapture()
	}

	res := false
	for i, m := range matches{
		if i >= 10{
			break
		}
		if o.fn.Evaluate(m[0]){
			res = true
			if tx.Capture{
				tx.CaptureField(i, m[0])
			}
		}
	}
	return res
}