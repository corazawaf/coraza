package operators

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
	"unicode/utf8"
)

type ValidateUtf8Encoding struct{}

func (o *ValidateUtf8Encoding) Init(data string){
}

func (o *ValidateUtf8Encoding) Evaluate(tx *engine.Transaction, value string) bool{
    return utf8.ValidString(value)
}


