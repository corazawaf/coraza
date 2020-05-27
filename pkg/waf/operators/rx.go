package operators

import (
	pcre"github.com/gijsbers/go-pcre"
	"github.com/jptosso/coraza/pkg/models"
	"strconv"
)

type Rx struct{
	re string
}

func (o *Rx) Init(data string){
	o.re = data
}

func (o *Rx) Evaluate(tx *models.Transaction, value string) bool{
	renow := tx.MacroExpansion(o.re)
	re := pcre.MustCompile(renow, 0)
	m := re.MatcherString(value, 0)
	subject := []byte(value)
	i := 0
	if tx.Capture{
		tx.Collections["tx"].ResetCapture()
	}
	for m.Match(subject, 0){
		index := m.Index()
		if tx.Capture{
			tx.Collections["tx"].Data[strconv.Itoa(i)] = []string{string(subject)}
		}
		subject = subject[index[1]:]
	    if len(subject) == 0{
	    	break
	    }
	    i++
	    if i >= 9{
	    	//We only collect 10
	    	break
	    }
	}
	return m.Matches()
}