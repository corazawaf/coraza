package operators

import (
	//pcre"github.com/gijsbers/go-pcre"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"regexp"
)

/*
Previously made with go-pcre but falling but to rails stack
*/
type Rx struct{
	re string
}

func (o *Rx) Init(data string){
	o.re = data
}

func (o *Rx) Evaluate(tx *engine.Transaction, value string) bool{
	r, _ := regexp.Compile(o.re)
	matches := r.FindAllStringSubmatch(value, -1)
	i := 1
	if tx.Capture{
		tx.ResetCapture()
	}
	
	tx.CaptureField(0, value)	
	for _, v := range matches {
		if i >= 10{
			//we only use 10 captures
			break
		}
		if tx.Capture && len(v) > 1{
			tx.CaptureField(i, v[1])
		}
		i += 1
	}
	return i > 1
}

/*
func (o *Rx) Evaluate(tx *engine.Transaction, value string) bool{
	renow := tx.MacroExpansion(o.re)
	re := pcre.MustCompile(renow, 0)
	m := re.MatcherString(value, 0)
	subject := []byte(value)
	i := 1
	if tx.Capture{
		tx.Collections["tx"].ResetCapture()
	}
	
	tx.CaptureField(0, value)
	for m.Match(subject, 0){
		index := m.Index()
		subject = subject[index[1]:]
		if tx.Capture{
			fmt.Println(string(subject), index)
			tx.CaptureField(i, string(subject))
		}
	    if len(subject) == 0{
	    	break
	    }
	    i++
	    if i >= 10{
	    	//We only collect 10
	    	break
	    }
	}
	return m.Matches()
}
*/