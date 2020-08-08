package operators

import (
	pcre"github.com/gijsbers/go-pcre"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

//It is possible to apply recursion limits but it must be added to the library
// https://pcre.org/pcre.txt
//          unsigned long int match_limit;
//          unsigned long int match_limit_recursion;
type Rx struct{
	re string
}

func (o *Rx) Init(data string){
	o.re = data
}

func (o *Rx) Evaluate(tx *engine.Transaction, value string) bool{
	//renow := tx.MacroExpansion(o.re)
	re := pcre.MustCompile(o.re, 0)
	//TODO JIT optimization but test check concurrency first
	m := re.MatcherString(value, 0)
	if tx.Capture{
		tx.ResetCapture()
	}
	//m.Match(subject, 0)
	for i := 0;i < m.Groups()+1;i++ {
		if i == 10{
			return true
		}
		if tx.Capture{
			tx.CaptureField(i, m.GroupString(i))
		}
	}
	return m.Matches()
}