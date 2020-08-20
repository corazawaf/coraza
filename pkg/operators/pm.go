package operators

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
	ahocorasick"github.com/bobusumisu/aho-corasick"
	"strings"
)
type Pm struct{
	data []string
}

func (o *Pm) Init(data string){
	o.data = strings.Split(data, " ")
	// TODO this operator is supposed to support snort data syntax: "@pm A|42|C|44|F"
	// TODO modsecurity uses mutex to queue ahocorasick, maybe its for a reason...
}

func (o *Pm) Evaluate(tx *engine.Transaction, value string) bool{
	trie := ahocorasick.NewTrieBuilder().
	    AddStrings(o.data).
	    Build()
	matches := trie.MatchString(value)
	return len(matches) > 0
}

func (o *Pm) GetType() string{
	return ""
}