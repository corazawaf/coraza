package operators

import(
	"github.com/jptosso/coraza/pkg/models"
	ahocorasick"github.com/bobusumisu/aho-corasick"
	"strings"
)
type Pm struct{
	data []string
}

func (o *Pm) Init(data string){
	o.data = strings.Split(data, " ")
    
}

func (o *Pm) Evaluate(tx *models.Transaction, value string) bool{
	trie := ahocorasick.NewTrieBuilder().
	    AddStrings(o.data).
	    Build()
	matches := trie.MatchString(value)

	//fmt.Printf("Separado en %d para %s con %d matches\n", len(spl), search, len(matches))
	return len(matches) > 0
}

func (o *Pm) GetType() string{
	return ""
}