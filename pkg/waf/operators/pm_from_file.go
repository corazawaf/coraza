package operators
import(
	"strings"
	"sync"
	ahocorasick"github.com/bobusumisu/aho-corasick"
	"github.com/jptosso/coraza-waf/pkg/models"
	"io/ioutil"
	_"path"	
	"fmt"
)


type PmFromFile struct{
	Data []string
	mux *sync.RWMutex
}

func (o *PmFromFile) Init(data string){
	o.Data = []string{}
    content, err := ioutil.ReadFile(data)
    if err != nil{
    	fmt.Println("Error loading file " + data)
    	return
    }
    sp := strings.Split(string(content), "\n")
    for _, l := range sp {
    	if len(l) == 0{
    		continue
    	}
    	if l[0] != '#'{
    		o.Data = append(o.Data, l)
    	}
    }
    o.mux = &sync.RWMutex{}
}

func (o *PmFromFile) Evaluate(tx *models.Transaction, value string) bool{
	o.mux.RLock()
	defer o.mux.RUnlock()
	trie := ahocorasick.NewTrieBuilder().
	    AddStrings(o.Data).
	    Build()
	matches := trie.MatchString(value)

	//fmt.Printf("Separado en %d para %s con %d matches\n", len(spl), search, len(matches))
	return len(matches) > 0
}

func (o *PmFromFile) GetType() string{
	return ""
}