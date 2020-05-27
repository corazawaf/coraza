package actions

import(
	"github.com/jptosso/coraza/pkg/models"
	_"github.com/jptosso/coraza/pkg/utils"
	"strings"
	"strconv"
)

type Expirevar struct {
	collection string
	ttl int
	key string
}

func (a *Expirevar) Init(r *models.Rule, data string, errors []string) () {
	spl := strings.SplitN(data, "=", 2)
	a.ttl, _ = strconv.Atoi(spl[1])
	spl = strings.SplitN(spl[0], ".", 2)
	if len(spl) != 2{
		//... error
	}
	col := spl[0]
	a.key = spl[1]
	collection := ""
	col = col
	collection = collection
}

func (a *Expirevar) Evaluate(r *models.Rule, tx *models.Transaction) () {
	//a.collection.SetTtl(a.key, a.ttl)
}

func (a *Expirevar) GetType() string{
	return ""
}
